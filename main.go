package main

import (
	"archive/tar"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	grypedistro "github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	appName          = "wolfi-scanner"
	appVersion       = "0.0.4"
	sbomDir          = "/var/lib/db/sbom"
	metricsAddr      = ":9090"
	dbUpdateInterval = 24 * time.Hour
	httpReadTimeout  = 10 * time.Second
	httpWriteTimeout = 10 * time.Second
	httpIdleTimeout  = 120 * time.Second
	shutdownTimeout  = 5 * time.Second
	maxSBOMFileSize  = 50 << 20 // 50 MiB
)

var (
	daemon      = flag.Bool("daemon", false, "run as daemon with periodic scans and metrics server")
	debug       = flag.Bool("debug", false, "enable debug logging and dump extracted SBOMs")
	testMode    = flag.Bool("test", false, "only scan the first matching container")
	onlyFixed   = flag.Bool("only-fixed", false, "only report vulnerabilities with available fixes")
	imageFilter = flag.String("image-filter", "cgr.dev/", "comma-separated list of image prefixes to match")
	scanPeriod  = flag.Duration("scan-period", 6*time.Hour, "time between scans (daemon mode)")
)

var errNoSBOM = errors.New("no SBOM files found")

// Prometheus metrics
var (
	vulnGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "scanner_vulnerabilities",
		Help: "Current vulnerabilities per image and severity",
	}, []string{"image", "severity", "fixable", "id", "pkg"})
	pkgGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "scanner_packages",
		Help: "Package count per image",
	}, []string{"image"})
	scanDuration  = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "scanner_duration_seconds", Help: "Scan duration", Buckets: []float64{1, 5, 10, 30, 60, 120, 300}})
	scansTotal    = prometheus.NewCounter(prometheus.CounterOpts{Name: "scanner_scans_total", Help: "Total scans"})
	scanErrors    = prometheus.NewCounter(prometheus.CounterOpts{Name: "scanner_errors_total", Help: "Failed scans"})
	imagesScanned = prometheus.NewGauge(prometheus.GaugeOpts{Name: "scanner_images_scanned", Help: "Images scanned in last run"})
	lastScanTime  = prometheus.NewGauge(prometheus.GaugeOpts{Name: "scanner_last_scan_timestamp_seconds", Help: "Last scan unix timestamp"})
)

func init() {
	prometheus.MustRegister(vulnGauge, pkgGauge, scanDuration, scansTotal, scanErrors, imagesScanned, lastScanTime)
}

type scanner struct {
	mu     sync.RWMutex
	store  vulnerability.Provider
	client *kubernetes.Clientset
	config *rest.Config
	logger *slog.Logger
}

type vuln struct {
	id          string
	pkg         string
	version     string
	image       string
	severity    string
	fixVersions []string
}

func (v vuln) fix() string {
	if len(v.fixVersions) > 0 {
		return strings.Join(v.fixVersions, ", ")
	}
	return "-"
}

// --- main ---

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", appName, appVersion)
		return
	}

	logger := setupLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func setupLogger() *slog.Logger {
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func run(ctx context.Context, logger *slog.Logger) error {
	config, err := getK8sConfig(logger)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}
	s, err := newScanner(client, config, logger)
	if err != nil {
		return err
	}
	if *daemon {
		return s.runDaemon(ctx)
	}
	return s.scan(ctx)
}

// --- scanner lifecycle ---

func newScanner(client *kubernetes.Clientset, config *rest.Config, logger *slog.Logger) (*scanner, error) {
	store, err := loadDB(logger)
	if err != nil {
		return nil, err
	}
	return &scanner{client: client, config: config, store: store, logger: logger}, nil
}

func loadDB(logger *slog.Logger) (vulnerability.Provider, error) {
	logger.Info("loading vulnerability database")
	id := clio.Identification{Name: appName, Version: appVersion}
	store, status, err := grype.LoadVulnerabilityDB(v6dist.DefaultConfig(), v6inst.DefaultConfig(id), true)
	if err != nil {
		return nil, fmt.Errorf("load vulnerability database: %w", err)
	}
	if status != nil {
		logger.Info("database loaded", "built", status.Built, "age", time.Since(status.Built).Round(time.Hour))
	}
	return store, nil
}

func (s *scanner) getStore() vulnerability.Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store
}

func (s *scanner) setStore(st vulnerability.Provider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = st
}

func (s *scanner) runDaemon(ctx context.Context) error {
	s.logger.Info("starting daemon", "scan_period", *scanPeriod)
	go s.scanLoop(ctx)
	go s.dbUpdateLoop(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "OK") })
	srv := &http.Server{
		Addr: metricsAddr, Handler: mux,
		ReadTimeout: httpReadTimeout, WriteTimeout: httpWriteTimeout, IdleTimeout: httpIdleTimeout,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		srv.Shutdown(c)
	}()
	s.logger.Info("metrics server listening", "addr", metricsAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}

func (s *scanner) scanLoop(ctx context.Context) {
	if err := s.scan(ctx); err != nil {
		s.logger.Error("scan failed", "error", err)
	}
	ticker := time.NewTicker(*scanPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scan(ctx); err != nil {
				s.logger.Error("scan failed", "error", err)
			}
		}
	}
}

func (s *scanner) dbUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(dbUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Info("updating vulnerability database")
			st, err := loadDB(s.logger)
			if err != nil {
				s.logger.Error("db update failed", "error", err)
				continue
			}
			s.setStore(st)
		}
	}
}

// --- scan ---

func (s *scanner) scan(ctx context.Context) error {
	start := time.Now()
	ok := false
	defer func() {
		scanDuration.Observe(time.Since(start).Seconds())
		if !ok {
			scanErrors.Inc()
		}
	}()

	sboms, err := s.fetchSBOMs(ctx)
	if err != nil {
		return fmt.Errorf("fetch SBOMs: %w", err)
	}
	if len(sboms) == 0 {
		s.logger.Info("no matching images found")
		ok = true
		return nil
	}

	all := s.findVulns(sboms)
	reported := filterVulns(all)
	recordMetrics(reported)
	fmt.Print(formatReport(reported))

	ok = true
	scansTotal.Inc()
	imagesScanned.Set(float64(len(sboms)))
	lastScanTime.SetToCurrentTime()
	s.logger.Info("scan completed",
		"duration", time.Since(start).Round(time.Second),
		"images", len(sboms),
		"total", len(all),
		"reported", len(reported))
	return nil
}

// --- SBOM fetching ---

type sbomData struct {
	image string
	files map[string]string
}

func (s *scanner) fetchSBOMs(ctx context.Context) ([]sbomData, error) {
	pods, err := s.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	filters := parseFilters(*imageFilter)
	var result []sbomData
	seen := make(map[string]bool)

	for _, pod := range pods.Items {
		for _, ctr := range pod.Spec.Containers {
			if !matchesAny(ctr.Image, filters) || seen[ctr.Image] {
				continue
			}
			if *testMode && len(result) >= 1 {
				return result, nil
			}

			s.logger.Debug("extracting SBOM", "image", ctr.Image, "pod", pod.Namespace+"/"+pod.Name)
			data, err := s.extractSBOM(ctx, pod.Namespace, pod.Name, ctr.Name, ctr.Image)
			if err != nil {
				if !errors.Is(err, errNoSBOM) {
					s.logger.Warn("SBOM extraction failed", "image", ctr.Image, "error", err)
				}
				continue
			}

			if *debug {
				for name, content := range data.files {
					fmt.Fprintf(os.Stderr, "--- SBOM: %s (image: %s) ---\n%s\n", name, data.image, content)
				}
			}

			result = append(result, *data)
			seen[ctr.Image] = true
		}
	}
	return result, nil
}

func parseFilters(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if f := strings.TrimSpace(p); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func matchesAny(image string, filters []string) bool {
	for _, f := range filters {
		if strings.Contains(image, f) {
			return true
		}
	}
	return false
}

func (s *scanner) extractSBOM(ctx context.Context, ns, pod, container, image string) (*sbomData, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("[ -d %s ] && [ -n \"$(ls -A %s 2>/dev/null)\" ] && echo ok || echo empty", sbomDir, sbomDir)}
	out, err := s.execInPod(ctx, ns, pod, container, cmd)
	if err != nil {
		return nil, fmt.Errorf("check SBOM dir: %w", err)
	}
	if strings.TrimSpace(out) != "ok" {
		return nil, errNoSBOM
	}

	files, err := s.copyFromPod(ctx, ns, pod, container, sbomDir)
	if err != nil {
		return nil, fmt.Errorf("copy SBOMs: %w", err)
	}
	if len(files) == 0 {
		return nil, errNoSBOM
	}
	return &sbomData{image: image, files: files}, nil
}

func (s *scanner) copyFromPod(ctx context.Context, ns, pod, container, srcPath string) (map[string]string, error) {
	req := s.client.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(ns).SubResource("exec").
		Param("container", container).
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"tar", "cf", "-", "-C", srcPath, "."},
			Stdout:  true, Stderr: true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.config, "POST", req.URL())
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: pw, Stderr: io.Discard})
	}()

	files := make(map[string]string)
	tr := tar.NewReader(pr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxSBOMFileSize+1))
		if err != nil {
			s.logger.Warn("failed to read tar entry", "file", hdr.Name, "error", err)
			continue
		}
		if int64(len(content)) > maxSBOMFileSize {
			s.logger.Warn("SBOM too large, skipping", "file", hdr.Name)
			continue
		}
		files[hdr.Name] = string(content)
	}
	return files, nil
}

func (s *scanner) execInPod(ctx context.Context, ns, pod, container string, cmd []string) (string, error) {
	req := s.client.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(ns).SubResource("exec").
		Param("container", container).
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd, Stdout: true, Stderr: true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.config, "POST", req.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr strings.Builder
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout, Stderr: &stderr,
	}); err != nil {
		return "", fmt.Errorf("exec: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.String(), nil
}

// --- vulnerability scanning ---

func (s *scanner) findVulns(sboms []sbomData) []vuln {
	var result []vuln
	for _, data := range sboms {
		matches, err := s.matchVulns(data)
		if err != nil {
			s.logger.Warn("scan failed", "image", data.image, "error", err)
			continue
		}
		for _, m := range matches.Sorted() {
			result = append(result, toVuln(m, data.image))
		}
	}
	return result
}

func (s *scanner) matchVulns(data sbomData) (match.Matches, error) {
	var pkgs []syftPkg.Package
	var distro *linux.Release
	var src *source.Description

	for _, content := range data.files {
		sbom, _, _, err := format.Decode(strings.NewReader(content))
		if err != nil {
			continue
		}
		if distro == nil && sbom.Artifacts.LinuxDistribution != nil {
			distro = sbom.Artifacts.LinuxDistribution
		}
		if src == nil {
			src = &sbom.Source
		}
		// Only include APK packages. Per-package SBOMs also contain source
		// entries (Go modules, GitHub refs, etc.) that cause false positives
		// when scanned independently of the full image catalog.
		for _, p := range sbom.Artifacts.Packages.Sorted() {
			if p.Type == syftPkg.ApkPkg {
				pkgs = append(pkgs, p)
			}
		}
	}
	if len(pkgs) == 0 {
		return match.Matches{}, nil
	}

	var gd *grypedistro.Distro
	if distro != nil {
		gd = grypedistro.New(grypedistro.Type(distro.ID), distro.VersionID, "", distro.IDLike...)
	}

	grypePkgs := grypePkg.FromPackages(pkgs, grypePkg.SynthesisConfig{
		GenerateMissingCPEs: true,
		Distro:              grypePkg.DistroConfig{Override: gd},
	})
	s.logger.Debug("scanning", "image", data.image, "packages", len(grypePkgs))

	vm := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: s.getStore(),
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
		NormalizeByCVE:        true,
	}
	matches, _, err := vm.FindMatches(grypePkgs, grypePkg.Context{Source: src, Distro: gd})
	if err != nil {
		return match.Matches{}, fmt.Errorf("find matches: %w", err)
	}

	// The APK matcher always performs CPE matching internally. When scanning
	// per-package SBOMs (rather than an image directly), this produces false
	// positives from overly broad NVD CPEs (e.g. "gitlab" matching "gitlab-runner").
	// Filter out CPE-only matches where no CPE product matches the package name.
	var kept []match.Match
	for _, m := range matches.Sorted() {
		if !isSpuriousCPEMatch(m) {
			kept = append(kept, m)
		}
	}
	return match.NewMatches(kept...), nil
}

func toVuln(m match.Match, image string) vuln {
	v := vuln{id: m.Vulnerability.ID, pkg: m.Package.Name, version: m.Package.Version, image: image}
	if m.Vulnerability.Metadata != nil {
		v.severity = m.Vulnerability.Metadata.Severity
	}
	if m.Vulnerability.Fix.State == "fixed" {
		v.fixVersions = m.Vulnerability.Fix.Versions
	}
	return v
}

// isSpuriousCPEMatch returns true when a match came exclusively via CPE and
// none of the matched CPE products match the package name. This filters broad
// NVD CPEs (e.g. "gitlab" matching "gitlab-runner") while keeping legitimate
// ones (e.g. "redis" matching "redis").
func isSpuriousCPEMatch(m match.Match) bool {
	for _, d := range m.Details {
		if d.Type != match.CPEMatch {
			return false
		}
	}
	if len(m.Details) == 0 {
		return false
	}
	pkgName := m.Package.Name
	for _, d := range m.Details {
		result, ok := d.Found.(match.CPEResult)
		if !ok {
			continue
		}
		for _, cpe := range result.CPEs {
			// cpe:2.3:part:vendor:product:version:...
			if parts := strings.SplitN(cpe, ":", 6); len(parts) >= 5 && parts[4] == pkgName {
				return false
			}
		}
	}
	return true
}

// --- filtering ---

func filterVulns(vulns []vuln) []vuln {
	if !*onlyFixed {
		return vulns
	}
	out := make([]vuln, 0, len(vulns))
	for _, v := range vulns {
		if len(v.fixVersions) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// --- output ---

func formatReport(vulns []vuln) string {
	if len(vulns) == 0 {
		return "No vulnerabilities found.\n"
	}

	var sb strings.Builder

	type group struct {
		image string
		vulns []vuln
	}
	var order []string
	groups := make(map[string]*group)
	for _, v := range vulns {
		g, ok := groups[v.image]
		if !ok {
			order = append(order, v.image)
			g = &group{image: v.image}
			groups[v.image] = g
		}
		g.vulns = append(g.vulns, v)
	}

	for _, image := range order {
		g := groups[image]

		counts := make(map[string]int)
		for _, v := range g.vulns {
			counts[v.severity]++
		}
		var parts []string
		for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
			if n := counts[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}

		sb.WriteString(fmt.Sprintf("\n%s (%s)\n", image, strings.Join(parts, ", ")))
		sb.WriteString(strings.Repeat("─", 80) + "\n")

		tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "SEVERITY\tPACKAGE\tINSTALLED\tVULNERABILITY\tFIX\n")
		for _, v := range g.vulns {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", v.severity, v.pkg, v.version, v.id, v.fix())
		}
		tw.Flush()
	}
	sb.WriteString("\n")
	return sb.String()
}

// --- metrics ---

func recordMetrics(vulns []vuln) {
	vulnGauge.Reset()
	pkgsByImage := make(map[string]map[string]bool)
	for _, v := range vulns {
		if pkgsByImage[v.image] == nil {
			pkgsByImage[v.image] = make(map[string]bool)
		}
		pkgsByImage[v.image][v.pkg] = true
		if v.severity != "" {
			fixable := "no"
			if len(v.fixVersions) > 0 {
				fixable = "yes"
			}
			vulnGauge.WithLabelValues(v.image, v.severity, fixable, v.id, v.pkg).Set(1)
		}
	}
	for image, pkgs := range pkgsByImage {
		pkgGauge.WithLabelValues(image).Set(float64(len(pkgs)))
	}
}

// --- kubernetes config ---

func getK8sConfig(logger *slog.Logger) (*rest.Config, error) {
	if c, err := rest.InClusterConfig(); err == nil {
		logger.Info("using in-cluster config")
		return c, nil
	}
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if env := os.Getenv("KUBECONFIG"); env != "" {
		kubeconfig = env
	}
	c, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	logger.Info("using kubeconfig", "path", kubeconfig)
	return c, nil
}
