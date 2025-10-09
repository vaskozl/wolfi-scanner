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
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	"github.com/anchore/grype/grype/matcher/stock"
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
	appVersion       = "0.0.2"
	sbomDir          = "/var/lib/db/sbom"
	metricsAddr      = ":9090"
	healthPath       = "/health"
	metricsPath      = "/metrics"
	testModeLimit    = 1
	dbUpdateInterval = 24 * time.Hour
	httpReadTimeout  = 10 * time.Second
	httpWriteTimeout = 10 * time.Second
	httpIdleTimeout  = 120 * time.Second
	shutdownTimeout  = 5 * time.Second
)

var (
	daemon      = flag.Bool("daemon", false, "run as daemon with periodic scans and metrics server")
	testMode    = flag.Bool("test", false, "test mode: only process first container")
	onlyFixed   = flag.Bool("only-fixed", false, "only report vulnerabilities with available fixes")
	imageFilter = flag.String("image-filter", "ghcr.io/vaskozl", "filter to match container images")
	scanPeriod  = flag.Duration("scan-period", 6*time.Hour, "time between vulnerability scans (daemon mode only)")
	emailTo     = flag.String("email-to", "", "email address to send reports to (if empty, prints to stdout)")
	emailFrom   = flag.String("email-from", "", "email address to send reports from")
	smtpServer  = flag.String("smtp-server", "", "SMTP server address (e.g., smtp.gmail.com:587)")
	smtpUser    = flag.String("smtp-user", "", "SMTP authentication username (optional)")
	smtpPass    = flag.String("smtp-password", "", "SMTP authentication password (optional)")
)

// Errors
var (
	ErrNoSBOMFiles = errors.New("no SBOM files found")
)

// Prometheus metrics
var (
	vulnerabilities = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_vulnerabilities",
			Help: "Current number of vulnerabilities per image and severity",
		},
		[]string{"image", "severity", "fixable"},
	)
	packages = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scanner_packages",
			Help: "Number of packages per container image",
		},
		[]string{"image"},
	)
	scanDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "scanner_duration_seconds",
			Help:    "Duration of vulnerability scans",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
		},
	)
	scansTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "scanner_scans_total",
			Help: "Total number of vulnerability scans performed",
		},
	)
	scanErrors = prometheus.NewCounter(
	prometheus.CounterOpts{
			Name: "scanner_errors_total",
			Help: "Total number of failed scans",
		},
	)
	imagesScanned = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "scanner_images_scanned",
			Help: "Number of images scanned in last run",
		},
	)
	lastScanTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "scanner_last_scan_timestamp_seconds",
			Help: "Unix timestamp of last completed scan",
		},
	)
)

func init() {
	prometheus.MustRegister(
		vulnerabilities,
		packages,
		scanDuration,
		scansTotal,
		scanErrors,
		imagesScanned,
		lastScanTime,
	)
}

// scanner manages the vulnerability scanning process.
type scanner struct {
	store  vulnerability.Provider
	client *kubernetes.Clientset
	config *rest.Config
	logger *slog.Logger
}

type sbomData struct {
	files map[string]string
	image string
}

type vuln struct {
	fixVersions []string
	id          string
	pkg         string
	image       string
	severity    string
	desc        string
	dataSource  string
}

func main() {
	flag.Parse()

	logger := setupLogger()
	ctx, cancel := setupSignalHandler()
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error("application failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	config, err := getK8sConfig(logger)
	if err != nil {
		return fmt.Errorf("get kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	scanner, err := newScanner(ctx, client, config, logger)
	if err != nil {
		return fmt.Errorf("create scanner: %w", err)
	}

	if *daemon {
		return runDaemon(ctx, scanner)
	}

	return runOnce(ctx, scanner)
}

func runDaemon(ctx context.Context, s *scanner) error {
	s.logger.Info("starting daemon mode", "scan_period", *scanPeriod, "db_update_interval", dbUpdateInterval)

	go s.scanPeriodically(ctx)
	go s.updateDBPeriodically(ctx)

	return startMetricsServer(ctx, s.logger)
}

func runOnce(ctx context.Context, s *scanner) error {
	s.logger.Info("starting one-time scan")
	return s.scan(ctx)
}

func setupLogger() *slog.Logger {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

func setupSignalHandler() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
}

func newScanner(ctx context.Context, client *kubernetes.Clientset, config *rest.Config, logger *slog.Logger) (*scanner, error) {
	logger.Info("loading vulnerability database")

	appID := clio.Identification{
		Name:    appName,
		Version: appVersion,
	}

	store, status, err := grype.LoadVulnerabilityDB(
		v6dist.DefaultConfig(),
		v6inst.DefaultConfig(appID),
		true, // check for updates
	)
	if err != nil {
		return nil, fmt.Errorf("load vulnerability database: %w", err)
	}

	if status != nil {
		logger.Info("vulnerability database loaded",
			"built", status.Built,
			"age", time.Since(status.Built).Round(time.Hour))
	}

	return &scanner{
		client: client,
		config: config,
		store:  store,
		logger: logger,
	}, nil
}

func (s *scanner) scanPeriodically(ctx context.Context) {
	if err := s.scan(ctx); err != nil {
		s.logger.Error("initial scan failed", "error", err)
	}

	ticker := time.NewTicker(*scanPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping periodic scanner")
			return
		case <-ticker.C:
			if err := s.scan(ctx); err != nil {
				s.logger.Error("periodic scan failed", "error", err)
			}
		}
	}
}

func (s *scanner) updateDBPeriodically(ctx context.Context) {
	ticker := time.NewTicker(dbUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping DB updater")
			return
		case <-ticker.C:
			s.logger.Info("updating vulnerability database")
			appID := clio.Identification{Name: appName, Version: appVersion}
			store, status, err := grype.LoadVulnerabilityDB(
				v6dist.DefaultConfig(),
				v6inst.DefaultConfig(appID),
				true,
			)
			if err != nil {
				s.logger.Error("failed to update vulnerability database", "error", err)
				continue
			}
			s.store = store
			if status != nil {
				s.logger.Info("vulnerability database updated",
					"built", status.Built,
					"age", time.Since(status.Built).Round(time.Hour))
			}
		}
	}
}

func (s *scanner) scan(ctx context.Context) error {
	s.logger.Info("starting vulnerability scan")
	start := time.Now()

	sbomList, err := s.fetchSBOMs(ctx)
	if err != nil {
		scanDuration.Observe(time.Since(start).Seconds())
		scanErrors.Inc()
		return fmt.Errorf("fetch SBOMs: %w", err)
	}

	if len(sbomList) == 0 {
		s.logger.Info("no images found to scan")
		scanDuration.Observe(time.Since(start).Seconds())
		scansTotal.Inc()
		lastScanTime.SetToCurrentTime()
		return nil
	}

	vulns, err := s.findVulnerabilities(ctx, sbomList)
	if err != nil {
		scanDuration.Observe(time.Since(start).Seconds())
		scanErrors.Inc()
		return fmt.Errorf("find vulnerabilities: %w", err)
	}

	if err := s.handleResults(vulns); err != nil {
		scanDuration.Observe(time.Since(start).Seconds())
		scanErrors.Inc()
		return fmt.Errorf("handle results: %w", err)
	}

	// Record successful scan metrics
	scanDuration.Observe(time.Since(start).Seconds())
	scansTotal.Inc()
	imagesScanned.Set(float64(len(sbomList)))
	lastScanTime.SetToCurrentTime()

	s.logger.Info("scan completed",
		"duration", time.Since(start).Round(time.Second),
		"images_scanned", len(sbomList),
		"vulnerabilities", len(vulns))

	return nil
}

func (s *scanner) fetchSBOMs(ctx context.Context) ([]sbomData, error) {
	pods, err := s.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var result []sbomData
	seen := make(map[string]bool)
	processed := 0

	for _, pod := range pods.Items {
		for _, ctr := range pod.Spec.Containers {
			if !strings.Contains(ctr.Image, *imageFilter) {
				continue
			}

			if seen[ctr.Image] {
				continue
			}

			if *testMode && processed >= testModeLimit {
				s.logger.Info("test mode limit reached", "limit", testModeLimit)
				return result, nil
			}

			s.logger.Debug("extracting SBOM",
				"image", ctr.Image,
				"pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
				"container", ctr.Name)

			data, err := s.extractSBOM(ctx, pod.Namespace, pod.Name, ctr.Name, ctr.Image)
			if err != nil {
				if errors.Is(err, ErrNoSBOMFiles) {
					s.logger.Warn("no SBOM files in container", "image", ctr.Image)
				} else {
					s.logger.Warn("failed to extract SBOM", "image", ctr.Image, "error", err)
				}
				continue
			}

			result = append(result, *data)
			seen[ctr.Image] = true
			processed++
		}
	}

	return result, nil
}

func (s *scanner) extractSBOM(ctx context.Context, namespace, podName, containerName, image string) (*sbomData, error) {
	// Check if SBOM directory exists and has files
	checkCmd := []string{"sh", "-c", fmt.Sprintf("[ -d %s ] && [ -n \"$(ls -A %s 2>/dev/null)\" ] && echo ok || echo empty", sbomDir, sbomDir)}
	output, err := s.execInPod(ctx, namespace, podName, containerName, checkCmd)
	if err != nil {
		return nil, fmt.Errorf("check SBOM directory: %w", err)
	}

	if strings.TrimSpace(output) != "ok" {
		return nil, ErrNoSBOMFiles
	}

	// Use tar to stream all files at once (like kubectl cp)
	files, err := s.copyFilesFromPod(ctx, namespace, podName, containerName, sbomDir)
	if err != nil {
		return nil, fmt.Errorf("copy SBOM files: %w", err)
	}

	if len(files) == 0 {
		return nil, ErrNoSBOMFiles
	}

	return &sbomData{
		image: image,
		files: files,
	}, nil
}

// copyFilesFromPod copies all files from a directory in a pod using tar streaming.
// This is much more efficient than running cat for each file individually.
func (s *scanner) copyFilesFromPod(ctx context.Context, namespace, podName, containerName, srcPath string) (map[string]string, error) {
	// Create tar command to archive the directory
	cmd := []string{"tar", "cf", "-", "-C", srcPath, "."}

	req := s.client.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", containerName).
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd,
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.config, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("create executor: %w", err)
	}

	// Capture stdout (tar stream) and stderr
	reader, writer := io.Pipe()
	var stderr strings.Builder

	go func() {
		defer writer.Close()
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: writer,
			Stderr: &stderr,
		}); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Debug("tar stream error", "error", err, "stderr", stderr.String())
		}
	}()

	// Extract files from tar stream
	files := make(map[string]string)
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar header: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Read file content
		content, err := io.ReadAll(tarReader)
		if err != nil {
			s.logger.Warn("failed to read file from tar", "file", header.Name, "error", err)
			continue
		}

		files[header.Name] = string(content)
	}

	return files, nil
}

func (s *scanner) execInPod(ctx context.Context, namespace, podName, containerName string, cmd []string) (string, error) {
	req := s.client.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", containerName).
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd,
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr strings.Builder
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", fmt.Errorf("exec failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

func (s *scanner) findVulnerabilities(ctx context.Context, sbomList []sbomData) ([]vuln, error) {
	var result []vuln

	// Track metrics per image
	type imageMetrics struct {
		packages    map[string]bool
		fixable     map[string]int // severity -> count
		unfixable   map[string]int // severity -> count
	}
	metrics := make(map[string]*imageMetrics)

	for _, data := range sbomList {
		if metrics[data.image] == nil {
			metrics[data.image] = &imageMetrics{
				packages:  make(map[string]bool),
				fixable:   make(map[string]int),
				unfixable: make(map[string]int),
			}
		}

		// Aggregate all packages from all SBOM files for this image
		matches, err := s.scanAggregatedSBOMs(data)
			if err != nil {
			s.logger.Warn("scan failed", "image", data.image, "error", err)
				continue
			}

		for _, m := range matches.Sorted() {
			v := s.matchToVuln(m, data.image)
			result = append(result, v)

			// Track unique packages
			metrics[data.image].packages[v.pkg] = true

			// Track vulnerabilities by severity and fixability
			if v.severity != "" {
				if len(v.fixVersions) > 0 {
					metrics[data.image].fixable[v.severity]++
				} else {
					metrics[data.image].unfixable[v.severity]++
				}
			}
		}
	}

	// Record metrics per image
	for image, m := range metrics {
		packages.WithLabelValues(image).Set(float64(len(m.packages)))

		// Record vulnerabilities by severity and fixability
		for severity, count := range m.fixable {
			vulnerabilities.WithLabelValues(image, severity, "yes").Set(float64(count))
		}
		for severity, count := range m.unfixable {
			vulnerabilities.WithLabelValues(image, severity, "no").Set(float64(count))
		}
	}

	return result, nil
}

func (s *scanner) scanAggregatedSBOMs(data sbomData) (match.Matches, error) {
	var packages []syftPkg.Package
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

		for _, p := range sbom.Artifacts.Packages.Sorted() {
			if s.isMetadataArtifact(p, distro) {
				continue
			}
			packages = append(packages, p)
		}
	}

	if len(packages) == 0 {
		return match.Matches{}, nil
	}

	var grypeDistro *grypedistro.Distro
	if distro != nil {
		grypeDistro = grypedistro.New(grypedistro.Type(distro.ID), distro.VersionID, "", distro.IDLike...)
	}

	grypePackages := grypePkg.FromPackages(packages, grypePkg.SynthesisConfig{
		GenerateMissingCPEs: true,
		Distro:              grypePkg.DistroConfig{Override: grypeDistro},
	})

	s.logger.Debug("scanning packages", "image", data.image, "packages", len(grypePackages))

	vulnMatcher := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: s.store,
		Matchers: matcher.NewDefaultMatchers(matcher.Config{
			Stock: stock.MatcherConfig{UseCPEs: true},
		}),
		NormalizeByCVE: true,
	}

	matches, _, err := vulnMatcher.FindMatches(grypePackages, grypePkg.Context{
		Source: src,
		Distro: grypeDistro,
	})
	if err != nil {
		return match.Matches{}, fmt.Errorf("find matches: %w", err)
	}

	return *matches, nil
}

func (s *scanner) isMetadataArtifact(p syftPkg.Package, distro *linux.Release) bool {
	if strings.HasSuffix(p.Name, ".yaml") || strings.HasSuffix(p.Name, ".yml") {
		return true
	}
	if string(p.Type) == "" || p.Type == "UnknownPackage" {
		return true
	}
	if p.Name == "wolfi" || (distro != nil && p.Name == distro.Name) {
		return true
	}
	return false
}

func (s *scanner) matchToVuln(m match.Match, imageName string) vuln {
	v := vuln{
		id:    m.Vulnerability.ID,
		pkg:   m.Package.Name,
		image: imageName,
	}

	if m.Vulnerability.Metadata != nil {
		v.severity = m.Vulnerability.Metadata.Severity
		v.desc = m.Vulnerability.Metadata.Description
		v.dataSource = m.Vulnerability.Metadata.DataSource
	}

	if m.Vulnerability.Fix.State == "fixed" {
		v.fixVersions = m.Vulnerability.Fix.Versions
	}

	return v
}

func (s *scanner) handleResults(vulns []vuln) error {
	if *onlyFixed {
		filtered := make([]vuln, 0, len(vulns))
		for _, v := range vulns {
			if len(v.fixVersions) > 0 {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
	}

	if len(vulns) == 0 {
		s.logger.Info("no vulnerabilities found")
		fmt.Println("No vulnerabilities found in any scanned images.")
		return nil
	}

	report := formatReport(vulns)

	if *emailTo == "" {
		fmt.Print(report)
		return nil
	}

	if err := sendEmail(report); err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	s.logger.Info("email sent", "to", *emailTo)
	return nil
}

func formatReport(vulns []vuln) string {
	var sb strings.Builder

	severityCounts := make(map[string]int)
	fixableCounts := make(map[string]int)
	for _, v := range vulns {
		severityCounts[v.severity]++
		if len(v.fixVersions) > 0 {
			fixableCounts[v.severity]++
		}
	}

	sb.WriteString("=== Vulnerability Summary ===\n")
	sb.WriteString(fmt.Sprintf("Total: %d vulnerabilities\n", len(vulns)))
	for _, severity := range []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"} {
		if count := severityCounts[severity]; count > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d (%d fixable)\n", severity, count, fixableCounts[severity]))
		}
	}
	sb.WriteString("\n=== Detailed Findings ===\n\n")

	for _, v := range vulns {
		sb.WriteString(fmt.Sprintf("%s: %s in %s affected by %s: %s\n  %s\n",
			v.severity, v.pkg, v.image, v.id, v.dataSource, v.desc))

		if len(v.fixVersions) > 0 {
			sb.WriteString("  Update to: " + strings.Join(v.fixVersions, ", ") + "\n")
		} else {
			sb.WriteString("  No fix available :(\n")
		}
		sb.WriteString(fmt.Sprintf("  * %s\n\n", v.image))
	}

	return sb.String()
}

func sendEmail(report string) error {
	if *smtpServer == "" || *emailFrom == "" {
		return errors.New("smtp-server and email-from are required")
	}

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\nTo: %s\r\n", *emailFrom, *emailTo))
	msg.WriteString("Subject: Vulnerability Scan Report\r\n")
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.WriteString(report)

	var auth smtp.Auth
	if *smtpUser != "" {
		host := *smtpServer
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		auth = smtp.PlainAuth("", *smtpUser, *smtpPass, host)
	}

	return smtp.SendMail(*smtpServer, auth, *emailFrom, []string{*emailTo}, []byte(msg.String()))
}

func getK8sConfig(logger *slog.Logger) (*rest.Config, error) {
	if config, err := rest.InClusterConfig(); err == nil {
		logger.Info("using in-cluster kubernetes config")
		return config, nil
	}

	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if env := os.Getenv("KUBECONFIG"); env != "" {
		kubeconfig = env
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	logger.Info("using local kubeconfig", "path", kubeconfig)
	return config, nil
}

func startMetricsServer(ctx context.Context, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc(healthPath, handleHealth)

	server := &http.Server{
		Addr:         metricsAddr,
		Handler:      mux,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
		IdleTimeout:  httpIdleTimeout,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("metrics server shutdown failed", "error", err)
		}
	}()

	logger.Info("starting metrics server", "addr", metricsAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server failed: %w", err)
	}

	return nil
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
