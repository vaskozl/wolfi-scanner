# wolfi-scanner

In-cluster vulnerability scanner for container images that ship Wolfi/Chainguard SBOMs.

It connects to the Kubernetes API, extracts SBOM files from running containers (`/var/lib/db/sbom`), and scans them with [Grype](https://github.com/anchore/grype).

## Features

- Scans running pods for SBOM-based vulnerability data
- Filters images by configurable prefixes (default: `cgr.dev/`)
- Automatically filters spurious CPE matches (e.g. broad NVD CPEs like `gitlab:gitlab` matching `gitlab-runner`) while keeping legitimate ones (e.g. `redis:redis` matching `redis`)
- Tabular CLI output grouped by image
- Prometheus metrics for alerting and dashboards
- Daemon mode with periodic scans and DB updates

## Usage

You can run this tool both interactively and in cluster. When in cluster it exposes `/metrics`.

```bash
% go run main.go -image-filter ghcr.io/vaskozl
time=2026-02-18T23:08:22.499Z level=INFO msg="using kubeconfig" path=/Users/vasko/.kube/config
time=2026-02-18T23:08:22.499Z level=INFO msg="loading vulnerability database"
time=2026-02-18T23:08:23.493Z level=INFO msg="database loaded" built=2026-02-18T14:37:10.000Z age=9h0m0s

ghcr.io/vaskozl/redis:8.6.0@sha256:530d8f29aa3b7b343623ee030b17c35fa7e9920e33216cef4dd1ae881e597143 (1 Low)
────────────────────────────────────────────────────────────────────────────────
SEVERITY  PACKAGE  INSTALLED  VULNERABILITY   FIX
Low       redis    8.6.0-r0   CVE-2025-49112  -

ghcr.io/vaskozl/sonarr:4.0.16@sha256:e84d53f89f4774dc62c2632300d31a3b40ff64e9c19b4f82825729ddf256830e (3 High, 1 Medium)
────────────────────────────────────────────────────────────────────────────────
SEVERITY  PACKAGE  INSTALLED   VULNERABILITY        FIX
High      glibc    2.42-r4     CVE-2025-15281       2.42-r7
Medium    busybox  1.37.0-r50  CVE-2025-60876       1.37.0-r52
High      glibc    2.42-r4     CVE-2026-0861        2.42-r6
High      glibc    2.42-r4     CVE-2026-0915        2.42-r6
Unknown   busybox  1.37.0-r50  GHSA-48hw-cv6f-mcpj  1.37.0-r52
Unknown   glibc    2.42-r4     GHSA-5pf6-63v3-88hw  2.42-r6
Unknown   glibc    2.42-r4     GHSA-qg56-4cfq-w9w3  2.42-r7
Unknown   glibc    2.42-r4     GHSA-xp56-6525-9chf  2.42-r6
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-daemon` | `false` | Run as daemon with periodic scans and metrics server |
| `-debug` | `false` | Enable debug logging and dump extracted SBOMs |
| `-test` | `false` | Only scan the first matching container |
| `-only-fixed` | `false` | Only report vulnerabilities with available fixes |
| `-image-filter` | `cgr.dev/` | Comma-separated list of image prefixes to match |
| `-scan-period` | `6h` | Time between scans (daemon mode) |

### Examples

One-shot scan of all `cgr.dev/` images in the cluster:

```
wolfi-scanner
```

Scan a specific image prefix:

```
wolfi-scanner -image-filter "ghcr.io/myorg/"
```

Multiple prefixes:

```
wolfi-scanner -image-filter "cgr.dev/,ghcr.io/myorg/"
```

Daemon mode (serves Prometheus metrics on `:9090`):

```
wolfi-scanner -daemon -scan-period 1h
```

### Output

Logs go to stderr, the vulnerability report goes to stdout:

```
ghcr.io/example/app (1 High, 1 Low)
────────────────────────────────────────────────────────────────────────────────
SEVERITY  PACKAGE  VULNERABILITY   FIX
High      git-lfs  CVE-2025-26625  3.7.1
Low       redis    CVE-2025-49112  -
```

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `scanner_vulnerabilities` | Gauge | `image`, `severity`, `fixable`, `id`, `pkg` | Current vulnerabilities per image |
| `scanner_packages` | Gauge | `image` | Package count per image |
| `scanner_duration_seconds` | Histogram | | Scan duration |
| `scanner_scans_total` | Counter | | Total scans performed |
| `scanner_errors_total` | Counter | | Total failed scans |
| `scanner_images_scanned` | Gauge | | Images scanned in last run |
| `scanner_last_scan_timestamp_seconds` | Gauge | | Unix timestamp of last scan |

## Alerting

See [`examples/vmrule-alerts.yaml`](examples/vmrule-alerts.yaml) for a VictoriaMetrics VMRule that fires alerts on:

- **ContainerCriticalVulns** -- Critical/High severity with a fix available (fires after 1d)
- **ContainerMediumVulnsFixAvailable** -- Medium severity with a fix available (fires after 7d)
- **ContainerTooManyVulns** -- More than 20 total vulnerabilities in one image (fires after 1d)

The alerts use the `scanner_vulnerabilities` gauge labels to include the CVE ID, package name, and image in the alert annotations.

Apply with:

```
kubectl apply -f examples/vmrule-alerts.yaml
```

## Building

```
go build -o wolfi-scanner .
```
