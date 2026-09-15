package main

import (
	"net/http"

	"github.com/Mesverrum/snmp-sd/snmpdiscovery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Same names as Alloy discovery.snmp so one dashboard works for the CLI and the component.
type cliMetrics struct {
	scans        prometheus.Counter
	failures     prometheus.Counter
	skipped      prometheus.Counter
	duration     prometheus.Histogram
	scanInFlight prometheus.Gauge
	devices      *prometheus.GaugeVec
	targets      *prometheus.GaugeVec
	sweep        prometheus.Gauge
	pingUp       prometheus.Gauge
	pingDead     prometheus.Gauge
	dropped      prometheus.Counter
	dedupes      prometheus.Gauge
	stale        *prometheus.GaugeVec
	probes       *prometheus.CounterVec
	probeErrors  *prometheus.CounterVec
	inFlight     prometheus.Gauge
	probeOK      prometheus.Gauge
	probeErrs    prometheus.Gauge
	firstAuth    *prometheus.CounterVec
	authFallback *prometheus.CounterVec
	authFailures prometheus.Counter
	probeRetries prometheus.Counter
	fingerprint  *prometheus.CounterVec
	modDropped   *prometheus.CounterVec
	deviceInfo   *prometheus.GaugeVec
}

func newCLIMetrics(reg prometheus.Registerer) *cliMetrics {
	m := &cliMetrics{
		scans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scans_total",
			Help: "SNMP discovery scans that ran to completion.",
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scan_failures_total",
			Help: "SNMP discovery scans that failed.",
		}),
		skipped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scan_skipped_total",
			Help: "Scan ticks skipped because a previous scan was still running.",
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "discovery_snmp_scan_duration_seconds",
			Help:    "Duration of completed SNMP discovery scans.",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600},
		}),
		scanInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_scan_in_progress",
			Help: "1 while an SNMP discovery scan is running.",
		}),
		devices: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_devices",
			Help: "Devices in the last successful catalog.",
		}, []string{"group"}),
		targets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_targets",
			Help: "Targets in the last successful catalog by scrape tier.",
		}, []string{"tier"}),
		sweep: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_sweep_addresses",
			Help: "Addresses considered by the last CIDR sweep.",
		}),
		pingUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_ping_up",
			Help: "Addresses that passed the ICMP filter last scan.",
		}),
		pingDead: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_ping_dead",
			Help: "Addresses the ICMP filter dropped last scan.",
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_dropped_total",
			Help: "Devices dropped after consecutive silent cycles.",
		}),
		dedupes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_dedupes",
			Help: "Addresses folded into another sysName last scan.",
		}),
		stale: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_catalog_stale",
			Help: "Catalog entries with Misses > 0 after the last scan.",
		}, []string{"group"}),
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probes_total",
			Help: "SNMP identity probes (one per address).",
		}, []string{"result", "group"}),
		probeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_errors_total",
			Help: "Identity probe failures by reason.",
		}, []string{"reason", "group"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probes_in_flight",
			Help: "Identity probes currently running.",
		}),
		probeOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probe_successes",
			Help: "Successful identity probes on the last scan.",
		}),
		probeErrs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probe_errors",
			Help: "Failed identity probes on the last scan.",
		}),
		firstAuth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_first_auth_success_total",
			Help: "Probes that succeeded on the first named auth.",
		}, []string{"group"}),
		authFallback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_fallback_total",
			Help: "Probes that succeeded only after an earlier named auth failed.",
		}, []string{"group", "auth"}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_failures_total",
			Help: "Named-auth attempts that failed.",
		}),
		probeRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_retries_total",
			Help: "Extra SNMP Get attempts after the first try for an auth.",
		}),
		fingerprint: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_fingerprint_total",
			Help: "Fingerprint outcome: known matcher vs default/unknown chain.",
		}, []string{"result", "group"}),
		modDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_modules_dropped_total",
			Help: "Fingerprinter module names missing from snmp.yml.",
		}, []string{"group"}),
		deviceInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_device_info",
			Help: "Last-good catalog identity (1 per device).",
		}, []string{"address", "device_name", "sysObjectID", "group", "auth"}),
	}
	if reg != nil {
		reg.MustRegister(
			m.scans, m.failures, m.skipped, m.duration, m.scanInFlight,
			m.devices, m.targets, m.sweep, m.pingUp, m.pingDead,
			m.dropped, m.dedupes, m.stale, m.probes, m.probeErrors,
			m.inFlight, m.probeOK, m.probeErrs, m.firstAuth, m.authFallback,
			m.authFailures, m.probeRetries, m.fingerprint, m.modDropped, m.deviceInfo,
		)
	}
	return m
}

func (m *cliMetrics) ProbeBegin() {
	if m == nil {
		return
	}
	m.inFlight.Inc()
}

func (m *cliMetrics) ProbeEnd(d snmpdiscovery.ProbeDetail) {
	if m == nil {
		return
	}
	m.inFlight.Dec()
	group := labelOrUnknown(d.Group)
	if d.Success {
		m.probes.WithLabelValues("success", group).Inc()
		if d.FirstAuth {
			m.firstAuth.WithLabelValues(group).Inc()
		} else {
			m.authFallback.WithLabelValues(group, labelOrUnknown(d.Auth)).Inc()
		}
	} else {
		m.probes.WithLabelValues("error", group).Inc()
		reason := d.Reason
		if reason == "" || reason == snmpdiscovery.ProbeReasonOK {
			reason = snmpdiscovery.ProbeReasonOther
		}
		m.probeErrors.WithLabelValues(reason, group).Inc()
	}
	if d.AuthFails > 0 {
		m.authFailures.Add(float64(d.AuthFails))
	}
	if d.Retries > 0 {
		m.probeRetries.Add(float64(d.Retries))
	}
}

func (m *cliMetrics) DeviceFound(d snmpdiscovery.DeviceFoundDetail) {
	if m == nil {
		return
	}
	group := labelOrUnknown(d.Group)
	result := d.Fingerprint
	if result == "" {
		result = snmpdiscovery.FingerprintUnknown
	}
	m.fingerprint.WithLabelValues(result, group).Inc()
	if n := len(d.DroppedModules); n > 0 {
		m.modDropped.WithLabelValues(group).Add(float64(n))
	}
}

func (m *cliMetrics) observeScan(stats snmpdiscovery.ScanStats, published []snmpdiscovery.AlloyTarget, cat *snmpdiscovery.Catalog, tiers []string) {
	if m == nil {
		return
	}
	m.scans.Inc()
	m.duration.Observe(stats.Duration.Seconds())
	m.sweep.Set(float64(stats.Sweep))
	m.pingUp.Set(float64(stats.PingUp))
	dead := stats.Sweep - stats.PingUp
	if dead < 0 {
		dead = 0
	}
	m.pingDead.Set(float64(dead))
	m.probeOK.Set(float64(stats.ProbeSuccess))
	m.probeErrs.Set(float64(stats.ProbeErrors))
	m.dedupes.Set(float64(stats.Dedupes))
	if stats.Dropped > 0 {
		m.dropped.Add(float64(stats.Dropped))
	}

	m.devices.Reset()
	m.stale.Reset()
	m.deviceInfo.Reset()
	byGroup := map[string]int{}
	if cat != nil {
		for _, e := range cat.SnapshotEntries() {
			g := labelOrUnknown(e.Target.SnmpGroup)
			byGroup[g]++
			if e.Misses > 0 {
				m.stale.WithLabelValues(g).Inc()
			}
			m.deviceInfo.WithLabelValues(
				e.Target.Address,
				e.Target.DeviceName,
				e.Target.SysObjectID,
				g,
				labelOrUnknown(e.Target.Auth),
			).Set(1)
		}
	} else {
		for _, t := range published {
			byGroup[labelOrUnknown(t.SnmpGroup)]++
		}
	}
	for g, n := range byGroup {
		m.devices.WithLabelValues(g).Set(float64(n))
	}

	m.targets.Reset()
	if len(tiers) == 0 {
		tiers = append([]string{}, snmpdiscovery.AllTiers...)
	}
	for _, tier := range tiers {
		m.targets.WithLabelValues(tier).Set(float64(len(snmpdiscovery.TierTargets(published, tier))))
	}
}

func labelOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func metricsHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
