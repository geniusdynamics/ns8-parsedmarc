#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Cluster metrics: what this module gives to the NS8 metrics module
(ns8-metrics: Prometheus, Alertmanager and Grafana on the leader node).

- Metrics: bin/export-metrics prints aggregate DMARC counts in the
  Prometheus text format. The node runs it every 5 minutes and serves the
  output through its node_exporter, which Prometheus already scrapes, with
  the module="<module_id>" label (copied to module_id by ns8-metrics). No
  port, no listener, no process of the module: core 3.24.0 or later.
- Alert rules: Redis hash module/<id>/metrics_alert_rules, field
  "parsedmarc", event metrics-alert-rules-changed.
- Dashboard: Redis hash module/<id>/metrics_dashboards, field
  "parsedmarc", event metrics-dashboard-changed. It queries only the
  Prometheus datasource of ns8-metrics (uid "prometheus"): no OpenSearch
  datasource, no password leaves the module.

ns8-metrics scans module/*/metrics_* whenever it provisions, so the keys
can be published before it is installed. Only aggregate counts per tenant
and domain are exported: never source addresses, never message samples.
"""

import base64
import json
import math
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import agent

RULES_FIELD = "parsedmarc"
DASHBOARD_FIELD = "parsedmarc"
PROMETHEUS_UID = "prometheus"   # datasource uid provisioned by ns8-metrics

WINDOW = "7d"            # counts: reports whose period began in the last 7 days
LAST_REPORT_WINDOW = "30d"   # last report timestamp: domains seen in 30 days
MAX_DOMAINS = 500        # per tenant and report type: bounded cardinality
DEADLINE = 20            # seconds; the node kills export-metrics after 30
REQUEST_TIMEOUT = 8

# Unprefixed indices hold the domains of no tenant: label tenant="default",
# a reserved tenant name, so it never clashes with a real tenant
DEFAULT_TENANT = "default"

# Index name start of each report type without a tenant prefix
AGGREGATE_BASE = "dmarc_aggregate"
FAILURE_BASE = "dmarc_f"        # dmarc_failure-*, older dmarc_forensic-*
SMTP_TLS_BASE = "smtp_tls"

# (name, help) of every exported family, in output order
FAMILIES = [
    ("parsedmarc_up",
     "1 if the report storage (OpenSearch or Elasticsearch) answered every query of the last collection"),
    ("parsedmarc_collect_duration_seconds",
     "Time spent collecting these metrics"),
    ("parsedmarc_collect_timestamp_seconds",
     "Unix time of the collection; old values mean export-metrics no longer runs"),
    ("parsedmarc_aggregate_messages_7d",
     "Messages in the DMARC aggregate reports whose period began in the last 7 days, by DMARC result"),
    ("parsedmarc_aggregate_dkim_aligned_messages_7d",
     "Messages of the last 7 days aggregate reports with an aligned DKIM pass"),
    ("parsedmarc_aggregate_spf_aligned_messages_7d",
     "Messages of the last 7 days aggregate reports with an aligned SPF pass"),
    ("parsedmarc_aggregate_reports_7d",
     "DMARC aggregate reports whose period began in the last 7 days"),
    ("parsedmarc_aggregate_last_report_timestamp_seconds",
     "End of the period of the newest aggregate report, for the domains with reports in the last 30 days"),
    ("parsedmarc_failure_reports_7d",
     "DMARC failure (forensic) reports that arrived in the last 7 days"),
    ("parsedmarc_smtp_tls_sessions_7d",
     "Sessions in the SMTP TLS reports whose period began in the last 7 days, by result"),
    ("parsedmarc_mailbox_watcher_up",
     "1 if the parsedmarc process reading the mailbox is running"),
]


def log(message):
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# Prometheus text format
# --------------------------------------------------------------------------

def _escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _number(value):
    value = float(value)
    if math.isfinite(value) and value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def format_metrics(samples):
    """samples: {family: [(labels dict, value)]} -> Prometheus text"""
    out = []
    for name, help_text in FAMILIES:
        rows = samples.get(name)
        if not rows:
            continue
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} gauge")
        for labels, value in rows:
            if labels:
                lbl = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
                out.append(f"{name}{{{lbl}}} {_number(value)}")
            else:
                out.append(f"{name} {_number(value)}")
    return "\n".join(out) + "\n" if out else ""


# --------------------------------------------------------------------------
# Report storage queries
# --------------------------------------------------------------------------

class Backend:
    """Read-only client of the report storage. Bundled: the 'grafana'
    account (read access to the report indices only), TLS verified with the
    private CA. External: the configured account."""

    def __init__(self, settings, read_secret, opensearch_port=None, ca_file=None, deadline=None):
        self.deadline = deadline or (time.time() + DEADLINE)
        self.skip_verify = False
        if settings["backend"] == "bundled":
            self.url = f"https://127.0.0.1:{opensearch_port}"
            self.user = "grafana"
            self.password = read_secret("grafana_password")
            self.ca_file = ca_file
        else:
            url = settings["external_hosts"].split(",")[0].strip()
            if not url.startswith("http"):
                url = ("https://" if settings["external_ssl"] else "http://") + url
            self.url = url.rstrip("/")
            self.user = settings["external_user"]
            self.password = read_secret("external_password")
            self.ca_file = None
            self.skip_verify = settings["external_skip_verify"]

    def _context(self):
        # Built per request: a missing CA file is a failed query, not a crash
        ctx = ssl.create_default_context(cafile=self.ca_file)
        if self.skip_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def search(self, index, body):
        remaining = self.deadline - time.time()
        if remaining <= 1:
            raise TimeoutError("collection deadline reached")
        url = f"{self.url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        headers = {"Content-Type": "application/json"}
        if self.user:
            token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            headers["Authorization"] = "Basic " + token
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
        kwargs = {"timeout": min(REQUEST_TIMEOUT, remaining)}
        if url.startswith("https"):
            kwargs["context"] = self._context()
        try:
            with urllib.request.urlopen(req, **kwargs) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as ex:
            # The body may echo the query, never the credentials
            raise RuntimeError(f"search {index}: HTTP {ex.code}") from None


def tenant_filters(tenants, base):
    """filters aggregation: one bucket per tenant (index prefix
    <tenant>_<base>) and one for the unprefixed indices. Tenant names are
    lowercase letters and digits, so no prefix contains another one."""
    filters = {DEFAULT_TENANT: {"prefix": {"_index": base}}}
    for name in tenants:
        filters[name] = {"prefix": {"_index": f"{name}_{base}"}}
    return {"filters": {"filters": filters}}


def _sum(field):
    return {"sum": {"field": field}}


def _filtered_sum(term_field, field):
    return {"filter": {"term": {term_field: True}}, "aggs": {"m": _sum(field)}}


def aggregate_query(tenants):
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {"date_begin": {"gte": f"now-{LAST_REPORT_WINDOW}"}}},
        "aggs": {"t": dict(tenant_filters(tenants, AGGREGATE_BASE), aggs={"d": {
            "terms": {"field": "published_policy.domain.keyword", "size": MAX_DOMAINS},
            "aggs": {
                "last": {"max": {"field": "date_end"}},
                "w": {
                    "filter": {"range": {"date_begin": {"gte": f"now-{WINDOW}"}}},
                    "aggs": {
                        "messages": _sum("message_count"),
                        "pass": _filtered_sum("passed_dmarc", "message_count"),
                        "dkim": _filtered_sum("dkim_aligned", "message_count"),
                        "spf": _filtered_sum("spf_aligned", "message_count"),
                        "reports": {"cardinality": {"field": "report_id.keyword"}},
                    },
                },
            },
        }})},
    }


def failure_query(tenants):
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {"arrival_date": {"gte": f"now-{WINDOW}"}}},
        "aggs": {"t": dict(tenant_filters(tenants, FAILURE_BASE), aggs={"d": {
            "terms": {"field": "domain.keyword", "size": MAX_DOMAINS}}})},
    }


def smtp_tls_query(tenants):
    # policies is a dynamic object array, not nested: a report about
    # several policy domains counts its sessions for each of them
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {"date_begin": {"gte": f"now-{WINDOW}"}}},
        "aggs": {"t": dict(tenant_filters(tenants, SMTP_TLS_BASE), aggs={"d": {
            "terms": {"field": "policies.policy_domain.keyword", "size": MAX_DOMAINS},
            "aggs": {
                "ok": _sum("policies.successful_session_count"),
                "failed": _sum("policies.failed_session_count"),
            },
        }})},
    }


def _buckets(response):
    """[(tenant, domain bucket)] of a tenant/domain response"""
    out = []
    tenants = ((response.get("aggregations") or {}).get("t") or {}).get("buckets") or {}
    for tenant, tb in sorted(tenants.items()):
        for db in (tb.get("d") or {}).get("buckets") or []:
            if db.get("key"):
                out.append((tenant, db))
    return out


def _value(agg, default=0):
    if not agg:
        return default
    value = agg.get("value")
    return default if value is None else value


def parse_aggregate(response, samples):
    for tenant, db in _buckets(response):
        lbl = {"tenant": tenant, "domain": db["key"]}
        w = db.get("w") or {}
        total = _value(w.get("messages"))
        passed = _value((w.get("pass") or {}).get("m"))
        samples["parsedmarc_aggregate_messages_7d"].append((dict(lbl, dmarc="pass"), passed))
        samples["parsedmarc_aggregate_messages_7d"].append((dict(lbl, dmarc="fail"), max(total - passed, 0)))
        samples["parsedmarc_aggregate_dkim_aligned_messages_7d"].append(
            (lbl, _value((w.get("dkim") or {}).get("m"))))
        samples["parsedmarc_aggregate_spf_aligned_messages_7d"].append(
            (lbl, _value((w.get("spf") or {}).get("m"))))
        samples["parsedmarc_aggregate_reports_7d"].append((lbl, _value(w.get("reports"))))
        last = _value(db.get("last"), None)
        if last is not None:
            samples["parsedmarc_aggregate_last_report_timestamp_seconds"].append((lbl, int(last) // 1000))


def parse_failure(response, samples):
    for tenant, db in _buckets(response):
        samples["parsedmarc_failure_reports_7d"].append(
            ({"tenant": tenant, "domain": db["key"]}, db.get("doc_count", 0)))


def parse_smtp_tls(response, samples):
    for tenant, db in _buckets(response):
        lbl = {"tenant": tenant, "domain": db["key"]}
        samples["parsedmarc_smtp_tls_sessions_7d"].append((dict(lbl, result="successful"), _value(db.get("ok"))))
        samples["parsedmarc_smtp_tls_sessions_7d"].append((dict(lbl, result="failed"), _value(db.get("failed"))))


def watcher_states(instances, runner=subprocess.run):
    """{instance: 1|0} from systemctl --user is-active"""
    if not instances:
        return {}
    units = [f"parsedmarc-watch@{i}.service" for i in instances]
    try:
        res = runner(["systemctl", "--user", "is-active", *units], capture_output=True, text=True, timeout=5)
        states = res.stdout.split()
    except Exception as ex:
        log(f"watcher states not available: {ex}")
        return {}
    if len(states) != len(units):
        return {}
    return {i: int(s == "active") for i, s in zip(instances, states)}


def collect(settings, backend, instances, runner=subprocess.run, now=time.time):
    """Run the queries; return the samples dict. Never raises for a backend
    failure: parsedmarc_up is 0 then."""
    start = now()
    samples = {name: [] for name, _ in FAMILIES}
    tenants = [t["name"] for t in settings["tenants"]]
    up = 1
    try:
        parse_aggregate(backend.search(f"*{AGGREGATE_BASE}*", aggregate_query(tenants)), samples)
        parse_failure(backend.search(f"*{FAILURE_BASE}*", failure_query(tenants)), samples)
        parse_smtp_tls(backend.search(f"*{SMTP_TLS_BASE}*", smtp_tls_query(tenants)), samples)
    except Exception as ex:
        log(agent.SD_WARNING + f"report storage query failed: {ex}")
        up = 0
        # Partial results would look like a drop of the traffic
        for name in list(samples):
            samples[name] = []
    for inst, state in watcher_states(instances, runner).items():
        samples["parsedmarc_mailbox_watcher_up"].append(({"mailbox": inst}, state))
    end = now()
    samples["parsedmarc_up"] = [({}, up)]
    samples["parsedmarc_collect_duration_seconds"] = [({}, round(end - start, 3))]
    samples["parsedmarc_collect_timestamp_seconds"] = [({}, int(end))]
    return samples


# --------------------------------------------------------------------------
# Alert rules
# --------------------------------------------------------------------------

AGG = "parsedmarc_aggregate_messages_7d"


def alert_rules():
    """Rule file for module/<id>/metrics_alert_rules. ns8-metrics adds the
    module_id matcher to every selector and the module_id label."""
    rules = [
        {
            "alert": "ParsedmarcStorageDown",
            "expr": "parsedmarc_up == 0",
            "for": "15m",
            "labels": {"severity": "critical"},
            "annotations": {
                "summary_en": "parsedmarc cannot read its report storage",
                "summary_it": "parsedmarc non riesce a leggere l'archivio dei report",
                "description_en": "The OpenSearch or Elasticsearch storage of {{ $labels.module_id }} did not answer "
                                  "for 15 minutes: new DMARC reports may not be stored.",
                "description_it": "L'archivio OpenSearch o Elasticsearch di {{ $labels.module_id }} non risponde "
                                  "da 15 minuti: i nuovi report DMARC potrebbero non essere salvati.",
            },
        },
        {
            "alert": "ParsedmarcMetricsStale",
            "expr": "time() - parsedmarc_collect_timestamp_seconds > 1800",
            "for": "5m",
            "labels": {"severity": "warning"},
            "annotations": {
                "summary_en": "parsedmarc metrics are not updated",
                "summary_it": "Le metriche di parsedmarc non sono aggiornate",
                "description_en": "The metrics of {{ $labels.module_id }} were collected more than 30 minutes ago: "
                                  "export-metrics fails or times out, see the node log "
                                  "(refresh-module-metrics).",
                "description_it": "Le metriche di {{ $labels.module_id }} risalgono a più di 30 minuti fa: "
                                  "export-metrics fallisce o va in timeout, vedere il log del nodo "
                                  "(refresh-module-metrics).",
            },
        },
        {
            "alert": "ParsedmarcMailboxWatcherDown",
            "expr": "parsedmarc_mailbox_watcher_up == 0",
            "for": "15m",
            "labels": {"severity": "warning"},
            "annotations": {
                "summary_en": "parsedmarc does not read the mailbox {{ $labels.mailbox }}",
                "summary_it": "parsedmarc non legge la casella {{ $labels.mailbox }}",
                "description_en": "The process reading the reports of mailbox {{ $labels.mailbox }} of "
                                  "{{ $labels.module_id }} is not running for 15 minutes.",
                "description_it": "Il processo che legge i report della casella {{ $labels.mailbox }} di "
                                  "{{ $labels.module_id }} non è attivo da 15 minuti.",
            },
        },
        {
            "alert": "ParsedmarcDmarcFailureRateHigh",
            "expr": (f'sum by (node, tenant, domain) ({AGG}{{dmarc="fail"}})\n'
                     f'  / sum by (node, tenant, domain) ({AGG}) > 0.1\n'
                     f'and sum by (node, tenant, domain) ({AGG}) > 100'),
            "for": "1h",
            "labels": {"severity": "warning"},
            "annotations": {
                "summary_en": "Many messages of {{ $labels.domain }} fail DMARC",
                "summary_it": "Molti messaggi di {{ $labels.domain }} non superano DMARC",
                "description_en": "{{ $value | humanizePercentage }} of the messages from {{ $labels.domain }} "
                                  "(tenant {{ $labels.tenant }}) in the aggregate reports of the last 7 days "
                                  "fail DMARC: a legitimate sender is not aligned, or someone spoofs the domain.",
                "description_it": "Il {{ $value | humanizePercentage }} dei messaggi di {{ $labels.domain }} "
                                  "(tenant {{ $labels.tenant }}) nei report aggregati degli ultimi 7 giorni "
                                  "non supera DMARC: un mittente legittimo non è allineato, oppure qualcuno "
                                  "falsifica il dominio.",
            },
        },
        {
            "alert": "ParsedmarcNoAggregateReport",
            "expr": "time() - parsedmarc_aggregate_last_report_timestamp_seconds > 259200",
            "for": "1h",
            "labels": {"severity": "warning"},
            "annotations": {
                "summary_en": "No DMARC aggregate report for {{ $labels.domain }}",
                "summary_it": "Nessun report aggregato DMARC per {{ $labels.domain }}",
                "description_en": "The newest aggregate report about {{ $labels.domain }} (tenant "
                                  "{{ $labels.tenant }}) is older than 72 hours: check the mailbox, the rua "
                                  "address of the DMARC record and the watcher log.",
                "description_it": "Il report aggregato più recente per {{ $labels.domain }} (tenant "
                                  "{{ $labels.tenant }}) ha più di 72 ore: controllare la casella, l'indirizzo "
                                  "rua del record DMARC e il log del processo di lettura.",
            },
        },
    ]
    # JSON is YAML
    return json.dumps({"groups": [{"name": "parsedmarc", "rules": rules}]}, indent=1, ensure_ascii=False)


# --------------------------------------------------------------------------
# Grafana dashboard (Prometheus datasource of ns8-metrics)
# --------------------------------------------------------------------------

def dashboard_uid(module_id):
    # Grafana uids: at most 40 characters; module IDs are short
    return f"parsedmarc-{module_id}"[:40]


def dashboard(module_id):
    ds = {"type": "prometheus", "uid": PROMETHEUS_UID}
    sel = f'module_id="{module_id}",tenant=~"$tenant",domain=~"$domain"'

    def target(expr, ref="A", legend="", instant=False, fmt="time_series"):
        t = {"datasource": ds, "expr": expr, "refId": ref, "legendFormat": legend, "format": fmt}
        if instant:
            t.update(instant=True, range=False)
        return t

    panels = []

    def stat(pid, title, expr, x, unit="short", mappings=None, thresholds=None, desc=""):
        panels.append({
            "id": pid, "type": "stat", "title": title, "description": desc, "datasource": ds,
            "gridPos": {"h": 4, "w": 4, "x": x, "y": 0},
            "targets": [target(expr, instant=True)],
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": "value", "graphMode": "none", "textMode": "auto"},
            "fieldConfig": {"defaults": {
                "unit": unit, "mappings": mappings or [],
                "thresholds": thresholds or {"mode": "absolute", "steps": [{"color": "text", "value": None}]},
            }, "overrides": []},
        })

    stat(1, "Report storage", f'min(parsedmarc_up{{module_id="{module_id}"}})', 0,
         mappings=[{"type": "value", "options": {"0": {"text": "Down", "color": "red"},
                                                 "1": {"text": "Up", "color": "green"}}}],
         desc="OpenSearch or Elasticsearch answered the last collection")
    stat(2, "Messages (7 days)", f"sum({AGG}{{{sel}}})", 4,
         desc="Messages in the aggregate reports whose period began in the last 7 days")
    stat(3, "DMARC pass (7 days)", f'sum({AGG}{{{sel},dmarc="pass"}}) / sum({AGG}{{{sel}}})', 8,
         unit="percentunit",
         thresholds={"mode": "absolute", "steps": [{"color": "red", "value": None},
                                                   {"color": "orange", "value": 0.8},
                                                   {"color": "green", "value": 0.95}]})
    stat(4, "Aggregate reports (7 days)", f"sum(parsedmarc_aggregate_reports_7d{{{sel}}})", 12)
    stat(5, "Failure reports (7 days)", f"sum(parsedmarc_failure_reports_7d{{{sel}}}) or vector(0)", 16)
    stat(6, "SMTP TLS failed sessions (7 days)",
         f'sum(parsedmarc_smtp_tls_sessions_7d{{{sel},result="failed"}}) or vector(0)', 20)

    by = "sum by (tenant, domain)"
    table_targets = [
        target(f"{by} ({AGG}{{{sel}}})", "A", instant=True, fmt="table"),
        target(f'{by} ({AGG}{{{sel},dmarc="pass"}}) / {by} ({AGG}{{{sel}}})', "B", instant=True, fmt="table"),
        target(f"{by} (parsedmarc_aggregate_dkim_aligned_messages_7d{{{sel}}}) / {by} ({AGG}{{{sel}}})",
               "C", instant=True, fmt="table"),
        target(f"{by} (parsedmarc_aggregate_spf_aligned_messages_7d{{{sel}}}) / {by} ({AGG}{{{sel}}})",
               "D", instant=True, fmt="table"),
        target(f"{by} (parsedmarc_aggregate_reports_7d{{{sel}}})", "E", instant=True, fmt="table"),
        target(f"time() - max by (tenant, domain) (parsedmarc_aggregate_last_report_timestamp_seconds{{{sel}}})",
               "F", instant=True, fmt="table"),
    ]
    pct = {"unit": "percentunit", "decimals": 1, "custom.cellOptions": {"type": "color-text"}}

    def override(name, props):
        return {"matcher": {"id": "byName", "options": name},
                "properties": [{"id": k, "value": v} for k, v in props.items()]}

    panels.append({
        "id": 7, "type": "table", "title": "Domains (aggregate reports of the last 7 days)", "datasource": ds,
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": 4},
        "targets": table_targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "indexByName": {"tenant": 0, "domain": 1},
                "renameByName": {"tenant": "Tenant", "domain": "Domain", "Value #A": "Messages",
                                 "Value #B": "DMARC pass", "Value #C": "DKIM aligned",
                                 "Value #D": "SPF aligned", "Value #E": "Reports",
                                 "Value #F": "Last report"}}},
        ],
        "options": {"showHeader": True, "sortBy": [{"displayName": "Messages", "desc": True}]},
        "fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
            {"color": "red", "value": None}, {"color": "orange", "value": 0.8}, {"color": "green", "value": 0.95}]}},
            "overrides": [
                override("DMARC pass", pct), override("DKIM aligned", pct), override("SPF aligned", pct),
                override("Last report", {"unit": "s", "decimals": 0}),
            ]},
    })

    def timeseries(pid, title, targets, x, y, unit="short", w=12, desc=""):
        panels.append({
            "id": pid, "type": "timeseries", "title": title, "description": desc, "datasource": ds,
            "gridPos": {"h": 8, "w": w, "x": x, "y": y},
            "targets": targets,
            "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["lastNotNull"]},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"fillOpacity": 5, "lineWidth": 1}},
                            "overrides": []},
        })

    timeseries(8, "DMARC pass rate by domain",
               [target(f'{by} ({AGG}{{{sel},dmarc="pass"}}) / {by} ({AGG}{{{sel}}})',
                       legend="{{domain}} ({{tenant}})")], 0, 14, unit="percentunit",
               desc="Over the aggregate reports of the 7 days before each point")
    timeseries(9, "Messages failing DMARC by domain",
               [target(f'{by} ({AGG}{{{sel},dmarc="fail"}})', legend="{{domain}} ({{tenant}})")], 12, 14)
    timeseries(10, "Failure reports by domain",
               [target(f"{by} (parsedmarc_failure_reports_7d{{{sel}}})", legend="{{domain}} ({{tenant}})")],
               0, 22)
    timeseries(11, "SMTP TLS failed sessions by domain",
               [target(f'{by} (parsedmarc_smtp_tls_sessions_7d{{{sel},result="failed"}})',
                       legend="{{domain}} ({{tenant}})")], 12, 22)
    panels.append({
        "id": 12, "type": "stat", "title": "Mailbox watchers", "datasource": ds,
        "gridPos": {"h": 4, "w": 24, "x": 0, "y": 30},
        "targets": [target(f'max by (mailbox) (parsedmarc_mailbox_watcher_up{{module_id="{module_id}"}})',
                           legend="{{mailbox}}", instant=True)],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "none", "textMode": "value_and_name"},
        "fieldConfig": {"defaults": {"mappings": [{"type": "value", "options": {
            "0": {"text": "Stopped", "color": "red"}, "1": {"text": "Running", "color": "green"}}}]},
            "overrides": []},
    })

    def variable(name, label, query):
        return {
            "name": name, "label": label, "type": "query", "datasource": ds,
            "query": {"query": query, "refId": "PrometheusVariableQueryEditor-VariableQuery"},
            "definition": query, "refresh": 2, "sort": 1, "multi": True, "includeAll": True,
            "allValue": ".*", "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        }

    return {
        "uid": dashboard_uid(module_id),
        "title": f"DMARC reports ({module_id})",
        "description": "Aggregate DMARC, failure and SMTP TLS report counts of ns8-parsedmarc. "
                       "Details: OpenSearch Dashboards of the module.",
        "tags": ["parsedmarc", "dmarc", module_id],
        "editable": True,
        "schemaVersion": 39,
        "version": 1,
        "time": {"from": "now-30d", "to": "now"},
        "refresh": "",
        "timezone": "browser",
        "templating": {"list": [
            variable("tenant", "Tenant", f'label_values({AGG}{{module_id="{module_id}"}}, tenant)'),
            variable("domain", "Domain", f'label_values({AGG}{{module_id="{module_id}",tenant=~"$tenant"}}, domain)'),
        ]},
        "annotations": {"list": []},
        "panels": panels,
    }


# --------------------------------------------------------------------------
# Publication in Redis
# --------------------------------------------------------------------------

def _publish(rdb, module_id, event):
    rdb.publish(f"module/{module_id}/event/{event}", json.dumps({"module_id": module_id}))


def publish(rdb, module_id, enabled):
    """Publish (or remove) the alert rules and the dashboard, and tell
    ns8-metrics. The metrics themselves follow export-metrics."""
    rules_key = f"module/{module_id}/metrics_alert_rules"
    dash_key = f"module/{module_id}/metrics_dashboards"
    if enabled:
        rules = alert_rules()
        dash = json.dumps(dashboard(module_id), separators=(",", ":"))
        rules_changed = rdb.hget(rules_key, RULES_FIELD) != rules
        dash_changed = rdb.hget(dash_key, DASHBOARD_FIELD) != dash
        if rules_changed:
            rdb.hset(rules_key, RULES_FIELD, rules)
        if dash_changed:
            rdb.hset(dash_key, DASHBOARD_FIELD, dash)
    else:
        rules_changed = bool(rdb.hdel(rules_key, RULES_FIELD))
        dash_changed = bool(rdb.hdel(dash_key, DASHBOARD_FIELD))
    # Events only on changes: the dashboard event restarts the cluster Grafana
    if rules_changed:
        _publish(rdb, module_id, "metrics-alert-rules-changed")
    if dash_changed:
        _publish(rdb, module_id, "metrics-dashboard-changed")
    return rules_changed, dash_changed


def cluster_metrics(rdb):
    """The ns8-metrics instance of the cluster, if any"""
    module_id = rdb.get("cluster/default_instance/metrics") or ""
    info = {"installed": bool(module_id), "module_id": module_id, "grafana_path": ""}
    if module_id:
        info["grafana_path"] = (rdb.hget(f"module/{module_id}/settings", "grafana_path") or "").strip("/")
    return info
