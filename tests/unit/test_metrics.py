#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Unit tests of the cluster metrics code (imageroot/pypkg/parsedmarc_metrics.py).

Run from the repository root, without a node:

    python3 -m unittest discover -s tests/unit -v

The NS8 agent package is replaced by a stub. With NS8_METRICS_DIR set to a
checkout of NethServer/ns8-metrics (and PyYAML installed), the alert rules
also go through its metrics_alert_rules.py validation.
"""

import importlib
import json
import os
import re
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PYPKG = os.path.join(HERE, "..", "..", "imageroot", "pypkg")

# Stub of the NS8 agent package
agent_stub = types.ModuleType("agent")
agent_stub.SD_WARNING = "<4>"
agent_stub.SD_ERR = "<3>"
agent_stub.redis_connect = lambda **kw: None
sys.modules.setdefault("agent", agent_stub)
sys.path.insert(0, PYPKG)

pm = importlib.import_module("parsedmarc_metrics")
pdm = importlib.import_module("parsedmarc_ns8")

NOW_MS = 1_790_000_000_000

AGGREGATE_RESPONSE = {
    "aggregations": {"t": {"buckets": {
        "default": {"doc_count": 0, "d": {"buckets": []}},
        "acme": {"doc_count": 12, "d": {"buckets": [
            {"key": "example.com", "doc_count": 10,
             "last": {"value": NOW_MS - 3600_000, "value_as_string": "..."},
             "w": {"doc_count": 8,
                   "messages": {"value": 200.0},
                   "pass": {"doc_count": 6, "m": {"value": 150.0}},
                   "dkim": {"doc_count": 6, "m": {"value": 140.0}},
                   "spf": {"doc_count": 5, "m": {"value": 120.0}},
                   "reports": {"value": 4}}},
            # Reports in the last 30 days only
            {"key": "old.example.com", "doc_count": 2,
             "last": {"value": NOW_MS - 20 * 86400_000},
             "w": {"doc_count": 0, "messages": {"value": 0.0},
                   "pass": {"doc_count": 0, "m": {"value": 0.0}},
                   "dkim": {"doc_count": 0, "m": {"value": 0.0}},
                   "spf": {"doc_count": 0, "m": {"value": 0.0}},
                   "reports": {"value": 0}}},
        ]}},
        "beta": {"doc_count": 3, "d": {"buckets": [
            {"key": "example.de", "doc_count": 3,
             "last": {"value": NOW_MS},
             "w": {"doc_count": 3, "messages": {"value": 30.0},
                   "pass": {"doc_count": 3, "m": {"value": 30.0}},
                   "dkim": {"doc_count": 3, "m": {"value": 30.0}},
                   "spf": {"doc_count": 0, "m": {"value": 0.0}},
                   "reports": {"value": 1}}},
        ]}},
    }}},
}

FAILURE_RESPONSE = {
    "aggregations": {"t": {"buckets": {
        "default": {"doc_count": 1, "d": {"buckets": [{"key": "other.org", "doc_count": 1}]}},
        "acme": {"doc_count": 2, "d": {"buckets": [{"key": "example.com", "doc_count": 2}]}},
        "beta": {"doc_count": 0, "d": {"buckets": []}},
    }}},
}

SMTP_TLS_RESPONSE = {
    "aggregations": {"t": {"buckets": {
        "default": {"doc_count": 1, "d": {"buckets": [
            {"key": "mx.other.org", "doc_count": 1, "ok": {"value": 900.0}, "failed": {"value": 3.0}}]}},
    }}},
}

SETTINGS = dict(pdm.DEFAULTS, host="dmarc.example.org",
                tenants=[dict(pdm.TENANT_DEFAULTS, name="acme", domains=["example.com"]),
                         dict(pdm.TENANT_DEFAULTS, name="beta", domains=["example.de"])])


class FakeBackend:
    def __init__(self, fail=False):
        self.fail = fail
        self.queries = []

    def search(self, index, body):
        self.queries.append((index, body))
        if self.fail:
            raise OSError("connection refused")
        if "aggregate" in index:
            return AGGREGATE_RESPONSE
        if "smtp_tls" in index:
            return SMTP_TLS_RESPONSE
        return FAILURE_RESPONSE


class FakeRun:
    def __init__(self, states):
        self.states = states
        self.args = None

    def __call__(self, args, **kwargs):
        self.args = args
        return types.SimpleNamespace(stdout="\n".join(self.states) + "\n", returncode=0)


LABEL = r'[a-zA-Z_][a-zA-Z0-9_]*="(?:\\.|[^"\\])*"'
SAMPLE_RE = re.compile(
    rf'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{{(?P<labels>{LABEL}(?:,{LABEL})*)\}})?'
    r' (?P<value>-?[0-9.e+]+|NaN|[+-]Inf)$')


def parse_text(text):
    """Strict enough parser of the Prometheus text format: returns
    {(name, frozenset(labels)): value}, checks HELP/TYPE before samples"""
    out = {}
    declared = []
    for line in text.splitlines():
        if line.startswith("# HELP "):
            declared.append(line.split()[2])
            continue
        if line.startswith("# TYPE "):
            assert line.split()[2] == declared[-1], line
            assert line.split()[3] == "gauge", line
            continue
        m = SAMPLE_RE.match(line)
        assert m, f"invalid sample line: {line!r}"
        name = m.group("name")
        assert name == declared[-1], f"sample {name} outside its family"
        labels = frozenset(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"', m.group("labels") or ""))
        key = (name, labels)
        assert key not in out, f"duplicate sample {key}"
        out[key] = float(m.group("value"))
    assert len(declared) == len(set(declared)), "family declared twice"
    return out


def value(parsed, name, **labels):
    return parsed[(name, frozenset(labels.items()))]


class TestExporter(unittest.TestCase):

    def collect(self, backend, states=("active", "failed"), instances=("default", "t-acme")):
        times = iter([100.0, 101.25])
        return pm.collect(SETTINGS, backend, list(instances), runner=FakeRun(states), now=lambda: next(times))

    def test_output_format_and_values(self):
        text = pm.format_metrics(self.collect(FakeBackend()))
        parsed = parse_text(text)
        self.assertEqual(value(parsed, "parsedmarc_up"), 1)
        self.assertEqual(value(parsed, "parsedmarc_collect_duration_seconds"), 1.25)
        self.assertEqual(value(parsed, "parsedmarc_collect_timestamp_seconds"), 101)
        m = "parsedmarc_aggregate_messages_7d"
        self.assertEqual(value(parsed, m, tenant="acme", domain="example.com", dmarc="pass"), 150)
        self.assertEqual(value(parsed, m, tenant="acme", domain="example.com", dmarc="fail"), 50)
        self.assertEqual(value(parsed, m, tenant="beta", domain="example.de", dmarc="fail"), 0)
        self.assertEqual(value(parsed, m, tenant="acme", domain="old.example.com", dmarc="pass"), 0)
        self.assertEqual(value(parsed, "parsedmarc_aggregate_dkim_aligned_messages_7d",
                               tenant="acme", domain="example.com"), 140)
        self.assertEqual(value(parsed, "parsedmarc_aggregate_spf_aligned_messages_7d",
                               tenant="acme", domain="example.com"), 120)
        self.assertEqual(value(parsed, "parsedmarc_aggregate_reports_7d", tenant="acme", domain="example.com"), 4)
        self.assertEqual(value(parsed, "parsedmarc_aggregate_last_report_timestamp_seconds",
                               tenant="beta", domain="example.de"), NOW_MS // 1000)
        self.assertEqual(value(parsed, "parsedmarc_failure_reports_7d", tenant="default", domain="other.org"), 1)
        self.assertEqual(value(parsed, "parsedmarc_failure_reports_7d", tenant="acme", domain="example.com"), 2)
        self.assertEqual(value(parsed, "parsedmarc_smtp_tls_sessions_7d",
                               tenant="default", domain="mx.other.org", result="failed"), 3)
        self.assertEqual(value(parsed, "parsedmarc_smtp_tls_sessions_7d",
                               tenant="default", domain="mx.other.org", result="successful"), 900)
        self.assertEqual(value(parsed, "parsedmarc_mailbox_watcher_up", mailbox="default"), 1)
        self.assertEqual(value(parsed, "parsedmarc_mailbox_watcher_up", mailbox="t-acme"), 0)
        # Reserved labels of the node collector
        self.assertNotRegex(text, r'[{,](module|module_id)=')
        # Bounded cardinality: never per source address
        self.assertNotIn("source", text)

    def test_backend_down(self):
        parsed = parse_text(pm.format_metrics(self.collect(FakeBackend(fail=True))))
        self.assertEqual(value(parsed, "parsedmarc_up"), 0)
        names = {name for name, _ in parsed}
        self.assertFalse(any(n.startswith("parsedmarc_aggregate") for n in names))
        self.assertIn("parsedmarc_mailbox_watcher_up", names)

    def test_queries(self):
        backend = FakeBackend()
        self.collect(backend)
        indices = [q[0] for q in backend.queries]
        self.assertEqual(indices, ["*dmarc_aggregate*", "*dmarc_f*", "*smtp_tls*"])
        filters = backend.queries[0][1]["aggs"]["t"]["filters"]["filters"]
        self.assertEqual(filters, {"default": {"prefix": {"_index": "dmarc_aggregate"}},
                                   "acme": {"prefix": {"_index": "acme_dmarc_aggregate"}},
                                   "beta": {"prefix": {"_index": "beta_dmarc_aggregate"}}})
        for _, body in backend.queries:
            self.assertEqual(body["size"], 0)
            self.assertEqual(body["aggs"]["t"]["aggs"]["d"]["terms"]["size"], pm.MAX_DOMAINS)
        # The default bucket name is a reserved tenant name: no clash
        self.assertIn(pm.DEFAULT_TENANT, pdm.RESERVED_TENANTS)

    def test_empty_storage(self):
        class Empty(FakeBackend):
            def search(self, index, body):
                return {"hits": {"hits": []}}
        parsed = parse_text(pm.format_metrics(self.collect(Empty(), states=(), instances=())))
        self.assertEqual(value(parsed, "parsedmarc_up"), 1)
        self.assertEqual({n for n, _ in parsed}, {"parsedmarc_up", "parsedmarc_collect_duration_seconds",
                                                  "parsedmarc_collect_timestamp_seconds"})

    def test_label_escaping(self):
        text = pm.format_metrics({"parsedmarc_failure_reports_7d": [({"tenant": "a", "domain": 'x"\\\ny'}, 1)]})
        self.assertIn(r'domain="x\"\\\ny"', text)
        parse_text(text)

    def test_watcher_states(self):
        run = FakeRun(["active", "inactive"])
        self.assertEqual(pm.watcher_states(["default", "t-acme"], run), {"default": 1, "t-acme": 0})
        self.assertEqual(run.args[:3], ["systemctl", "--user", "is-active"])
        self.assertEqual(pm.watcher_states([], run), {})
        # Unexpected output: no samples rather than wrong ones
        self.assertEqual(pm.watcher_states(["default"], FakeRun([])), {})

    def test_backend_settings(self):
        secrets = {"grafana_password": "pw1", "external_password": "pw2"}
        b = pm.Backend(dict(SETTINGS, backend="bundled"), secrets.get, opensearch_port=20002, ca_file="ca.pem")
        self.assertEqual((b.url, b.user, b.password, b.ca_file), ("https://127.0.0.1:20002", "grafana", "pw1", "ca.pem"))
        b = pm.Backend(dict(SETTINGS, backend="external", external_hosts="es1.example.org:9200, es2",
                            external_user="ro", external_ssl=False), secrets.get)
        self.assertEqual((b.url, b.user, b.password), ("http://es1.example.org:9200", "ro", "pw2"))

    def test_settings_default(self):
        self.assertIs(pdm.DEFAULTS["metrics_enabled"], True)
        self.assertIn("metrics_enabled", pdm.configure_payload(dict(pdm.DEFAULTS)))


class TestBackendHTTP(unittest.TestCase):
    """Backend.search against a local HTTP server standing in for an
    external Elasticsearch"""

    def setUp(self):
        import http.server
        import threading
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append((self.path, self.headers.get("Authorization"), json.loads(body)))
                if "smtp_tls" in self.path:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'{"error": "forbidden"}')
                    return
                payload = json.dumps(AGGREGATE_RESPONSE).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        port = self.server.server_address[1]
        self.backend = pm.Backend(dict(SETTINGS, backend="external", external_hosts=f"127.0.0.1:{port}",
                                       external_user="reader", external_ssl=False),
                                  {"external_password": "s3cret"}.get)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_search(self):
        res = self.backend.search("*dmarc_aggregate*", {"size": 0})
        self.assertIn("aggregations", res)
        path, auth, body = self.requests[0]
        self.assertEqual(path, "/*dmarc_aggregate*/_search?ignore_unavailable=true&allow_no_indices=true")
        self.assertEqual(auth, "Basic cmVhZGVyOnMzY3JldA==")   # reader:s3cret
        self.assertEqual(body, {"size": 0})

    def test_http_error_hides_body(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.backend.search("*smtp_tls*", {})
        self.assertEqual(str(ctx.exception), "search *smtp_tls*: HTTP 403")

    def test_deadline(self):
        self.backend.deadline = 0
        with self.assertRaises(TimeoutError):
            self.backend.search("*dmarc_aggregate*", {})
        self.assertEqual(self.requests, [])


class TestDashboard(unittest.TestCase):

    def setUp(self):
        self.dash = pm.dashboard("parsedmarc1")
        self.text = json.dumps(self.dash)

    def walk(self, node):
        if isinstance(node, dict):
            yield node
            for v in node.values():
                yield from self.walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from self.walk(v)

    def test_datasource_is_the_cluster_prometheus(self):
        sources = [n["datasource"] for n in self.walk(self.dash) if "datasource" in n]
        self.assertTrue(sources)
        for ds in sources:
            self.assertEqual(ds, {"type": "prometheus", "uid": "prometheus"})

    def test_uid_and_scope(self):
        self.assertEqual(self.dash["uid"], "parsedmarc-parsedmarc1")
        self.assertLessEqual(len(pm.dashboard_uid("parsedmarc12345678901234567890")), 40)
        self.assertNotEqual(pm.dashboard("parsedmarc2")["uid"], self.dash["uid"])
        exprs = [n["expr"] for n in self.walk(self.dash) if "expr" in n]
        self.assertGreater(len(exprs), 10)
        for expr in exprs:
            for selector in re.findall(r"parsedmarc_[a-z0-9_]+\{([^}]*)\}", expr):
                self.assertIn('module_id="parsedmarc1"', selector, expr)
            self.assertEqual(expr.count("("), expr.count(")"), expr)

    def test_panels(self):
        ids = [p["id"] for p in self.dash["panels"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIsNone(self.dash.get("id"))
        metric_names = {name for name, _ in pm.FAMILIES}
        exprs = " ".join(n["expr"] for n in self.walk(self.dash) if "expr" in n)
        exprs += " ".join(v["query"]["query"] for v in self.dash["templating"]["list"])
        used = set(re.findall(r"(parsedmarc_[a-z0-9_]+)\{", exprs))
        self.assertTrue(used)
        self.assertLessEqual(used, metric_names)
        self.assertNotIn("password", self.text.lower())


class FakeRedis:
    def __init__(self):
        self.hashes = {}
        self.strings = {}
        self.events = []

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value

    def hdel(self, key, field):
        return 1 if self.hashes.get(key, {}).pop(field, None) is not None else 0

    def get(self, key):
        return self.strings.get(key)

    def publish(self, channel, message):
        json.loads(message)
        self.events.append(channel)


class TestPublication(unittest.TestCase):

    def test_publish_cycle(self):
        rdb = FakeRedis()
        self.assertEqual(pm.publish(rdb, "parsedmarc1", True), (True, True))
        self.assertEqual(rdb.events, ["module/parsedmarc1/event/metrics-alert-rules-changed",
                                      "module/parsedmarc1/event/metrics-dashboard-changed"])
        dash = json.loads(rdb.hget("module/parsedmarc1/metrics_dashboards", "parsedmarc"))
        self.assertEqual(dash["uid"], "parsedmarc-parsedmarc1")
        self.assertIn("ParsedmarcStorageDown", rdb.hget("module/parsedmarc1/metrics_alert_rules", "parsedmarc"))
        # Unchanged: no event, no Grafana restart
        rdb.events.clear()
        self.assertEqual(pm.publish(rdb, "parsedmarc1", True), (False, False))
        self.assertEqual(rdb.events, [])
        # Disabled: removed, events
        self.assertEqual(pm.publish(rdb, "parsedmarc1", False), (True, True))
        self.assertIsNone(rdb.hget("module/parsedmarc1/metrics_dashboards", "parsedmarc"))
        self.assertIsNone(rdb.hget("module/parsedmarc1/metrics_alert_rules", "parsedmarc"))
        self.assertEqual(len(rdb.events), 2)
        rdb.events.clear()
        self.assertEqual(pm.publish(rdb, "parsedmarc1", False), (False, False))
        self.assertEqual(rdb.events, [])

    def test_cluster_metrics(self):
        rdb = FakeRedis()
        self.assertEqual(pm.cluster_metrics(rdb), {"installed": False, "module_id": "", "grafana_path": ""})
        rdb.strings["cluster/default_instance/metrics"] = "metrics1"
        rdb.hset("module/metrics1/settings", "grafana_path", "/grafana/")
        self.assertEqual(pm.cluster_metrics(rdb), {"installed": True, "module_id": "metrics1",
                                                   "grafana_path": "grafana"})


class TestAlertRules(unittest.TestCase):

    def setUp(self):
        self.doc = json.loads(pm.alert_rules())
        self.rules = [r for g in self.doc["groups"] for r in g["rules"]]

    def test_shape(self):
        self.assertEqual(len(self.doc["groups"]), 1)
        self.assertFalse(self.doc["groups"][0]["name"].startswith("ns8:"))
        names = [r["alert"] for r in self.rules]
        self.assertEqual(len(names), len(set(names)))
        metric_names = {name for name, _ in pm.FAMILIES}
        for r in self.rules:
            self.assertNotIn("record", r)
            self.assertIn(r["labels"]["severity"], ("warning", "critical"))
            self.assertTrue({"summary_en", "summary_it", "description_en", "description_it"}
                            <= set(r["annotations"]), r["alert"])
            self.assertRegex(r["for"], r"^[0-9]+[mh]$")
            self.assertEqual(r["expr"].count("("), r["expr"].count(")"))
            used = set(re.findall(r"parsedmarc_[a-z0-9_]+", r["expr"]))
            self.assertTrue(used and used <= metric_names, r["expr"])
            # ns8-metrics sets the module_id matcher itself
            self.assertNotIn("module_id", r["expr"])

    @unittest.skipUnless(os.environ.get("NS8_METRICS_DIR"), "NS8_METRICS_DIR not set")
    def test_ns8_metrics_validation(self):
        sys.path.insert(0, os.path.join(os.environ["NS8_METRICS_DIR"], "imageroot", "bin"))
        mar = importlib.import_module("metrics_alert_rules")

        class FakePromtool:
            """Stands in for promtool: formatting is the identity, matcher
            edits append a marker so the rewrite sees a selector"""
            image = "fake"

            def __call__(self, arguments):
                if arguments[2] == "format":
                    return arguments[-1]
                expr = arguments[5]
                if arguments[3] == "set":
                    return expr + f" #{arguments[6]}={arguments[7]}"
                return re.sub(rf" #{re.escape(arguments[6])}=[^ ]*", "", expr)

            def check_rules(self, candidate):
                return ""

        warnings = []
        source = mar.AlertRuleSource(module_id="parsedmarc1", rule_set_name=pm.RULES_FIELD,
                                     payload=pm.alert_rules().encode(),
                                     redis_key="module/parsedmarc1/metrics_alert_rules")
        doc = mar.transform_alert_rule(source, FakePromtool(), warnings.append)
        self.assertEqual(warnings, [])
        self.assertEqual(doc["groups"][0]["name"], "ns8:parsedmarc1:parsedmarc:parsedmarc")
        for rule in doc["groups"][0]["rules"]:
            self.assertEqual(rule["labels"]["module_id"], "parsedmarc1")


if __name__ == "__main__":
    unittest.main()
