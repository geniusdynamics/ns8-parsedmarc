# ns8-parsedmarc

[parsedmarc](https://domainaware.github.io/parsedmarc/) for NethServer 8: it
reads DMARC aggregate, failure (forensic) and SMTP TLS reports from mailboxes,
stores them in OpenSearch (or an external Elasticsearch/OpenSearch) and shows
them in OpenSearch Dashboards and Grafana, with one view per tenant.

## Install

    add-module ghcr.io/geniusdynamics/parsedmarc:latest 1

Then open the module Settings page, or:

    api-cli run module/parsedmarc1/configure-module --data '{
      "host": "dmarc.example.org", "lets_encrypt": true,
      "backend": "bundled", "admin_password": "a-long-passphrase",
      "input_type": "imap", "imap_host": "imap.example.org", "imap_port": 993,
      "imap_ssl": true, "imap_user": "dmarc@example.org", "imap_password": "..."
    }'

`get-configuration` returns every setting without secrets: each secret shows
as `<name>_set` (`admin_password_set`, `imap_password_set`, ...). A secret left
empty in `configure-module` keeps its stored value.

## Hardware requirements

| Setup | RAM | Disk |
|---|---|---|
| Bundled OpenSearch + Dashboards (default, 1 GiB heap) | 4 GB free | 10 GB + about 1 GB per million aggregate records |
| + Grafana | + 200 MB | |
| External backend (parsedmarc only) | 300 MB per mailbox | small |

- The OpenSearch container uses about twice its heap (`opensearch_heap_mb`,
  default 1024). Dashboards uses about 600 MB to 1 GB.
- `vm.max_map_count`: the module is rootless and cannot change kernel
  settings. OpenSearch runs with `node.store.allow_mmap: false` (NIO file
  store) and as a single node, where the bootstrap checks are not enforced,
  so the default 65530 is fine. An administrator may still raise it
  (`sysctl -w vm.max_map_count=262144`) for slightly better performance, but
  the module does not depend on it.
- One shard per report type and day: with years of data, raise
  `cluster.max_shards_per_node`, or set a retention.

## Storage backend

- **Bundled OpenSearch** (default, Apache 2.0 licence): one node in the
  module pod, the security plugin on, TLS on HTTP and transport with a
  private CA made at the first configuration (`state/certs`). The demo users
  of the image are replaced: accounts are created through the REST API with
  the admin client certificate. Accounts: `admin` (your Dashboards login,
  `admin_password`), `parsedmarc` (writes the report indices only),
  `kibanaserver`, `grafana` (read only), one per tenant. Generated passwords
  live in `state/secrets` (0600). The API is published on `127.0.0.1` only.
- **External**: `external_type` (`opensearch` or `elasticsearch`),
  `external_hosts` (comma separated URLs), user and password,
  `external_ssl`, `external_skip_verify`. OpenSearch Dashboards is not
  bundled then: import the upstream
  [saved objects](https://github.com/domainaware/parsedmarc/tree/master/dashboards)
  into your Kibana or Dashboards.

## Retention

`retention_days` (bundled backend) installs the ISM policy
`parsedmarc-retention`: an index is deleted that many days after it was
created. parsedmarc writes one index per day of report, so this is close to
retention by report date, but a late report creates a new index that lives
the full period. 0 keeps everything.

## Dashboards

- **OpenSearch Dashboards** at `https://<host>/`, Traefik route with Let's
  Encrypt and HTTP to HTTPS. Login: the OpenSearch security plugin, user
  `admin` or a tenant user. The upstream parsedmarc dashboards (aggregate,
  failure, SMTP TLS) are imported at every start in the Global tenant (index
  patterns `*dmarc_aggregate*`, `*dmarc_f*`, `*smtp_tls*`, all tenants) and in
  each tenant (its own prefix).
  NS8 forward authentication is not used here: tenant users are not NS8
  users, and Dashboards needs its own session to select the tenant.
- **Grafana** (`grafana_enabled`) at `https://<host>/grafana/`, with the
  upstream "DMARC Reports" dashboard and one pair of datasources per tenant
  (`<tenant> dmarc-ag`, `<tenant> dmarc-fo`, and `All ...`), selected in the
  dashboard variables. Authentication: NS8 forward authentication (the
  cluster administrators, as for the Rspamd UI of ns8-mail), passed to
  Grafana with `auth.proxy`. Off by default: with the cluster metrics
  module, its Grafana shows the overview (see
  [Cluster metrics](#cluster-metrics-ns8-metrics)).

## Cluster metrics (ns8-metrics)

NS8 installs one metrics module per cluster (ns8-metrics: Prometheus,
Alertmanager and Grafana on the leader node). When `metrics_enabled` is on
(the default), this module feeds it, so the cluster Grafana and
Alertmanager show the DMARC state of every instance and the bundled
Grafana can stay off. Standalone, without ns8-metrics, nothing changes:
OpenSearch Dashboards and the optional bundled Grafana work as before.

What is published:

- **Metrics**: `bin/export-metrics` prints aggregate counts in the
  Prometheus text format. The node runs it every 5 minutes
  (`runagent -m parsedmarc1 export-metrics`, core 3.24.0 or later) and
  serves the output through its `node_exporter`, which Prometheus already
  scrapes, with the `module` label (copied to `module_id`). There is no
  extra port, no listener and no process of the module. The queries use
  the read-only `grafana` OpenSearch account (or the external account),
  stop after 20 seconds, and the output never holds a secret, a source
  address or a message sample. Older cores do not run the command: no
  metrics, the rest works.
- **Alert rules**: Redis hash `module/<id>/metrics_alert_rules`, field
  `parsedmarc`, then the `metrics-alert-rules-changed` event.
- **Dashboard** "DMARC reports (<id>)": Redis hash
  `module/<id>/metrics_dashboards`, field `parsedmarc`, uid
  `parsedmarc-<id>`, then the `metrics-dashboard-changed` event. It uses
  only the Prometheus datasource of ns8-metrics (uid `prometheus`).

The keys are published by `configure-module` (so also on restore and
clone) and on update; turning `metrics_enabled` off, or removing the
module, deletes them. ns8-metrics reads them whenever it provisions, so
the order of installation does not matter.

Open the dashboard in the cluster Grafana: enable Grafana in the settings
of the metrics module, then use "Open in the cluster Grafana" on the
Settings page of this module, or open `https://<leader>/<grafana path>/`
and search "DMARC". The module Settings page shows whether a metrics
module was found.

### Metrics

Counts cover a rolling window: reports arrive about one day after the
period they describe, so a window shorter than a few days would be mostly
empty. Labels: `tenant` (`default` for the domains of no tenant) and
`domain` (the domain of the published DMARC policy; at most 500 per
tenant and report type).

| Metric | Labels | Meaning |
|---|---|---|
| `parsedmarc_up` | | 1 if the storage answered every query of the last run |
| `parsedmarc_collect_duration_seconds` | | duration of the last run |
| `parsedmarc_collect_timestamp_seconds` | | time of the last run (the node keeps the last output of a failed run) |
| `parsedmarc_aggregate_messages_7d` | tenant, domain, `dmarc` = `pass`/`fail` | messages in the aggregate reports whose period began in the last 7 days |
| `parsedmarc_aggregate_dkim_aligned_messages_7d` | tenant, domain | of those, with an aligned DKIM pass |
| `parsedmarc_aggregate_spf_aligned_messages_7d` | tenant, domain | of those, with an aligned SPF pass |
| `parsedmarc_aggregate_reports_7d` | tenant, domain | aggregate reports of the last 7 days |
| `parsedmarc_aggregate_last_report_timestamp_seconds` | tenant, domain | end of the newest aggregate report period; domains with reports in the last 30 days |
| `parsedmarc_failure_reports_7d` | tenant, domain | failure (forensic) reports that arrived in the last 7 days |
| `parsedmarc_smtp_tls_sessions_7d` | tenant, domain, `result` = `successful`/`failed` | sessions in the SMTP TLS reports of the last 7 days; a report about several policy domains counts for each |
| `parsedmarc_mailbox_watcher_up` | `mailbox` (`default`, `t-<tenant>`) | 1 if the process reading that mailbox runs |

When the storage does not answer, only `parsedmarc_up 0`, the run time and
the watcher states are exported: partial counts would look like a drop of
the traffic.

### Alerts

| Alert | Condition | Severity |
|---|---|---|
| `ParsedmarcStorageDown` | `parsedmarc_up == 0` for 15 minutes | critical |
| `ParsedmarcMetricsStale` | last run older than 30 minutes, for 5 minutes (export-metrics fails or times out: see `journalctl -u refresh-module-metrics`) | warning |
| `ParsedmarcMailboxWatcherDown` | a mailbox watcher stopped for 15 minutes | warning |
| `ParsedmarcDmarcFailureRateHigh` | more than 10% of the messages of a domain fail DMARC, with more than 100 messages in 7 days, for 1 hour | warning |
| `ParsedmarcNoAggregateReport` | no aggregate report about a domain for 72 hours (only domains with reports in the last 30 days), for 1 hour | warning |

ns8-metrics scopes every rule to this instance (`module_id`). Critical
alerts are mailed when its `mail_to` is set.

### Why no OpenSearch datasource in the cluster Grafana

ns8-metrics also accepts datasources (`module/<id>/metrics_datasources`),
but an OpenSearch datasource is not used:

1. its Grafana (13.x) no longer bundles the Elasticsearch datasource, and
   plugin installation is disabled, so the upstream parsedmarc dashboard
   cannot query anything;
2. the datasource YAML, with the OpenSearch password, would be stored in
   Redis, readable by every module;
3. that Grafana runs on the leader node only, while the OpenSearch API of
   this module listens on the loopback of its own node.

The metrics above avoid the three: counts computed here, no secret in
Redis, collected on every node by `node_exporter`. The report details
(sources, DKIM and SPF results, samples) stay in OpenSearch Dashboards, or
in the bundled Grafana, which stays on 12.x for reason 1 (see
`renovate.json`).

## Mailboxes

- **Main mailbox** (`input_type`):
  - `imap`: `imap_host`, `imap_port`, `imap_ssl` (implicit TLS; off uses
    STARTTLS), `imap_skip_verify`, `imap_user`, `imap_password`;
  - `msgraph` (Microsoft 365): `msgraph_auth_method` `ClientSecret` or
    `UsernamePassword`, client ID, client secret, tenant ID, mailbox;
  - `gmail`: a service account key JSON (`gmail_credentials`) with domain-wide
    delegation and `gmail_delegated_user`;
  - common: `reports_folder`, `archive_folder`, `delete` (else archive),
    `watch` (IMAP IDLE / polling; off: a run every `poll_interval` minutes).
- **NS8 mail**: the "Pick a mail server" button lists the modules of the
  cluster that publish the `imap` service (ns8-mail: VPN address, port 143,
  STARTTLS). The mailbox user and password are typed in: mailbox lists of
  ns8-mail need a mail admin role this module does not request.
- Each mailbox runs its own parsedmarc process,
  `parsedmarc-watch@<name>.service` (`default`, `t-<tenant>`).
- Local files: `runagent -m parsedmarc1 parsedmarc-import <dir>` parses
  report files (XML, gz, zip, eml, mbox) from a directory readable by the
  module user, for example under `/home/parsedmarc1/.config/state`.

## Multi-tenant

Tenants are managed on the Tenants page (add, edit, remove) or in the
`tenants` list of `configure-module`:

    {"name": "acme", "domains": ["acme.example"], "password": "...",
     "mailbox_enabled": false}

- The domains of all tenants make the parsedmarc `index_prefix_domain_map`:
  reports of a tenant's domain are stored in `<tenant>_dmarc_aggregate-*`,
  `<tenant>_dmarc_failure-*`, `<tenant>_smtp_tls-*`; other domains in the
  unprefixed indices.
- A tenant with its own mailbox (`mailbox_enabled`, IMAP fields,
  `imap_password`) is read by its own process with `index_prefix =
  <tenant>_`: everything in that mailbox goes to the tenant, whatever the
  domain.
- With `password`, a tenant user `<tenant>` is created in OpenSearch with
  read access to its own indices only and a Dashboards tenant of the same
  name, where the dashboards are imported with its index patterns.
- Removing a tenant removes its user, role and Dashboards tenant; the indices
  stay (delete them, or let the retention do it).

Limits:

- A domain belongs to one tenant only; subdomains follow their base domain.
- With the domain map, upstream drops the SMTP TLS reports of domains no
  tenant lists.
- Tenant names: 2 to 31 lowercase letters and digits.
- Tenants exist only with the bundled backend's security. With an external
  backend the prefixes are written, but users and permissions are yours.
- Grafana is for the cluster administrators: every datasource is visible
  there.
- Index suffixes are not offered; `index_suffix` can be set in the extra INI.

## Report types and enrichment

`save_aggregate`, `save_failure` (failure reports may contain personal data),
`save_smtp_tls`, `strip_attachment_payloads`; `geoip`: `bundled` (the IPinfo
Lite database shipped with parsedmarc, updated online), `ipinfo`
(`ipinfo_token`) or `maxmind` (`maxmind_account_id`,
`maxmind_license_key`: GeoLite2 Country downloaded at configuration and
weekly by `parsedmarc-geoipupdate.timer`); `nameservers`, `dns_timeout`,
`offline`, `n_procs`, `log_level` (`silent`, `warnings`, `verbose`,
`debug`). Logs: the module log, identifiers `parsedmarc-<mailbox>`,
`opensearch-app`, `dashboards-app`, `grafana-app`.

## Summary email

`email_enabled`, `email_to`, `email_from`, `email_subject`: parsedmarc sends
the results of each run with new reports through the cluster smarthost
(Settings > Smarthost of NS8). The watchers restart on `smarthost-changed`.

## Other outputs

In the UI: Kafka, S3, syslog, webhook, Splunk HEC (secrets: `kafka_password`,
`s3_secret_access_key`, `splunk_token`). Other parsedmarc sections (`gelf`,
`loki`, `log_analytics`, `postgresql`, extra options like `index_suffix` of a
section not managed here) go to `state/parsedmarc-extra.ini`, appended to
every parsedmarc INI; it is backed up. Example:

    runagent -m parsedmarc1 sh -c 'umask 077; cat > parsedmarc-extra.ini' <<'EOF'
    [loki]
    url = http://loki.example.org:3100
    EOF
    runagent -m parsedmarc1 systemctl --user restart 'parsedmarc-watch@*'

A section must not repeat one the UI writes.

## Backup, restore, clone

- Backed up: `state/settings.json`, `state/secrets`, `state/certs`,
  `state/parsedmarc-extra.ini`, and the volumes `opensearch-snapshots`,
  `parsedmarc-data`, `grafana-data`. Before each backup,
  `module-dump-state` takes an OpenSearch snapshot of the report indices and
  the Dashboards saved objects into `opensearch-snapshots` (only the newest
  snapshot is kept; snapshots are incremental). The live `opensearch-data`
  volume is not backed up.
- Restore: `configure-module` runs with every setting and Let's Encrypt off,
  then the report indices are restored from the snapshot. Edited Dashboards
  objects are not restored (the upstream ones are imported again).
- Clone: core copies the state and every volume while the services are
  stopped; `configure-module` runs with Let's Encrypt off.

## Services

`parsedmarc.service` (pod; Requires its children) with `opensearch-app`,
`dashboards-app`, `grafana-app` (skipped when disabled) and
`parsedmarc-watch@*.service`. A unit reports started only when its service
answers: cluster and security index healthy and provisioned, Dashboards
`/api/status` answering and saved objects imported, Grafana `/api/health`.
`RestartSec=10`.

## Tests

`tests/` (Robot Framework, QEMU in CI): install, configure with two tenants,
read-back without secrets, secret file modes, backend health, parsing of the
upstream sample reports (`tests/fixtures`) through the parsedmarc CLI into
`acme_*` and `beta_*` indices, tenant isolation, tenant dashboards, Traefik
and authentication, backup snapshot, cluster metrics (export-metrics
output, published alert rules and dashboard, rules and series loaded by the
cluster Prometheus when a metrics module exists, withdrawal), removal.

`tests/unit` (no node needed): exporter output from canned OpenSearch
responses, queries, alert rules and dashboard, publication in Redis:

    python3 -m unittest discover -s tests/unit -v

With `NS8_METRICS_DIR` pointing to a checkout of ns8-metrics, the alert
rules also go through its `metrics_alert_rules.py` validation.

## Credits

parsedmarc, its dashboards and the sample reports are by Sean Whalen and
contributors, Apache License 2.0 (`imageroot/share`, `tests/fixtures`).
