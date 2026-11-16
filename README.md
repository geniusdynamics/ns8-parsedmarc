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
  Grafana with `auth.proxy`.

### Why not the Grafana of ns8-metrics

ns8-metrics does accept datasources and dashboards from other modules: a
module writes `module/<id>/metrics_datasources` (YAML) and
`module/<id>/metrics_dashboards` (JSON) and fires
`metrics-datasource-changed` / `metrics-dashboard-changed`. It is not used
because:

1. its Grafana (13.x) no longer bundles the Elasticsearch datasource, and
   plugin installation is disabled, so the parsedmarc dashboard cannot query
   anything;
2. the datasource YAML, with the OpenSearch password, would be stored in
   Redis, readable by every module;
3. that Grafana runs on the leader node only, while the OpenSearch API of
   this module listens on the loopback of its own node.

The bundled Grafana stays on 12.x for the same reason (see `renovate.json`).

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
and authentication, backup snapshot, removal.

## Credits

parsedmarc, its dashboards and the sample reports are by Sean Whalen and
contributors, Apache License 2.0 (`imageroot/share`, `tests/fixtures`).
