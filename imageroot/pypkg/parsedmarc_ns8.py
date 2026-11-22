#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Shared code of the ns8-parsedmarc actions and helpers.

The settings live in state/settings.json (no secrets). Secrets live in 0600
files under state/secrets. configure-module renders them into:

- state/opensearch/   opensearch.yml and the security bootstrap files
- state/certs/        the private CA, node and super admin certificates
- state/dashboards/   opensearch_dashboards.yml (0600: kibanaserver password)
- state/grafana/      grafana.ini and provisioning (0600: passwords)
- state/parsedmarc/   one INI per mailbox watcher (0600), the tenant map

The actions and helpers run in the state directory.
"""

import base64
import copy
import hashlib
import json
import os
import re
import secrets
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

import agent

SETTINGS_FILE = "settings.json"
SECRETS_DIR = "secrets"
CERTS_DIR = "certs"
OS_DIR = "opensearch"
OSD_DIR = "dashboards"
GRAFANA_DIR = "grafana"
PDM_DIR = "parsedmarc"
GEOIP_DIR = "geoip"
EXTRA_INI = "parsedmarc-extra.ini"   # CLI-only sections, appended to every INI
STAMPS_FILE = ".render-hashes.json"
SNAPSHOT_REPO = "ns8"
TENANTS_FILE = ".tenants-provisioned.json"

FLAG_OPENSEARCH = ".opensearch-enabled"
FLAG_DASHBOARDS = ".dashboards-enabled"
FLAG_GRAFANA = ".grafana-enabled"

INSTALL_DIR = os.environ.get("AGENT_INSTALL_DIR", "..")
SHARE_DIR = os.path.join(INSTALL_DIR, "share")

# Internal OpenSearch accounts. The super admin authenticates with the
# admin certificate, never with a password.
OS_ADMIN = "admin"            # Dashboards login of the NS8 administrator
OS_KIBANASERVER = "kibanaserver"
OS_WRITER = "parsedmarc"
OS_READER = "grafana"
RESERVED_TENANTS = {"admin", "kibanaserver", "parsedmarc", "grafana", "global", "private",
                    "default", "all", "kibana", "opensearch", "dashboards", "anonymous"}

DEFAULTS = {
    "host": "",
    "http2https": True,
    "lets_encrypt": False,
    # Storage backend: bundled single-node OpenSearch or an external cluster
    "backend": "bundled",
    "opensearch_heap_mb": 1024,
    "external_type": "opensearch",       # opensearch | elasticsearch
    "external_hosts": "",
    "external_user": "",
    "external_ssl": True,
    "external_skip_verify": False,
    "retention_days": 0,                 # 0: keep forever (bundled backend only)
    # Dashboards
    "dashboards_enabled": True,          # OpenSearch Dashboards (bundled backend)
    "grafana_enabled": False,            # bundled Grafana under /grafana
    # Cluster metrics (ns8-metrics): export-metrics, alert rules, dashboard
    "metrics_enabled": True,
    # Report types
    "save_aggregate": True,
    "save_failure": True,
    "save_smtp_tls": True,
    "strip_attachment_payloads": False,
    # Enrichment
    "geoip": "bundled",                  # bundled | ipinfo | maxmind
    "maxmind_account_id": "",
    "nameservers": [],
    "dns_timeout": 2.0,
    "offline": False,
    # Processing and logging
    "n_procs": 1,
    "log_level": "warnings",             # silent | warnings | verbose | debug
    # Main mailbox
    "input_type": "none",                # none | imap | msgraph | gmail
    "imap_host": "",
    "imap_port": 993,
    "imap_ssl": True,
    "imap_skip_verify": False,
    "imap_user": "",
    "reports_folder": "INBOX",
    "archive_folder": "Archive",
    "watch": True,
    "poll_interval": 30,                 # minutes, when watch is off
    "delete": False,
    "msgraph_auth_method": "ClientSecret",  # ClientSecret | UsernamePassword
    "msgraph_client_id": "",
    "msgraph_tenant_id": "",
    "msgraph_mailbox": "",
    "msgraph_user": "",
    "gmail_delegated_user": "",
    # Summary email through the cluster smarthost
    "email_enabled": False,
    "email_to": [],
    "email_from": "",
    "email_subject": "parsedmarc report",
    # Extra outputs
    "kafka_enabled": False,
    "kafka_hosts": "",
    "kafka_user": "",
    "kafka_ssl": True,
    "kafka_aggregate_topic": "dmarc_aggregate",
    "kafka_failure_topic": "dmarc_failure",
    "kafka_smtp_tls_topic": "smtp_tls",
    "s3_enabled": False,
    "s3_bucket": "",
    "s3_path": "parsedmarc",
    "s3_region": "",
    "s3_endpoint": "",
    "s3_access_key_id": "",
    "syslog_enabled": False,
    "syslog_server": "",
    "syslog_port": 514,
    "syslog_protocol": "udp",
    "webhook_enabled": False,
    "webhook_aggregate_url": "",
    "webhook_failure_url": "",
    "webhook_smtp_tls_url": "",
    "webhook_timeout": 60,
    "splunk_enabled": False,
    "splunk_url": "",
    "splunk_index": "email",
    "splunk_skip_verify": False,
    # Tenants: [{name, domains, mailbox_enabled, imap_host, imap_port,
    # imap_ssl, imap_skip_verify, imap_user, reports_folder,
    # archive_folder, delete}]
    "tenants": [],
}

TENANT_DEFAULTS = {
    "name": "",
    "domains": [],
    "mailbox_enabled": False,
    "imap_host": "",
    "imap_port": 993,
    "imap_ssl": True,
    "imap_skip_verify": False,
    "imap_user": "",
    "reports_folder": "INBOX",
    "archive_folder": "Archive",
    "delete": False,
}

# Write-only fields of configure-module: stored in state/secrets, reported by
# get-configuration as <name>_set
SECRET_FIELDS = ["admin_password", "external_password", "imap_password", "msgraph_client_secret",
                 "msgraph_password", "gmail_credentials", "ipinfo_token", "maxmind_license_key",
                 "kafka_password", "s3_secret_access_key", "splunk_token"]
TENANT_SECRET_FIELDS = ["password", "imap_password"]

TENANT_RE = re.compile(r"^[a-z][a-z0-9]{1,30}$")
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def log(message):
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# Files, settings and secrets
# --------------------------------------------------------------------------

def write_file(path, content, mode=0o644):
    """Atomic write; returns True if the content changed"""
    if isinstance(content, str):
        content = content.encode()
    try:
        with open(path, "rb") as fp:
            if fp.read() == content:
                if (os.stat(path).st_mode & 0o777) != mode:
                    os.chmod(path, mode)
                return False
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fp:
        fp.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def remove_file(path):
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def load_settings():
    settings = copy.deepcopy(DEFAULTS)
    try:
        with open(SETTINGS_FILE) as fp:
            settings.update(json.load(fp))
    except FileNotFoundError:
        pass
    settings["tenants"] = [dict(TENANT_DEFAULTS, **t) for t in settings["tenants"]]
    return settings


def save_settings(settings):
    write_file(SETTINGS_FILE, json.dumps(settings, indent=2, sort_keys=True) + "\n", 0o644)


def secret_path(name):
    return os.path.join(SECRETS_DIR, name)


def write_secret(name, value):
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    return write_file(secret_path(name), value, 0o600)


def read_secret(name, default=""):
    try:
        with open(secret_path(name)) as fp:
            return fp.read()
    except FileNotFoundError:
        return default


def remove_secret(name):
    return remove_file(secret_path(name))


def tenant_secret(tenant, field):
    return f"tenant-{tenant}-{field}"


def genpw(length=32):
    alphabet = string.ascii_letters + string.digits
    # Upper, lower and digit at least once: the OpenSearch password policy
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def ensure_internal_secrets():
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    for name in ["kibanaserver_password", "parsedmarc_password", "grafana_password",
                 "grafana_admin_password", "osd_cookie_password"]:
        if not read_secret(name):
            write_secret(name, genpw(40))


def config_view(settings):
    """get-configuration output: settings plus *_set markers, no secret"""
    out = copy.deepcopy(settings)
    for field in SECRET_FIELDS:
        out[field + "_set"] = bool(read_secret(field))
    tenants = []
    for t in out["tenants"]:
        t = dict(t)
        for field in TENANT_SECRET_FIELDS:
            t[field + "_set"] = bool(read_secret(tenant_secret(t["name"], field)))
        tenants.append(t)
    out["tenants"] = tenants
    return out


def configure_payload(settings):
    """configure-module input that applies the given settings again (restore
    and clone): every field, secrets excluded (they are already in
    state/secrets), Let's Encrypt off"""
    data = {k: copy.deepcopy(v) for k, v in settings.items() if k in DEFAULTS}
    data["lets_encrypt"] = False
    return data


# --------------------------------------------------------------------------
# Ports and environment
# --------------------------------------------------------------------------

def ports():
    plist = [int(p) for p in os.environ["TCP_PORTS"].split(",")]
    return {"dashboards": plist[0], "opensearch": plist[1], "grafana": plist[2]}


def is_bundled(settings):
    return settings["backend"] == "bundled"


def mailbox_instances(settings):
    """Watcher instances: the main mailbox and the tenant mailboxes"""
    inst = []
    if settings["input_type"] != "none":
        inst.append("default")
    for t in settings["tenants"]:
        if t["mailbox_enabled"]:
            inst.append("t-" + t["name"])
    return inst


# --------------------------------------------------------------------------
# Certificates of the bundled OpenSearch
# --------------------------------------------------------------------------

def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=sys.stderr, stderr=sys.stderr)


LEAF_EXT = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")


def ensure_certs():
    """Private CA, node certificate (127.0.0.1, localhost) and super admin
    client certificate, PKCS#8 keys (0600)"""
    os.makedirs(CERTS_DIR, mode=0o700, exist_ok=True)
    os.chmod(CERTS_DIR, 0o700)
    ca, cakey = f"{CERTS_DIR}/ca.pem", f"{CERTS_DIR}/ca-key.pem"
    old = os.umask(0o077)
    try:
        if not os.path.exists(ca):
            _openssl("genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", cakey)
            _openssl("req", "-x509", "-new", "-key", cakey, "-sha256", "-days", "7300",
                     "-subj", "/O=NS8/OU=parsedmarc/CN=parsedmarc-ca",
                     # Python 3.13 (parsedmarc image) verifies strictly: a CA
                     # needs critical basicConstraints and keyUsage
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                     "-addext", "subjectKeyIdentifier=hash", "-out", ca)
        for name, subj, ext in [
            ("node", "/O=NS8/OU=parsedmarc/CN=node",
             "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n" + LEAF_EXT),
            ("admin", "/O=NS8/OU=parsedmarc/CN=admin", "extendedKeyUsage=clientAuth\n" + LEAF_EXT),
        ]:
            crt, key = f"{CERTS_DIR}/{name}.pem", f"{CERTS_DIR}/{name}-key.pem"
            if os.path.exists(crt):
                continue
            csr, extf = f"{CERTS_DIR}/{name}.csr", f"{CERTS_DIR}/{name}.ext"
            _openssl("genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
            _openssl("req", "-new", "-key", key, "-subj", subj, "-out", csr)
            with open(extf, "w") as fp:
                fp.write(ext)
            _openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", cakey, "-CAcreateserial",
                     "-sha256", "-days", "7300", "-extfile", extf, "-out", crt)
            remove_file(csr)
            remove_file(extf)
    finally:
        os.umask(old)
    for f in os.listdir(CERTS_DIR):
        os.chmod(os.path.join(CERTS_DIR, f), 0o600 if "key" in f or f.endswith(".srl") else 0o644)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _yaml_str(value):
    return json.dumps(str(value))


def render_opensearch(settings):
    cfg = f"""# Generated by ns8-parsedmarc configure-module: do not edit
cluster.name: parsedmarc
node.name: parsedmarc
network.host: 0.0.0.0
discovery.type: single-node
# vm.max_map_count cannot be raised by a rootless module: no mmap store
node.store.allow_mmap: false
bootstrap.memory_lock: false
path.repo: ["/usr/share/opensearch/snapshots"]
plugins.security.ssl.transport.pemcert_filepath: certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.pem
plugins.security.ssl.http.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn: ["CN=admin,OU=parsedmarc,O=NS8"]
plugins.security.nodes_dn: ["CN=node,OU=parsedmarc,O=NS8"]
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.audit.type: noop
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
"""
    # The image's default internal_users.yml holds demo users with public
    # passwords: replace it. The accounts are created through the REST API.
    users = """_meta:
  type: "internalusers"
  config_version: 2
"""
    # Basic authentication only; a wildcard of a role user is reduced to
    # the indices the user may read (tenant isolation in the dashboards)
    secconfig = """_meta:
  type: "config"
  config_version: 2
config:
  dynamic:
    do_not_fail_on_forbidden: true
    http:
      anonymous_auth_enabled: false
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: true
        authentication_backend:
          type: intern
"""
    changed = write_file(f"{OS_DIR}/opensearch.yml", cfg)
    changed |= write_file(f"{OS_DIR}/internal_users.yml", users)
    changed |= write_file(f"{OS_DIR}/config.yml", secconfig)
    return changed


def render_dashboards(settings):
    cfg = f"""# Generated by ns8-parsedmarc configure-module: do not edit
server.host: "0.0.0.0"
server.port: 5601
server.name: parsedmarc
opensearch.hosts: ["https://127.0.0.1:9200"]
opensearch.ssl.verificationMode: full
opensearch.ssl.certificateAuthorities: ["/usr/share/opensearch-dashboards/config/ca.pem"]
opensearch.username: {OS_KIBANASERVER}
opensearch.password: {_yaml_str(read_secret("kibanaserver_password"))}
opensearch.requestHeadersAllowlist: ["securitytenant", "Authorization"]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.multitenancy.enable_filter: false
opensearch_security.readonly_mode.roles: []
opensearch_security.cookie.secure: {"true" if settings["http2https"] else "false"}
opensearch_security.cookie.password: {_yaml_str(read_secret("osd_cookie_password"))}
opensearch_security.auth.type: "basicauth"
"""
    changed = write_file(f"{OSD_DIR}/opensearch_dashboards.yml", cfg, 0o600)
    changed |= write_file(f"{OSD_DIR}/ca.pem", _read(f"{CERTS_DIR}/ca.pem"))
    return changed


def _read(path, default=""):
    try:
        with open(path) as fp:
            return fp.read()
    except FileNotFoundError:
        return default


def backend_endpoint(settings):
    """(section, hosts, user, password, ssl, skip_verify, ca_path)"""
    if is_bundled(settings):
        return ("opensearch", "https://127.0.0.1:9200", OS_WRITER, read_secret("parsedmarc_password"),
                True, False, "/etc/parsedmarc/ca.pem")
    return (settings["external_type"], settings["external_hosts"], settings["external_user"],
            read_secret("external_password"), settings["external_ssl"], settings["external_skip_verify"], "")


def _ini_value(value):
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(value).replace("%", "%%").replace("\n", " ")


def _ini(sections):
    out = ["# Generated by ns8-parsedmarc: do not edit, see state/" + EXTRA_INI]
    for name, values in sections:
        out.append(f"\n[{name}]")
        for k, v in values.items():
            if v is None or v == "":
                continue
            out.append(f"{k} = {_ini_value(v)}")
    return "\n".join(out) + "\n"


def smarthost():
    try:
        rdb = agent.redis_connect(use_replica=True)
        return agent.get_smarthost_settings(rdb)
    except Exception as ex:
        log(f"smarthost settings not available: {ex}")
        return {"enabled": False}


def common_sections(settings, tenant_prefix=None, with_domain_map=True):
    general = {
        "save_aggregate": settings["save_aggregate"],
        "save_failure": settings["save_failure"],
        "save_smtp_tls": settings["save_smtp_tls"],
        "strip_attachment_payloads": settings["strip_attachment_payloads"],
        "offline": settings["offline"],
        "dns_timeout": settings["dns_timeout"],
        "n_procs": settings["n_procs"],
    }
    if settings["nameservers"]:
        general["nameservers"] = ",".join(settings["nameservers"])
    level = settings["log_level"]
    general["silent"] = level == "silent"
    general["warnings"] = level in ("warnings", "verbose", "debug")
    general["verbose"] = level in ("verbose", "debug")
    general["debug"] = level == "debug"
    if settings["geoip"] == "maxmind" and os.path.exists(f"{GEOIP_DIR}/GeoLite2-Country.mmdb"):
        general["ip_db_path"] = "/var/lib/geoip/GeoLite2-Country.mmdb"
    elif settings["geoip"] == "ipinfo" and read_secret("ipinfo_token"):
        general["ipinfo_api_token"] = read_secret("ipinfo_token")
    if with_domain_map and not tenant_prefix and settings["tenants"]:
        general["index_prefix_domain_map"] = "/etc/parsedmarc/domain_map.yaml"
    sections = [("general", general)]

    section, hosts, user, password, use_ssl, skip, ca = backend_endpoint(settings)
    if hosts:
        out = {"hosts": hosts, "user": user, "password": password, "ssl": use_ssl,
               "skip_certificate_verification": skip, "cert_path": ca}
        if tenant_prefix:
            out["index_prefix"] = tenant_prefix
        sections.append((section, out))

    if settings["kafka_enabled"]:
        sections.append(("kafka", {
            "hosts": settings["kafka_hosts"], "user": settings["kafka_user"],
            "password": read_secret("kafka_password"), "ssl": settings["kafka_ssl"],
            "aggregate_topic": settings["kafka_aggregate_topic"],
            "failure_topic": settings["kafka_failure_topic"],
            "smtp_tls_topic": settings["kafka_smtp_tls_topic"]}))
    if settings["s3_enabled"]:
        sections.append(("s3", {
            "bucket": settings["s3_bucket"], "path": settings["s3_path"],
            "region_name": settings["s3_region"], "endpoint_url": settings["s3_endpoint"],
            "access_key_id": settings["s3_access_key_id"],
            "secret_access_key": read_secret("s3_secret_access_key")}))
    if settings["syslog_enabled"]:
        sections.append(("syslog", {"server": settings["syslog_server"], "port": settings["syslog_port"],
                                    "protocol": settings["syslog_protocol"]}))
    if settings["webhook_enabled"]:
        sections.append(("webhook", {
            "aggregate_url": settings["webhook_aggregate_url"],
            "failure_url": settings["webhook_failure_url"],
            "smtp_tls_url": settings["webhook_smtp_tls_url"],
            "timeout": settings["webhook_timeout"]}))
    if settings["splunk_enabled"]:
        sections.append(("splunk_hec", {
            "url": settings["splunk_url"], "token": read_secret("splunk_token"),
            "index": settings["splunk_index"],
            "skip_certificate_verification": settings["splunk_skip_verify"]}))
    return sections


def smtp_section(settings, sh):
    if not settings["email_enabled"] or not settings["email_to"] or not sh.get("enabled"):
        return []
    enc = sh.get("encrypt_smtp", "starttls")
    return [("smtp", {
        "host": sh["host"], "port": sh["port"],
        "ssl": enc == "tls",
        "starttls": True if enc == "starttls" else (False if enc == "none" else None),
        "skip_certificate_verification": not sh.get("tls_verify", True),
        "user": sh.get("username", ""), "password": sh.get("password", ""),
        "from": settings["email_from"] or f"parsedmarc@{settings['host']}",
        "to": ",".join(settings["email_to"]),
        "subject": settings["email_subject"]})]


def imap_sections(src, password, inst):
    return [
        ("mailbox", {"reports_folder": src["reports_folder"], "archive_folder": src["archive_folder"],
                     "watch": True, "delete": src["delete"],
                     "attempts_file": f"/var/lib/parsedmarc/attempts-{inst}.json"}),
        ("imap", {"host": src["imap_host"], "port": src["imap_port"], "ssl": src["imap_ssl"],
                  "skip_certificate_verification": src["imap_skip_verify"],
                  "user": src["imap_user"], "password": password}),
    ]


def render_parsedmarc(settings, sh=None):
    """Watcher INIs (0600), the tenant domain map, the import INI used by
    parsedmarc-import (local report files, no mailbox)"""
    if sh is None:
        sh = smarthost()
    os.makedirs(PDM_DIR, exist_ok=True)
    os.makedirs(GEOIP_DIR, exist_ok=True)   # bind-mounted by the containers
    extra = _read(EXTRA_INI)
    changed = {}

    domain_map = "".join(f"{t['name']}:\n" + "".join(f"  - {d}\n" for d in t["domains"])
                         for t in settings["tenants"]) or "{}\n"
    write_file(f"{PDM_DIR}/domain_map.yaml", domain_map)
    if is_bundled(settings):
        write_file(f"{PDM_DIR}/ca.pem", _read(f"{CERTS_DIR}/ca.pem"))
    write_file(f"{PDM_DIR}/run.sh", RUN_SH)

    wanted = set()
    inst_files = {}
    if settings["input_type"] != "none":
        inst = "default"
        mb = []
        if settings["input_type"] == "imap":
            mb = imap_sections(settings, read_secret("imap_password"), inst)
        elif settings["input_type"] == "msgraph":
            mb = [("mailbox", {"reports_folder": settings["reports_folder"],
                               "archive_folder": settings["archive_folder"], "watch": True,
                               "delete": settings["delete"],
                               "attempts_file": f"/var/lib/parsedmarc/attempts-{inst}.json"}),
                  ("msgraph", {"auth_method": settings["msgraph_auth_method"],
                               "client_id": settings["msgraph_client_id"],
                               "client_secret": read_secret("msgraph_client_secret"),
                               "tenant_id": settings["msgraph_tenant_id"],
                               "mailbox": settings["msgraph_mailbox"],
                               "user": settings["msgraph_user"],
                               "password": read_secret("msgraph_password"),
                               "token_file": "/var/lib/parsedmarc/msgraph.token"})]
        elif settings["input_type"] == "gmail":
            write_file(f"{PDM_DIR}/gmail-credentials.json", read_secret("gmail_credentials"), 0o600)
            mb = [("mailbox", {"reports_folder": settings["reports_folder"],
                               "archive_folder": settings["archive_folder"], "watch": True,
                               "delete": settings["delete"],
                               "attempts_file": f"/var/lib/parsedmarc/attempts-{inst}.json"}),
                  ("gmail_api", {"credentials_file": "/etc/parsedmarc/gmail-credentials.json",
                                 "auth_mode": "service_account",
                                 "service_account_user": settings["gmail_delegated_user"],
                                 "token_file": "/var/lib/parsedmarc/gmail.token"})]
        if not settings["watch"]:
            mb[0][1]["watch"] = False
        inst_files[inst] = (common_sections(settings) + mb + smtp_section(settings, sh), settings["watch"])
    for t in settings["tenants"]:
        if not t["mailbox_enabled"]:
            continue
        inst = "t-" + t["name"]
        mb = imap_sections(t, read_secret(tenant_secret(t["name"], "imap_password")), inst)
        # A tenant mailbox writes under the tenant prefix whatever the domain
        inst_files[inst] = (common_sections(settings, tenant_prefix=t["name"] + "_") + mb, True)

    for inst, (sections, watch) in inst_files.items():
        wanted.add(inst)
        text = _ini(sections) + ("\n" + extra if extra else "")
        changed[inst] = write_file(f"{PDM_DIR}/{inst}.ini", text, 0o600)
        poll = f"{PDM_DIR}/{inst}.poll"
        if watch:
            changed[inst] |= remove_file(poll)
        else:
            changed[inst] |= write_file(poll, f"{int(settings['poll_interval']) * 60}\n")
    for f in os.listdir(PDM_DIR):
        m = re.match(r"^(.+)\.(ini|poll)$", f)
        if m and m.group(1) not in wanted and m.group(1) != "import":
            remove_file(f"{PDM_DIR}/{f}")
    if settings["input_type"] != "gmail":
        remove_file(f"{PDM_DIR}/gmail-credentials.json")
    imp = common_sections(settings)
    imp[0][1]["fail_on_output_error"] = True   # parsedmarc-import exits non-zero
    write_file(f"{PDM_DIR}/import.ini", _ini(imp), 0o600)
    return changed


RUN_SH = """#!/bin/sh
# Generated by ns8-parsedmarc: run one mailbox watcher
cfg="/etc/parsedmarc/$1.ini"
poll="/etc/parsedmarc/$1.poll"
if [ -f "$poll" ]; then
    interval=$(cat "$poll")
    while true; do
        parsedmarc -c "$cfg"
        sleep "$interval"
    done
fi
exec parsedmarc -c "$cfg"
"""


def grafana_datasources(settings):
    """(name, index pattern, time field) of the Grafana datasources: the
    upstream dashboard selects them by the dmarc-ag / dmarc-fo suffixes"""
    out = []
    groups = [("All", "*")] + [(t["name"], t["name"] + "_") for t in settings["tenants"]]
    for label, prefix in groups:
        out.append((f"{label} dmarc-ag", f"{prefix}dmarc_aggregate*", "date_begin"))
        out.append((f"{label} dmarc-fo", f"{prefix}dmarc_f*", "arrival_date"))
    return out


def render_grafana(settings):
    base = f"{GRAFANA_DIR}/provisioning"
    os.makedirs(f"{base}/dashboards/json", exist_ok=True)
    os.makedirs(f"{base}/datasources", exist_ok=True)
    if is_bundled(settings):
        url, user, password, ca = "https://127.0.0.1:9200", OS_READER, read_secret("grafana_password"), \
            _read(f"{CERTS_DIR}/ca.pem")
        skip = False
    else:
        url = settings["external_hosts"].split(",")[0].strip()
        if not url.startswith("http"):
            url = ("https://" if settings["external_ssl"] else "http://") + url
        user, password, ca, skip = settings["external_user"], read_secret("external_password"), "", \
            settings["external_skip_verify"]
    ds = {"apiVersion": 1, "prune": True, "datasources": []}
    for i, (name, index, timefield) in enumerate(grafana_datasources(settings)):
        entry = {
            "name": name, "uid": "pdm-" + hashlib.sha1(name.encode()).hexdigest()[:12],
            "type": "elasticsearch", "access": "proxy", "url": url, "isDefault": i == 0,
            "basicAuth": bool(user), "basicAuthUser": user,
            "jsonData": {"index": index, "timeField": timefield, "maxConcurrentShardRequests": 5,
                         "tlsAuthWithCACert": bool(ca), "tlsSkipVerify": skip},
            "secureJsonData": {"basicAuthPassword": password},
        }
        if ca:
            entry["secureJsonData"]["tlsCACert"] = ca
        ds["datasources"].append(entry)
    changed = write_file(f"{base}/datasources/parsedmarc.yaml", json.dumps(ds, indent=1), 0o600)
    changed |= write_file(f"{base}/dashboards/parsedmarc.yaml", json.dumps({
        "apiVersion": 1,
        "providers": [{"name": "parsedmarc", "type": "file", "disableDeletion": True,
                       "allowUiUpdates": True, "updateIntervalSeconds": 60,
                       "options": {"path": "/etc/grafana/provisioning/dashboards/json"}}]}, indent=1))
    with open(os.path.join(SHARE_DIR, "Grafana-DMARC_Reports.json")) as fp:
        dash = json.load(fp)
    for var in dash.get("templating", {}).get("list", []):
        if var.get("type") == "datasource":
            var["hide"] = 0     # one datasource per tenant: let the viewer pick it
            var["current"] = {}
    dash["id"] = None
    changed |= write_file(f"{base}/dashboards/json/dmarc-reports.json", json.dumps(dash))
    host = settings["host"]
    scheme = "https" if settings["http2https"] else "http"
    ini = f"""# Generated by ns8-parsedmarc configure-module: do not edit
[server]
http_addr = 0.0.0.0
http_port = 3000
root_url = {scheme}://{host}/grafana/
serve_from_sub_path = true
[paths]
data = /var/lib/grafana
logs = /var/lib/grafana/log
plugins = /var/lib/grafana/plugins
provisioning = /etc/grafana/provisioning
[security]
admin_user = admin
admin_password = {read_secret("grafana_admin_password")}
cookie_secure = {"true" if settings["http2https"] else "false"}
[auth.proxy]
enabled = true
header_name = X-Auth-User
header_property = username
auto_sign_up = true
[auth]
disable_login_form = true
[auth.basic]
enabled = false
[users]
allow_sign_up = false
auto_assign_org_role = Admin
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[plugins]
plugin_admin_enabled = false
[log]
level = warn
"""
    changed |= write_file(f"{GRAFANA_DIR}/grafana.ini", ini, 0o600)
    return changed


def set_flag(path, on):
    if on:
        return write_file(path, "")
    return remove_file(path)


def render_all(settings):
    """Render every file; returns the units whose configuration changed"""
    ensure_internal_secrets()
    bundled = is_bundled(settings)
    restart = set()
    set_flag(FLAG_OPENSEARCH, bundled)
    set_flag(FLAG_DASHBOARDS, bundled and settings["dashboards_enabled"])
    set_flag(FLAG_GRAFANA, settings["grafana_enabled"])
    if bundled:
        ensure_certs()
        if render_opensearch(settings):
            restart.add("opensearch-app.service")
        if settings["dashboards_enabled"] and render_dashboards(settings):
            restart.add("dashboards-app.service")
    if settings["grafana_enabled"] and render_grafana(settings):
        restart.add("grafana-app.service")
    for inst, ch in render_parsedmarc(settings).items():
        if ch:
            restart.add(f"parsedmarc-watch@{inst}.service")
    return restart


# --------------------------------------------------------------------------
# OpenSearch and Dashboards REST
# --------------------------------------------------------------------------

def _ctx(client_cert=True):
    ctx = ssl.create_default_context(cafile=f"{CERTS_DIR}/ca.pem")
    if client_cert:
        ctx.load_cert_chain(f"{CERTS_DIR}/admin.pem", f"{CERTS_DIR}/admin-key.pem")
    return ctx


def os_request(path, method="GET", body=None, timeout=60, ok404=False):
    """Request to the bundled OpenSearch as super admin (client certificate)"""
    url = f"https://127.0.0.1:{ports()['opensearch']}{path}"
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as ex:
        if ok404 and ex.code == 404:
            return None
        detail = ex.read().decode(errors="replace")[:500]
        raise RuntimeError(f"{method} {path}: HTTP {ex.code} {detail}") from None
    return json.loads(raw) if raw else {}


def osd_request(path, method="GET", body=None, tenant=None, timeout=120, content_type="application/json"):
    """Request to the bundled Dashboards as the admin user"""
    url = f"http://127.0.0.1:{ports()['dashboards']}{path}"
    auth = base64.b64encode(f"{OS_ADMIN}:{read_secret('admin_password')}".encode()).decode()
    headers = {"Authorization": "Basic " + auth, "osd-xsrf": "true"}
    if tenant:
        headers["securitytenant"] = tenant
    if body is not None:
        headers["Content-Type"] = content_type
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def wait_for(check, timeout, what):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if check():
                return True
        except Exception as ex:
            last = ex
        time.sleep(3)
    raise RuntimeError(f"{what} did not become ready within {timeout}s: {last}")


def opensearch_ready():
    health = os_request("/_cluster/health", timeout=10)
    if health.get("status") not in ("green", "yellow"):
        return False
    sec = os_request("/_plugins/_security/health", timeout=10)
    return sec.get("status") == "UP"


def dashboards_ready():
    status = osd_request("/api/status", timeout=10)
    return bool(status)


READ_ACTIONS = ["read", "indices:admin/mappings/get", "indices:admin/mappings/fields/get*",
                "indices:admin/get", "indices:admin/resolve/index", "indices:monitor/settings/get"]


def provision_opensearch(settings):
    """Accounts, roles, tenants, retention policy and snapshot repository"""
    sec = "/_plugins/_security/api"
    os_request(f"{sec}/roles/parsedmarc_writer", "PUT", {
        "cluster_permissions": ["cluster_monitor", "cluster_composite_ops", "indices:admin/template/*",
                                "indices:admin/index_template/*", "indices:data/write/bulk*"],
        "index_permissions": [{"index_patterns": ["*dmarc*", "*smtp_tls*"], "allowed_actions": ["indices_all"]}],
    })
    os_request(f"{sec}/roles/parsedmarc_reader", "PUT", {
        "cluster_permissions": ["cluster_composite_ops_ro", "cluster_monitor"],
        "index_permissions": [{"index_patterns": ["*dmarc*", "*smtp_tls*"], "allowed_actions": READ_ACTIONS}],
    })
    users = {
        OS_KIBANASERVER: read_secret("kibanaserver_password"),
        OS_WRITER: read_secret("parsedmarc_password"),
        OS_READER: read_secret("grafana_password"),
    }
    if read_secret("admin_password"):
        users[OS_ADMIN] = read_secret("admin_password")
    for user, pw in users.items():
        os_request(f"{sec}/internalusers/{user}", "PUT", {"password": pw, "backend_roles": []})

    tenant_names = [t["name"] for t in settings["tenants"]]
    for t in tenant_names:
        os_request(f"{sec}/tenants/{t}", "PUT", {"description": f"parsedmarc tenant {t}"})
        os_request(f"{sec}/roles/tenant_{t}", "PUT", {
            "cluster_permissions": ["cluster_composite_ops_ro"],
            "index_permissions": [{"index_patterns": [f"{t}_dmarc*", f"{t}_smtp_tls*"],
                                   "allowed_actions": READ_ACTIONS}],
            "tenant_permissions": [{"tenant_patterns": [t], "allowed_actions": ["kibana_all_write"]}],
        })
        os_request(f"{sec}/rolesmapping/tenant_{t}", "PUT", {"users": [t]})
        pw = read_secret(tenant_secret(t, "password"))
        if pw:
            os_request(f"{sec}/internalusers/{t}", "PUT", {"password": pw, "backend_roles": []})
        else:
            os_request(f"{sec}/internalusers/{t}", "DELETE", ok404=True)
    # Accounts, roles and tenants of the removed tenants
    try:
        with open(TENANTS_FILE) as fp:
            previous = json.load(fp)
    except FileNotFoundError:
        previous = []
    for t in previous:
        if t in tenant_names:
            continue
        for kind, name in (("internalusers", t), ("rolesmapping", f"tenant_{t}"),
                           ("roles", f"tenant_{t}"), ("tenants", t)):
            os_request(f"{sec}/{kind}/{name}", "DELETE", ok404=True)
    write_file(TENANTS_FILE, json.dumps(tenant_names))

    os_request(f"{sec}/rolesmapping/all_access", "PUT", {"users": [OS_ADMIN], "backend_roles": ["admin"]})
    os_request(f"{sec}/rolesmapping/kibana_server", "PUT", {"users": [OS_KIBANASERVER]})
    os_request(f"{sec}/rolesmapping/parsedmarc_writer", "PUT", {"users": [OS_WRITER]})
    os_request(f"{sec}/rolesmapping/parsedmarc_reader", "PUT", {"users": [OS_READER]})
    os_request(f"{sec}/rolesmapping/kibana_user", "PUT", {"users": tenant_names, "backend_roles": ["kibanauser"]})

    # Retention: delete the dated indices after retention_days
    policy_path = "/_plugins/_ism/policies/parsedmarc-retention"
    current = os_request(policy_path, ok404=True)
    days = int(settings["retention_days"] or 0)
    if days > 0:
        policy = {"policy": {
            "description": "ns8-parsedmarc report retention",
            "default_state": "hot",
            "states": [
                {"name": "hot", "actions": [],
                 "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{days}d"}}]},
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": ["*dmarc_aggregate-*", "*dmarc_failure-*", "*smtp_tls-*"],
                              "priority": 100}],
        }}
        if current:
            os_request(f"{policy_path}?if_seq_no={current['_seq_no']}&if_primary_term={current['_primary_term']}",
                       "PUT", policy)
            os_request("/_plugins/_ism/change_policy/*dmarc*,*smtp_tls*", "POST",
                       {"policy_id": "parsedmarc-retention"}, ok404=True)
        else:
            os_request(policy_path, "PUT", policy)
        os_request("/_plugins/_ism/add/*dmarc*,*smtp_tls*", "POST", {"policy_id": "parsedmarc-retention"}, ok404=True)
    elif current:
        os_request("/_plugins/_ism/remove/*dmarc*,*smtp_tls*", "POST", ok404=True)
        os_request(policy_path, "DELETE", ok404=True)

    os_request(f"/_snapshot/{SNAPSHOT_REPO}", "PUT",
               {"type": "fs", "settings": {"location": "/usr/share/opensearch/snapshots"}})


def saved_objects(prefix):
    """The upstream saved objects with the index patterns of a tenant"""
    out = []
    with open(os.path.join(SHARE_DIR, "opensearch_dashboards.ndjson")) as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("type") == "index-pattern":
                obj["attributes"]["title"] = prefix + obj["attributes"]["title"]
            out.append(json.dumps(obj))
    return ("\n".join(out) + "\n").encode()


def import_saved_objects(tenant, prefix):
    boundary = "ns8parsedmarc" + secrets.token_hex(8)
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"export.ndjson\"\r\n"
            "Content-Type: application/ndjson\r\n\r\n").encode() + saved_objects(prefix) + \
        f"\r\n--{boundary}--\r\n".encode()
    res = osd_request("/api/saved_objects/_import?overwrite=true", "POST", body, tenant=tenant,
                      content_type=f"multipart/form-data; boundary={boundary}")
    if not res.get("success"):
        raise RuntimeError(f"saved objects import into {tenant} failed: {json.dumps(res)[:500]}")


def provision_dashboards(settings):
    """The parsedmarc dashboards in the global tenant (every index, readable
    per index permission) and in each tenant (its own indices)"""
    if not read_secret("admin_password"):
        return
    import_saved_objects("global", "*")
    for t in settings["tenants"]:
        import_saved_objects(t["name"], t["name"] + "_")


def latest_snapshot():
    snaps = (os_request(f"/_snapshot/{SNAPSHOT_REPO}/_all", ok404=True) or {}).get("snapshots", [])
    snaps = [s for s in snaps if s.get("state") == "SUCCESS"]
    return sorted(snaps, key=lambda s: s.get("start_time_in_millis", 0))[-1]["snapshot"] if snaps else None
