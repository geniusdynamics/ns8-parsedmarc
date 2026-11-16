<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getConfiguration">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-configuration')"
          :description="error.getConfiguration"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="12"
          />
          <cv-form v-else @submit.prevent="configureModule">
            <h4 class="mg-bottom">{{ $t("settings.web_access") }}</h4>
            <ConfigField
              name="host"
              v-model="cfg.host"
              :label="$t('settings.host')"
              placeholder="dmarc.example.org"
              :helper="$t('settings.host_helper')"
              :invalid-message="error.host"
              :disabled="busy"
              ref="host"
            />
            <ConfigField
              name="lets_encrypt"
              type="toggle"
              v-model="cfg.lets_encrypt"
              :label="core.$t('apps_lets_encrypt.request_https_certificate')"
              :tooltip="core.$t('apps_lets_encrypt.lets_encrypt_tips')"
              :disabled="busy"
            />
            <ConfigField
              name="http2https"
              type="toggle"
              v-model="cfg.http2https"
              :label="$t('settings.http2https')"
              :disabled="busy"
            />

            <h4 class="mg-bottom">{{ $t("settings.storage") }}</h4>
            <ConfigField
              name="backend"
              type="select"
              v-model="cfg.backend"
              :label="$t('settings.backend')"
              :helper="$t('settings.backend_helper')"
              :options="[
                { value: 'bundled', label: $t('settings.backend_bundled') },
                { value: 'external', label: $t('settings.backend_external') },
              ]"
              :disabled="busy"
            />
            <template v-if="cfg.backend === 'bundled'">
              <ConfigField
                name="opensearch_heap_mb"
                type="number"
                v-model="cfg.opensearch_heap_mb"
                :label="$t('settings.opensearch_heap_mb')"
                :helper="$t('settings.opensearch_heap_mb_helper')"
                :invalid-message="error.opensearch_heap_mb"
                :disabled="busy"
              />
              <ConfigField
                name="admin_password"
                type="password"
                v-model="secrets.admin_password"
                :secret-set="set.admin_password_set"
                :label="$t('settings.admin_password')"
                :helper="$t('settings.admin_password_helper')"
                :invalid-message="error.admin_password"
                :disabled="busy"
                ref="admin_password"
              />
              <ConfigField
                name="retention_days"
                type="number"
                v-model="cfg.retention_days"
                :label="$t('settings.retention_days')"
                :helper="$t('settings.retention_days_helper')"
                :invalid-message="error.retention_days"
                :disabled="busy"
              />
              <ConfigField
                name="dashboards_enabled"
                type="toggle"
                v-model="cfg.dashboards_enabled"
                :label="$t('settings.dashboards_enabled')"
                :tooltip="$t('settings.dashboards_enabled_tooltip')"
                :disabled="busy"
              />
            </template>
            <template v-else>
              <ConfigField
                name="external_type"
                type="select"
                v-model="cfg.external_type"
                :label="$t('settings.external_type')"
                :options="[
                  { value: 'opensearch', label: 'OpenSearch' },
                  { value: 'elasticsearch', label: 'Elasticsearch' },
                ]"
                :disabled="busy"
              />
              <ConfigField
                name="external_hosts"
                v-model="cfg.external_hosts"
                :label="$t('settings.external_hosts')"
                placeholder="https://search.example.org:9200"
                :invalid-message="error.external_hosts"
                :disabled="busy"
                ref="external_hosts"
              />
              <ConfigField
                name="external_user"
                v-model="cfg.external_user"
                :label="$t('settings.user')"
                :disabled="busy"
              />
              <ConfigField
                name="external_password"
                type="password"
                v-model="secrets.external_password"
                :secret-set="set.external_password_set"
                :label="$t('settings.password')"
                :disabled="busy"
              />
              <ConfigField
                name="external_ssl"
                type="toggle"
                v-model="cfg.external_ssl"
                :label="$t('settings.ssl')"
                :disabled="busy"
              />
              <ConfigField
                name="external_skip_verify"
                type="toggle"
                v-model="cfg.external_skip_verify"
                :label="$t('settings.skip_verify')"
                :disabled="busy"
              />
            </template>
            <ConfigField
              name="grafana_enabled"
              type="toggle"
              v-model="cfg.grafana_enabled"
              :label="$t('settings.grafana_enabled')"
              :tooltip="$t('settings.grafana_enabled_tooltip')"
              :disabled="busy"
            />

            <h4 class="mg-bottom">{{ $t("settings.mailbox") }}</h4>
            <ConfigField
              name="input_type"
              type="select"
              v-model="cfg.input_type"
              :label="$t('settings.input_type')"
              :options="[
                { value: 'none', label: $t('settings.input_none') },
                { value: 'imap', label: 'IMAP' },
                { value: 'msgraph', label: 'Microsoft Graph (Microsoft 365)' },
                { value: 'gmail', label: 'Gmail API' },
              ]"
              :disabled="busy"
            />
            <template v-if="cfg.input_type === 'imap'">
              <MailServerPicker
                class="mg-bottom"
                :disabled="busy"
                @select="pickServer(cfg, $event)"
              />
              <ConfigField
                name="imap_host"
                v-model="cfg.imap_host"
                :label="$t('settings.imap_host')"
                placeholder="imap.example.org"
                :invalid-message="error.imap_host"
                :disabled="busy"
                ref="imap_host"
              />
              <ConfigField
                name="imap_port"
                type="number"
                v-model="cfg.imap_port"
                :label="$t('settings.port')"
                :disabled="busy"
              />
              <ConfigField
                name="imap_ssl"
                type="toggle"
                v-model="cfg.imap_ssl"
                :label="$t('settings.imap_ssl')"
                :tooltip="$t('settings.imap_ssl_tooltip')"
                :disabled="busy"
              />
              <ConfigField
                name="imap_skip_verify"
                type="toggle"
                v-model="cfg.imap_skip_verify"
                :label="$t('settings.skip_verify')"
                :disabled="busy"
              />
              <ConfigField
                name="imap_user"
                v-model="cfg.imap_user"
                :label="$t('settings.user')"
                :disabled="busy"
              />
              <ConfigField
                name="imap_password"
                type="password"
                v-model="secrets.imap_password"
                :secret-set="set.imap_password_set"
                :label="$t('settings.password')"
                :invalid-message="error.imap_password"
                :disabled="busy"
                ref="imap_password"
              />
            </template>
            <template v-if="cfg.input_type === 'msgraph'">
              <ConfigField
                name="msgraph_auth_method"
                type="select"
                v-model="cfg.msgraph_auth_method"
                :label="$t('settings.msgraph_auth_method')"
                :options="[
                  { value: 'ClientSecret', label: 'ClientSecret' },
                  { value: 'UsernamePassword', label: 'UsernamePassword' },
                ]"
                :disabled="busy"
              />
              <ConfigField
                name="msgraph_client_id"
                v-model="cfg.msgraph_client_id"
                :label="$t('settings.msgraph_client_id')"
                :invalid-message="error.msgraph_client_id"
                :disabled="busy"
                ref="msgraph_client_id"
              />
              <ConfigField
                name="msgraph_client_secret"
                type="password"
                v-model="secrets.msgraph_client_secret"
                :secret-set="set.msgraph_client_secret_set"
                :label="$t('settings.msgraph_client_secret')"
                :disabled="busy"
              />
              <ConfigField
                name="msgraph_tenant_id"
                v-model="cfg.msgraph_tenant_id"
                :label="$t('settings.msgraph_tenant_id')"
                :invalid-message="error.msgraph_tenant_id"
                :disabled="busy"
                ref="msgraph_tenant_id"
              />
              <ConfigField
                name="msgraph_mailbox"
                v-model="cfg.msgraph_mailbox"
                :label="$t('settings.msgraph_mailbox')"
                :disabled="busy"
              />
              <template v-if="cfg.msgraph_auth_method === 'UsernamePassword'">
                <ConfigField
                  name="msgraph_user"
                  v-model="cfg.msgraph_user"
                  :label="$t('settings.user')"
                  :disabled="busy"
                />
                <ConfigField
                  name="msgraph_password"
                  type="password"
                  v-model="secrets.msgraph_password"
                  :secret-set="set.msgraph_password_set"
                  :label="$t('settings.password')"
                  :disabled="busy"
                />
              </template>
            </template>
            <template v-if="cfg.input_type === 'gmail'">
              <ConfigField
                name="gmail_credentials"
                type="textarea"
                v-model="secrets.gmail_credentials"
                :label="$t('settings.gmail_credentials')"
                :helper="
                  set.gmail_credentials_set
                    ? $t('settings.gmail_credentials_set')
                    : $t('settings.gmail_credentials_helper')
                "
                :invalid-message="error.gmail_credentials"
                :disabled="busy"
                ref="gmail_credentials"
              />
              <ConfigField
                name="gmail_delegated_user"
                v-model="cfg.gmail_delegated_user"
                :label="$t('settings.gmail_delegated_user')"
                :invalid-message="error.gmail_delegated_user"
                :disabled="busy"
                ref="gmail_delegated_user"
              />
            </template>
            <template v-if="cfg.input_type !== 'none'">
              <ConfigField
                name="reports_folder"
                v-model="cfg.reports_folder"
                :label="$t('settings.reports_folder')"
                :disabled="busy"
              />
              <ConfigField
                name="archive_folder"
                v-model="cfg.archive_folder"
                :label="$t('settings.archive_folder')"
                :disabled="busy"
              />
              <ConfigField
                name="delete"
                type="toggle"
                v-model="cfg.delete"
                :label="$t('settings.delete')"
                :tooltip="$t('settings.delete_tooltip')"
                :disabled="busy"
              />
              <ConfigField
                name="watch"
                type="toggle"
                v-model="cfg.watch"
                :label="$t('settings.watch')"
                :tooltip="$t('settings.watch_tooltip')"
                :disabled="busy"
              />
              <ConfigField
                v-if="!cfg.watch"
                name="poll_interval"
                type="number"
                v-model="cfg.poll_interval"
                :label="$t('settings.poll_interval')"
                :disabled="busy"
              />
            </template>

            <cv-accordion class="mg-bottom maxwidth">
              <cv-accordion-item>
                <template slot="title">{{
                  $t("settings.processing")
                }}</template>
                <template slot="content">
                  <ConfigField
                    name="save_aggregate"
                    type="toggle"
                    v-model="cfg.save_aggregate"
                    :label="$t('settings.save_aggregate')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="save_failure"
                    type="toggle"
                    v-model="cfg.save_failure"
                    :label="$t('settings.save_failure')"
                    :tooltip="$t('settings.save_failure_tooltip')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="save_smtp_tls"
                    type="toggle"
                    v-model="cfg.save_smtp_tls"
                    :label="$t('settings.save_smtp_tls')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="strip_attachment_payloads"
                    type="toggle"
                    v-model="cfg.strip_attachment_payloads"
                    :label="$t('settings.strip_attachment_payloads')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="geoip"
                    type="select"
                    v-model="cfg.geoip"
                    :label="$t('settings.geoip')"
                    :options="[
                      { value: 'bundled', label: $t('settings.geoip_bundled') },
                      { value: 'ipinfo', label: $t('settings.geoip_ipinfo') },
                      { value: 'maxmind', label: $t('settings.geoip_maxmind') },
                    ]"
                    :disabled="busy"
                  />
                  <ConfigField
                    v-if="cfg.geoip === 'ipinfo'"
                    name="ipinfo_token"
                    type="password"
                    v-model="secrets.ipinfo_token"
                    :secret-set="set.ipinfo_token_set"
                    :label="$t('settings.ipinfo_token')"
                    :disabled="busy"
                  />
                  <template v-if="cfg.geoip === 'maxmind'">
                    <ConfigField
                      name="maxmind_account_id"
                      v-model="cfg.maxmind_account_id"
                      :label="$t('settings.maxmind_account_id')"
                      :invalid-message="error.maxmind_account_id"
                      :disabled="busy"
                      ref="maxmind_account_id"
                    />
                    <ConfigField
                      name="maxmind_license_key"
                      type="password"
                      v-model="secrets.maxmind_license_key"
                      :secret-set="set.maxmind_license_key_set"
                      :label="$t('settings.maxmind_license_key')"
                      :invalid-message="error.maxmind_license_key"
                      :disabled="busy"
                      ref="maxmind_license_key"
                    />
                  </template>
                  <ConfigField
                    name="nameservers"
                    v-model="nameserversText"
                    :label="$t('settings.nameservers')"
                    :helper="$t('settings.nameservers_helper')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="dns_timeout"
                    type="number"
                    v-model="cfg.dns_timeout"
                    :label="$t('settings.dns_timeout')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="offline"
                    type="toggle"
                    v-model="cfg.offline"
                    :label="$t('settings.offline')"
                    :tooltip="$t('settings.offline_tooltip')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="n_procs"
                    type="number"
                    v-model="cfg.n_procs"
                    :label="$t('settings.n_procs')"
                    :disabled="busy"
                  />
                  <ConfigField
                    name="log_level"
                    type="select"
                    v-model="cfg.log_level"
                    :label="$t('settings.log_level')"
                    :options="
                      ['silent', 'warnings', 'verbose', 'debug'].map((v) => ({
                        value: v,
                        label: $t('settings.log_' + v),
                      }))
                    "
                    :disabled="busy"
                  />
                </template>
              </cv-accordion-item>
              <cv-accordion-item>
                <template slot="title">{{
                  $t("settings.summary_email")
                }}</template>
                <template slot="content">
                  <p class="mg-bottom">
                    {{ $t("settings.summary_email_description") }}
                  </p>
                  <ConfigField
                    name="email_enabled"
                    type="toggle"
                    v-model="cfg.email_enabled"
                    :label="$t('settings.email_enabled')"
                    :disabled="busy"
                  />
                  <template v-if="cfg.email_enabled">
                    <ConfigField
                      name="email_to"
                      v-model="emailToText"
                      :label="$t('settings.email_to')"
                      :helper="$t('settings.comma_separated')"
                      :disabled="busy"
                    />
                    <ConfigField
                      name="email_from"
                      v-model="cfg.email_from"
                      :label="$t('settings.email_from')"
                      :disabled="busy"
                    />
                    <ConfigField
                      name="email_subject"
                      v-model="cfg.email_subject"
                      :label="$t('settings.email_subject')"
                      :disabled="busy"
                    />
                  </template>
                </template>
              </cv-accordion-item>
              <cv-accordion-item>
                <template slot="title">{{ $t("settings.outputs") }}</template>
                <template slot="content">
                  <p class="mg-bottom">
                    {{ $t("settings.outputs_description") }}
                  </p>
                  <div
                    v-for="out in outputs"
                    :key="out.key"
                    class="mg-bottom output"
                  >
                    <ConfigField
                      :name="out.key + '_enabled'"
                      type="toggle"
                      v-model="cfg[out.key + '_enabled']"
                      :label="out.label"
                      :disabled="busy"
                    />
                    <template v-if="cfg[out.key + '_enabled']">
                      <ConfigField
                        v-for="f in out.fields"
                        :key="f.name"
                        :name="f.name"
                        :type="f.type || 'text'"
                        :options="f.options || []"
                        :label="$t('settings.' + f.name)"
                        :secret-set="!!f.secret && set[f.name + '_set']"
                        :value="f.secret ? secrets[f.name] : cfg[f.name]"
                        @input="
                          f.secret
                            ? (secrets[f.name] = $event)
                            : (cfg[f.name] = $event)
                        "
                        :disabled="busy"
                      />
                    </template>
                  </div>
                </template>
              </cv-accordion-item>
            </cv-accordion>

            <NsInlineNotification
              v-if="error.configureModule"
              kind="error"
              :title="$t('action.configure-module')"
              :description="error.configureModule"
              :showCloseButton="false"
            />
            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="busy"
              >{{ $t("settings.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import {
  QueryParamService,
  UtilService,
  TaskService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";
import ConfigField from "@/components/ConfigField";
import MailServerPicker from "@/components/MailServerPicker";

// configure-module fields edited here (tenants have their own page)
const FIELDS = [
  "host",
  "http2https",
  "lets_encrypt",
  "backend",
  "opensearch_heap_mb",
  "external_type",
  "external_hosts",
  "external_user",
  "external_ssl",
  "external_skip_verify",
  "retention_days",
  "dashboards_enabled",
  "grafana_enabled",
  "save_aggregate",
  "save_failure",
  "save_smtp_tls",
  "strip_attachment_payloads",
  "geoip",
  "maxmind_account_id",
  "nameservers",
  "dns_timeout",
  "offline",
  "n_procs",
  "log_level",
  "input_type",
  "imap_host",
  "imap_port",
  "imap_ssl",
  "imap_skip_verify",
  "imap_user",
  "reports_folder",
  "archive_folder",
  "watch",
  "poll_interval",
  "delete",
  "msgraph_auth_method",
  "msgraph_client_id",
  "msgraph_tenant_id",
  "msgraph_mailbox",
  "msgraph_user",
  "gmail_delegated_user",
  "email_enabled",
  "email_to",
  "email_from",
  "email_subject",
  "kafka_enabled",
  "kafka_hosts",
  "kafka_user",
  "kafka_ssl",
  "kafka_aggregate_topic",
  "kafka_failure_topic",
  "kafka_smtp_tls_topic",
  "s3_enabled",
  "s3_bucket",
  "s3_path",
  "s3_region",
  "s3_endpoint",
  "s3_access_key_id",
  "syslog_enabled",
  "syslog_server",
  "syslog_port",
  "syslog_protocol",
  "webhook_enabled",
  "webhook_aggregate_url",
  "webhook_failure_url",
  "webhook_smtp_tls_url",
  "webhook_timeout",
  "splunk_enabled",
  "splunk_url",
  "splunk_index",
  "splunk_skip_verify",
];
const SECRETS = [
  "admin_password",
  "external_password",
  "imap_password",
  "msgraph_client_secret",
  "msgraph_password",
  "gmail_credentials",
  "ipinfo_token",
  "maxmind_license_key",
  "kafka_password",
  "s3_secret_access_key",
  "splunk_token",
];

export default {
  name: "Settings",
  components: { ConfigField, MailServerPicker },
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    moduleTask,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    const empty = (keys, val) => Object.fromEntries(keys.map((k) => [k, val]));
    return {
      q: { page: "settings" },
      urlCheckInterval: null,
      cfg: { backend: "bundled", input_type: "none", host: "" },
      secrets: empty(SECRETS, ""),
      set: empty(
        SECRETS.map((s) => s + "_set"),
        false
      ),
      nameserversText: "",
      emailToText: "",
      loading: { getConfiguration: true, configureModule: false },
      error: {
        getConfiguration: "",
        configureModule: "",
        ...empty(FIELDS, ""),
        ...empty(SECRETS, ""),
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.getConfiguration || this.loading.configureModule;
    },
    outputs() {
      return [
        {
          key: "kafka",
          label: "Kafka",
          fields: [
            { name: "kafka_hosts" },
            { name: "kafka_user" },
            { name: "kafka_password", type: "password", secret: true },
            { name: "kafka_ssl", type: "toggle" },
            { name: "kafka_aggregate_topic" },
            { name: "kafka_failure_topic" },
            { name: "kafka_smtp_tls_topic" },
          ],
        },
        {
          key: "s3",
          label: "Amazon S3 / S3 compatible",
          fields: [
            { name: "s3_bucket" },
            { name: "s3_path" },
            { name: "s3_region" },
            { name: "s3_endpoint" },
            { name: "s3_access_key_id" },
            { name: "s3_secret_access_key", type: "password", secret: true },
          ],
        },
        {
          key: "syslog",
          label: "Syslog",
          fields: [
            { name: "syslog_server" },
            { name: "syslog_port", type: "number" },
            {
              name: "syslog_protocol",
              type: "select",
              options: ["udp", "tcp", "tls"].map((v) => ({
                value: v,
                label: v.toUpperCase(),
              })),
            },
          ],
        },
        {
          key: "webhook",
          label: "Webhook",
          fields: [
            { name: "webhook_aggregate_url" },
            { name: "webhook_failure_url" },
            { name: "webhook_smtp_tls_url" },
            { name: "webhook_timeout", type: "number" },
          ],
        },
        {
          key: "splunk",
          label: "Splunk HEC",
          fields: [
            { name: "splunk_url" },
            { name: "splunk_token", type: "password", secret: true },
            { name: "splunk_index" },
            { name: "splunk_skip_verify", type: "toggle" },
          ],
        },
      ];
    },
  },
  created() {
    this.getConfiguration();
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  methods: {
    pickServer(target, server) {
      target.imap_host = server.host;
      target.imap_port = server.port;
      // ns8-mail serves IMAP with STARTTLS on port 143, with a certificate
      // for its mail host name, not for the cluster VPN address
      target.imap_ssl = server.port === 993;
      target.imap_skip_verify = true;
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const config = await this.runModuleTask("get-configuration");
        const cfg = {};
        for (const key of FIELDS) {
          cfg[key] = config[key];
        }
        this.cfg = cfg;
        for (const s of SECRETS) {
          this.set[s + "_set"] = !!config[s + "_set"];
          this.secrets[s] = "";
        }
        this.nameserversText = (config.nameservers || []).join(", ");
        this.emailToText = (config.email_to || []).join(", ");
      } catch (failure) {
        this.error.getConfiguration = this.taskErrorMessage(failure);
      }
      this.loading.getConfiguration = false;
    },
    validate() {
      this.clearErrors(this);
      if (!this.cfg.host) {
        this.error.host = this.$t("common.required");
        this.focusElement("host");
        return false;
      }
      if (
        this.cfg.backend === "bundled" &&
        !this.set.admin_password_set &&
        !this.secrets.admin_password
      ) {
        this.error.admin_password = this.$t("common.required");
        return false;
      }
      return true;
    },
    async configureModule() {
      if (!this.validate()) {
        return;
      }
      this.loading.configureModule = true;
      const data = { ...this.cfg };
      data.nameservers = this.linesToList(this.nameserversText);
      data.email_to = this.linesToList(this.emailToText);
      for (const s of SECRETS) {
        if (this.secrets[s]) {
          data[s] = this.secrets[s];
        }
      }
      try {
        await this.runModuleTask("configure-module", data, {
          title: this.$t("settings.instance_configuration", {
            instance: this.instanceName,
          }),
          description: this.$t("settings.configuring"),
          hidden: false,
        });
        this.getConfiguration();
      } catch (failure) {
        this.error.configureModule = this.taskErrorMessage(failure);
      }
      this.loading.configureModule = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}
.maxwidth {
  max-width: 38rem;
}
.output {
  border-left: 2px solid $ui-03;
  padding-left: $spacing-05;
}
</style>
