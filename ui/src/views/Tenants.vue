<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("tenants.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <NsInlineNotification
          kind="info"
          :title="$t('tenants.how_title')"
          :description="$t('tenants.how_description')"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="error.page">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('tenants.error_title')"
          :description="error.page"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <NsButton
          kind="secondary"
          :icon="Add20"
          :disabled="busy || !host"
          class="mg-bottom"
          @click="openEditor(null)"
          >{{ $t("tenants.add") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            v-if="loading.page"
            :paragraph="true"
            :line-count="5"
          />
          <NsEmptyState
            v-else-if="!tenants.length"
            :title="$t('tenants.empty')"
          >
            <template #description>{{
              host
                ? $t("tenants.empty_description")
                : $t("tenants.configure_first")
            }}</template>
          </NsEmptyState>
          <cv-structured-list v-else>
            <template slot="headings">
              <cv-structured-list-heading>{{
                $t("tenants.name")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("tenants.domains")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("tenants.dashboards_login")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("tenants.mailbox")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading></cv-structured-list-heading>
            </template>
            <template slot="items">
              <cv-structured-list-item v-for="t in tenants" :key="t.name">
                <cv-structured-list-data
                  ><strong>{{ t.name }}</strong>
                  <div class="hint">{{ t.name }}_dmarc_*</div>
                </cv-structured-list-data>
                <cv-structured-list-data>{{
                  t.domains.join(", ")
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  t.password_set ? t.name : $t("tenants.no_login")
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  t.mailbox_enabled
                    ? t.imap_user + "@" + t.imap_host
                    : $t("tenants.main_mailbox")
                }}</cv-structured-list-data>
                <cv-structured-list-data class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Edit20"
                    :disabled="busy"
                    @click="openEditor(t)"
                    >{{ $t("tenants.edit") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    :disabled="busy"
                    @click="toDelete = t"
                    >{{ $t("tenants.remove") }}</NsButton
                  >
                </cv-structured-list-data>
              </cv-structured-list-item>
            </template>
          </cv-structured-list>
        </cv-tile>
      </cv-column>
    </cv-row>

    <NsModal
      size="default"
      :visible="editorVisible"
      :primary-button-disabled="loading.save"
      @modal-hidden="editorVisible = false"
      @primary-click="saveTenant"
    >
      <template slot="title">{{
        editing
          ? $t("tenants.edit_title", { name: form.name })
          : $t("tenants.add")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent="saveTenant">
          <ConfigField
            name="name"
            v-model="form.name"
            :label="$t('tenants.name')"
            :helper="$t('tenants.name_helper')"
            :invalid-message="error.name"
            :disabled="!!editing || loading.save"
            ref="name"
          />
          <ConfigField
            name="domains"
            type="textarea"
            v-model="form.domainsText"
            :label="$t('tenants.domains')"
            :helper="$t('tenants.domains_helper')"
            :invalid-message="error.domains"
            placeholder="example.com"
            :disabled="loading.save"
            ref="domains"
          />
          <ConfigField
            name="password"
            type="password"
            v-model="form.password"
            :secret-set="!!(editing && editing.password_set)"
            :label="$t('tenants.password')"
            :helper="$t('tenants.password_helper')"
            :invalid-message="error.password"
            :disabled="loading.save"
            ref="password"
          />
          <ConfigField
            name="mailbox_enabled"
            type="toggle"
            v-model="form.mailbox_enabled"
            :label="$t('tenants.own_mailbox')"
            :tooltip="$t('tenants.own_mailbox_tooltip')"
            :disabled="loading.save"
          />
          <template v-if="form.mailbox_enabled">
            <MailServerPicker
              class="mg-bottom"
              :disabled="loading.save"
              @select="pickServer"
            />
            <ConfigField
              name="imap_host"
              v-model="form.imap_host"
              :label="$t('settings.imap_host')"
              :invalid-message="error.imap_host"
              :disabled="loading.save"
              ref="imap_host"
            />
            <ConfigField
              name="imap_port"
              type="number"
              v-model="form.imap_port"
              :label="$t('settings.port')"
              :disabled="loading.save"
            />
            <ConfigField
              name="imap_ssl"
              type="toggle"
              v-model="form.imap_ssl"
              :label="$t('settings.imap_ssl')"
              :disabled="loading.save"
            />
            <ConfigField
              name="imap_skip_verify"
              type="toggle"
              v-model="form.imap_skip_verify"
              :label="$t('settings.skip_verify')"
              :disabled="loading.save"
            />
            <ConfigField
              name="imap_user"
              v-model="form.imap_user"
              :label="$t('settings.user')"
              :disabled="loading.save"
            />
            <ConfigField
              name="imap_password"
              type="password"
              v-model="form.imap_password"
              :secret-set="!!(editing && editing.imap_password_set)"
              :label="$t('settings.password')"
              :invalid-message="error.imap_password"
              :disabled="loading.save"
              ref="imap_password"
            />
            <ConfigField
              name="reports_folder"
              v-model="form.reports_folder"
              :label="$t('settings.reports_folder')"
              :disabled="loading.save"
            />
            <ConfigField
              name="archive_folder"
              v-model="form.archive_folder"
              :label="$t('settings.archive_folder')"
              :disabled="loading.save"
            />
            <ConfigField
              name="delete"
              type="toggle"
              v-model="form.delete"
              :label="$t('settings.delete')"
              :disabled="loading.save"
            />
          </template>
          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="$t('action.configure-module')"
            :description="error.save"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("tenants.save") }}</template>
    </NsModal>

    <NsDangerDeleteModal
      :isShown="!!toDelete"
      :name="toDelete ? toDelete.name : ''"
      :title="$t('tenants.remove')"
      :warning="$t('common.please_read_carefully')"
      :description="
        $t('tenants.remove_description', {
          name: toDelete ? toDelete.name : '',
        })
      "
      :typeToConfirm="
        $t('common.type_to_confirm', { name: toDelete ? toDelete.name : '' })
      "
      @hide="toDelete = null"
      @confirm="removeTenant"
    />
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

const TENANT_FIELDS = [
  "name",
  "domains",
  "mailbox_enabled",
  "imap_host",
  "imap_port",
  "imap_ssl",
  "imap_skip_verify",
  "imap_user",
  "reports_folder",
  "archive_folder",
  "delete",
];

function emptyForm() {
  return {
    name: "",
    domainsText: "",
    password: "",
    mailbox_enabled: false,
    imap_host: "",
    imap_port: 993,
    imap_ssl: true,
    imap_skip_verify: false,
    imap_user: "",
    imap_password: "",
    reports_folder: "INBOX",
    archive_folder: "Archive",
    delete: false,
  };
}

export default {
  name: "Tenants",
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
    return this.$t("tenants.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "tenants" },
      urlCheckInterval: null,
      host: "",
      tenants: [],
      editorVisible: false,
      editing: null,
      toDelete: null,
      form: emptyForm(),
      loading: { page: true, save: false },
      error: {
        page: "",
        save: "",
        name: "",
        domains: "",
        password: "",
        imap_host: "",
        imap_password: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.page || this.loading.save;
    },
  },
  created() {
    this.load();
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
    async load() {
      this.loading.page = true;
      this.error.page = "";
      try {
        const config = await this.runModuleTask("get-configuration");
        this.host = config.host;
        this.tenants = config.tenants;
      } catch (failure) {
        this.error.page = this.taskErrorMessage(failure);
      }
      this.loading.page = false;
    },
    openEditor(tenant) {
      this.clearErrors(this);
      this.editing = tenant;
      this.form = emptyForm();
      if (tenant) {
        for (const key of TENANT_FIELDS) {
          this.form[key] = tenant[key];
        }
        this.form.domainsText = tenant.domains.join("\n");
      }
      this.editorVisible = true;
    },
    pickServer(server) {
      this.form.imap_host = server.host;
      this.form.imap_port = server.port;
      this.form.imap_ssl = server.port === 993;
      this.form.imap_skip_verify = true;
    },
    payload(tenant) {
      const out = {};
      for (const key of TENANT_FIELDS) {
        out[key] = tenant[key];
      }
      return out;
    },
    async submit(tenants) {
      this.loading.save = true;
      this.error.save = "";
      try {
        await this.runModuleTask(
          "configure-module",
          { host: this.host, tenants },
          {
            title: this.$t("tenants.saving"),
            description: this.$t("settings.configuring"),
            hidden: false,
          }
        );
        this.editorVisible = false;
        this.toDelete = null;
        await this.load();
      } catch (failure) {
        if (failure.validationErrors) {
          // tenants.<n>.<field> -> field of the editor
          for (const verr of failure.validationErrors) {
            const field = verr.parameter.split(".").pop();
            if (field in this.error) {
              this.error[field] = this.$t("validation." + verr.error);
            }
          }
          this.error.save = this.taskErrorMessage(failure);
        } else {
          this.error.save = this.taskErrorMessage(failure);
          this.error.page = this.error.save;
        }
      }
      this.loading.save = false;
    },
    saveTenant() {
      this.clearErrors(this);
      const domains = this.linesToList(this.form.domainsText).map((d) =>
        d.toLowerCase()
      );
      if (!/^[a-z][a-z0-9]{1,30}$/.test(this.form.name)) {
        this.error.name = this.$t("tenants.name_invalid");
        this.focusElement("name");
        return;
      }
      if (
        !this.editing &&
        this.tenants.some((t) => t.name === this.form.name)
      ) {
        this.error.name = this.$t("validation.tenant_name_duplicated");
        this.focusElement("name");
        return;
      }
      if (!domains.length) {
        this.error.domains = this.$t("common.required");
        this.focusElement("domains");
        return;
      }
      if (this.form.password && this.form.password.length < 10) {
        this.error.password = this.$t("validation.password_too_short");
        this.focusElement("password");
        return;
      }
      const entry = this.payload({ ...this.form, domains });
      if (this.form.password) {
        entry.password = this.form.password;
      }
      if (this.form.mailbox_enabled && this.form.imap_password) {
        entry.imap_password = this.form.imap_password;
      }
      const others = this.tenants
        .filter((t) => t.name !== entry.name)
        .map((t) => this.payload(t));
      this.submit([...others, entry]);
    },
    removeTenant() {
      const name = this.toDelete.name;
      this.submit(
        this.tenants.filter((t) => t.name !== name).map((t) => this.payload(t))
      );
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}
.hint {
  color: $text-02;
  font-size: 0.75rem;
}
.actions {
  white-space: nowrap;
}
</style>
