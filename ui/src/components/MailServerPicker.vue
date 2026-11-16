<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<!-- Fill the IMAP server from the mail modules of the cluster (ns8-mail and
     other modules publishing the imap service) -->
<template>
  <div>
    <NsButton
      kind="tertiary"
      size="small"
      :icon="Email20"
      :loading="loading"
      :disabled="disabled || loading"
      @click="load"
      >{{ $t("settings.pick_mail_server") }}</NsButton
    >
    <div v-if="loaded" class="servers">
      <p v-if="!servers.length">{{ $t("settings.no_mail_servers") }}</p>
      <NsButton
        v-for="srv in servers"
        :key="srv.module_id"
        kind="ghost"
        size="small"
        @click="$emit('select', srv)"
        >{{ srv.ui_name || srv.module_id }} ({{ srv.host }}:{{
          srv.port
        }})</NsButton
      >
    </div>
    <NsInlineNotification
      v-if="error"
      kind="error"
      :title="$t('action.list-mail-servers')"
      :description="error"
      :showCloseButton="false"
    />
  </div>
</template>

<script>
import { mapState } from "vuex";
import { TaskService, UtilService, IconService } from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

export default {
  name: "MailServerPicker",
  mixins: [TaskService, UtilService, IconService, moduleTask],
  props: { disabled: { type: Boolean, default: false } },
  data() {
    return { servers: [], loaded: false, loading: false, error: "" };
  },
  computed: { ...mapState(["instanceName", "core"]) },
  methods: {
    async load() {
      this.loading = true;
      this.error = "";
      try {
        const out = await this.runModuleTask("list-mail-servers");
        this.servers = out.servers;
        this.loaded = true;
      } catch (failure) {
        this.error = this.taskErrorMessage(failure);
      }
      this.loading = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.servers {
  margin-top: $spacing-03;
}
</style>
