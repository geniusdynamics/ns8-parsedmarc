<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<!-- One settings field: text, password (write-only secret), number,
     toggle, select or textarea, bound with v-model -->
<template>
  <div class="mg-bottom config-field">
    <NsToggle
      v-if="type === 'toggle'"
      :value="name"
      :label="label"
      v-model="inner"
      :disabled="disabled"
    >
      <template v-if="tooltip" #tooltip>{{ tooltip }}</template>
      <template slot="text-left">{{ $t("common.disabled") }}</template>
      <template slot="text-right">{{ $t("common.enabled") }}</template>
    </NsToggle>
    <cv-select
      v-else-if="type === 'select'"
      :label="label"
      v-model="inner"
      :helper-text="helper"
      :invalid-message="invalidMessage"
      :disabled="disabled"
      :ref="name"
    >
      <cv-select-option
        v-for="opt in options"
        :key="opt.value"
        :value="opt.value"
        >{{ opt.label }}</cv-select-option
      >
    </cv-select>
    <cv-text-area
      v-else-if="type === 'textarea'"
      :label="label"
      v-model="inner"
      :helper-text="helper"
      :invalid-message="invalidMessage"
      :placeholder="placeholder"
      :disabled="disabled"
      :ref="name"
    />
    <NsTextInput
      v-else
      :type="type === 'password' ? 'password' : type"
      :autocomplete="type === 'password' ? 'new-password' : 'off'"
      :label="label"
      v-model.trim="inner"
      :helper-text="helper"
      :invalid-message="invalidMessage"
      :placeholder="
        type === 'password' && secretSet ? $t('common.unchanged') : placeholder
      "
      :disabled="disabled"
      :ref="name"
    />
  </div>
</template>

<script>
export default {
  name: "ConfigField",
  props: {
    value: { type: [String, Number, Boolean], default: "" },
    name: { type: String, default: "" },
    type: { type: String, default: "text" },
    label: { type: String, default: "" },
    helper: { type: String, default: "" },
    tooltip: { type: String, default: "" },
    placeholder: { type: String, default: "" },
    invalidMessage: { type: String, default: "" },
    disabled: { type: Boolean, default: false },
    secretSet: { type: Boolean, default: false },
    options: { type: Array, default: () => [] },
  },
  methods: {
    focus() {
      const el = this.$refs[this.name];
      if (el && el.focus) {
        el.focus();
      }
    },
  },
  computed: {
    inner: {
      get() {
        return this.value;
      },
      set(val) {
        if (this.type === "number") {
          const num = Number(val);
          this.$emit("input", val === "" || isNaN(num) ? val : num);
        } else {
          this.$emit("input", val);
        }
      },
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}
.config-field {
  max-width: 38rem;
}
</style>
