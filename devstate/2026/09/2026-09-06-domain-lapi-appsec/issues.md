# Issues

- [x] take small  spec `core_plugin_connection_source-files` → lapi + appsec package-layout specs (FindSpecHost at propose)
  Why: that spec names `package crowdsecconnection` file layout and forbids a new import path. This change removes that mixed package.
  Taken: deleted empty `openspec/specs/core_plugin_connection_source-files/`; layout lives in `core_plugin_lapi_connection` and `core_plugin_appsec_client`.
