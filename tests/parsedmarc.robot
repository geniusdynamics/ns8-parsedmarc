*** Settings ***
Library    SSHLibrary
Library    Collections

*** Variables ***
# Names under the reserved .test TLD: nothing resolves them
${TEST_HOST}       dmarc.ns8-ci.test
${ADMIN_PASS}      CiAdminPass2026xyz
${ACME_PASS}       CiAcmeTenantPass2026
${BETA_PASS}       CiBetaTenantPass2026
${IMPORT_DIR}      ci-import

*** Keywords ***
Run action
    [Arguments]    ${action}    ${data}={}
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/${action} --data '${data}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${action} failed: ${output}
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    RETURN    ${result}

Module python
    [Arguments]    ${code}
    ${output}  ${err}  ${rc} =    Execute Command    runagent -m ${module_id} python3 -c '${code}'
    ...    return_rc=True    return_stderr=True
    Should Be Equal As Integers    ${rc}  0    ${output} ${err}
    RETURN    ${output}

Document count
    [Arguments]    ${pattern}
    ${output} =    Module python    import parsedmarc_ns8 as p; p.os_request("/_refresh", "POST"); print(p.os_request("/${pattern}/_count?ignore_unavailable=true")["count"])
    RETURN    ${output}

Count as tenant
    [Arguments]    ${user}    ${password}    ${pattern}
    ${port} =    Module python    import os; print(os.environ["OPENSEARCH_PORT"])
    ${output} =    Execute Command    curl -s --cacert /home/${module_id}/.config/state/certs/ca.pem -u '${user}:${password}' 'https://127.0.0.1:${port}/${pattern}/_count'
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    RETURN    ${result}[count]

HTTP code
    [Arguments]    ${path}    ${auth}=${EMPTY}
    ${output} =    Execute Command    curl -sk -o /dev/null -w '\%{http_code}' --max-time 60 --resolve ${TEST_HOST}:443:127.0.0.1 ${auth} https://${TEST_HOST}${path}
    RETURN    ${output}

Redis hash field
    [Arguments]    ${key}    ${field}
    # redis-exec prints None for a missing field
    ${output} =    Execute Command    runagent redis-exec HGET ${key} ${field}
    IF    $output == 'None'    RETURN    ${EMPTY}
    RETURN    ${output}

Cluster Prometheus URL
    ${metrics_id} =    Execute Command    runagent redis-exec GET cluster/default_instance/metrics
    Skip If    $metrics_id in ('', 'None')    The cluster has no metrics module
    ${path} =    Execute Command    runagent -m ${metrics_id} python3 -c 'import os; print(os.environ.get("PROMETHEUS_PATH", "").strip("/"))'
    ${url} =    Evaluate    'http://127.0.0.1:9091' + ('/' + $path if $path else '')
    RETURN    ${url}

Prometheus rules should contain
    [Arguments]    ${url}    ${alert}
    ${output} =    Execute Command    curl -s ${url}/api/v1/rules
    Should Contain    ${output}    "${alert}"

Prometheus should have the series
    [Arguments]    ${url}
    Execute Command    runagent -m node refresh-module-metrics
    ${output} =    Execute Command    curl -s --get --data-urlencode 'query=parsedmarc_up{module_id="${module_id}"}' ${url}/api/v1/query
    ${result} =    Evaluate    json.loads($output)    modules=json
    Should Not Be Empty    ${result}[data][result]
    Should Be Equal    ${result}[data][result][0][value][1]    1

*** Test Cases ***
Check if parsedmarc is installed correctly
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${output}
    &{output} =    Evaluate    ${output}
    Set Suite Variable    ${module_id}    ${output.module_id}

Check if parsedmarc can be configured
    ${data} =    Catenate    SEPARATOR=
    ...    {"host":"${TEST_HOST}","http2https":true,"lets_encrypt":false,
    ...    "backend":"bundled","opensearch_heap_mb":512,"admin_password":"${ADMIN_PASS}",
    ...    "dashboards_enabled":true,"grafana_enabled":true,"retention_days":365,
    ...    "offline":true,"input_type":"none","save_aggregate":true,"save_failure":true,"save_smtp_tls":true,
    ...    "tenants":[{"name":"acme","domains":["example.com"],"password":"${ACME_PASS}"},
    ...    {"name":"beta","domains":["example.de","domain.de"],"password":"${BETA_PASS}"}]}
    Run action    configure-module    ${data}

Check if the configuration reads back without secrets
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-configuration --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Not Contain    ${output}    ${ADMIN_PASS}
    Should Not Contain    ${output}    ${ACME_PASS}
    ${config} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${config}[host]    ${TEST_HOST}
    Should Be Equal    ${config}[backend]    bundled
    Should Be True    ${config}[admin_password_set]
    Should Not Be True    ${config}[imap_password_set]
    Dictionary Should Not Contain Key    ${config}    admin_password
    ${names} =    Evaluate    [t['name'] for t in $config['tenants']]
    Should Be Equal    ${names}    ${{ ['acme', 'beta'] }}
    Should Be True    ${config}[tenants][0][password_set]
    Dictionary Should Not Contain Key    ${config}[tenants][0]    password
    Should Be True    ${config}[metrics_enabled]
    Dictionary Should Contain Key    ${config}[cluster_metrics]    installed
    Should Be Equal    ${config}[cluster_metrics][dashboard_uid]    parsedmarc-${module_id}

Check if the secrets are private
    ${output} =    Execute Command    find /home/${module_id}/.config/state/secrets /home/${module_id}/.config/state/parsedmarc -name '*.ini' -o -type f -path '*secrets*' | xargs stat -c '%a' | sort -u
    Should Be Equal    ${output}    600

Check if the backend is healthy
    ${output} =    Module python    import parsedmarc_ns8 as p; print(p.opensearch_ready())
    Should Be Equal    ${output}    True
    ${output} =    Execute Command    runagent -m ${module_id} systemctl --user is-active parsedmarc.service opensearch-app.service dashboards-app.service grafana-app.service
    Should Be Equal    ${output}    active\nactive\nactive\nactive

Check if sample reports are parsed into the tenant indices
    Execute Command    rm -rf /home/${module_id}/.config/state/${IMPORT_DIR}
    Put Directory    ${CURDIR}/fixtures    /home/${module_id}/.config/state/${IMPORT_DIR}    recursive=True
    Execute Command    chown -R ${module_id}:${module_id} /home/${module_id}/.config/state/${IMPORT_DIR}
    ${output}  ${err}  ${rc} =    Execute Command    runagent -m ${module_id} parsedmarc-import ${IMPORT_DIR}
    ...    return_rc=True    return_stderr=True
    Should Be Equal As Integers    ${rc}  0    ${output} ${err}
    ${count} =    Document count    acme_dmarc_aggregate-*
    Should Be True    ${count} > 0
    ${count} =    Document count    beta_dmarc_aggregate-*
    Should Be True    ${count} > 0
    ${count} =    Document count    acme_dmarc_failure-*
    Should Be True    ${count} > 0
    ${count} =    Document count    beta_dmarc_failure-*
    Should Be True    ${count} > 0
    ${count} =    Document count    dmarc_aggregate-*
    Should Be Equal As Integers    ${count}    0

Check if the metrics are exported
    ${output}  ${err}  ${rc} =    Execute Command    runagent -m ${module_id} export-metrics
    ...    return_rc=True    return_stderr=True
    Should Be Equal As Integers    ${rc}  0    ${err}
    Should Match Regexp    ${output}    (?m)^parsedmarc_up 1$
    Should Match Regexp    ${output}    (?m)^parsedmarc_collect_timestamp_seconds [0-9]+$
    Should Not Contain    ${output}    ${ADMIN_PASS}
    Should Not Contain    ${output}    ${ACME_PASS}

Check if the alert rules and the dashboard are published
    ${rules} =    Redis hash field    module/${module_id}/metrics_alert_rules    parsedmarc
    Should Contain    ${rules}    ParsedmarcStorageDown
    ${dash} =    Redis hash field    module/${module_id}/metrics_dashboards    parsedmarc
    ${dash} =    Evaluate    json.loads($dash)    modules=json
    Should Be Equal    ${dash}[uid]    parsedmarc-${module_id}
    ${uids} =    Evaluate    sorted({p['datasource']['uid'] for p in $dash['panels']})
    Should Be Equal    ${uids}    ${{ ['prometheus'] }}

Check if the cluster Prometheus loads the alert rules
    ${url} =    Cluster Prometheus URL
    Wait Until Keyword Succeeds    3 min    10s    Prometheus rules should contain    ${url}    ParsedmarcStorageDown

Check if the cluster Prometheus collects the metrics
    ${url} =    Cluster Prometheus URL
    ${rc} =    Execute Command    test -x /var/lib/nethserver/node/bin/refresh-module-metrics
    ...    return_rc=True    return_stdout=False
    Skip If    ${rc} != 0    The core has no export-metrics collector (3.24.0 or later)
    Wait Until Keyword Succeeds    5 min    20s    Prometheus should have the series    ${url}

Check if a tenant reads only its own indices
    ${own} =    Document count    acme_dmarc_aggregate-*
    ${seen} =    Count as tenant    acme    ${ACME_PASS}    *dmarc_aggregate*
    Should Be Equal As Integers    ${seen}    ${own}
    ${seen} =    Count as tenant    beta    ${BETA_PASS}    *dmarc_aggregate*
    ${own} =    Document count    beta_dmarc_aggregate-*
    Should Be Equal As Integers    ${seen}    ${own}

Check if the tenant dashboards are imported
    ${port} =    Module python    import os; print(os.environ["DASHBOARDS_PORT"])
    ${output} =    Execute Command    curl -s -u 'acme:${ACME_PASS}' -H 'securitytenant: acme' 'http://127.0.0.1:${port}/api/saved_objects/_find?type=index-pattern&per_page=100'
    Should Contain    ${output}    acme_dmarc_aggregate*
    Should Not Contain    ${output}    beta_dmarc

Check if the dashboards answer through Traefik and require authentication
    ${code} =    HTTP code    /api/status
    Should Be Equal    ${code}    401
    ${code} =    HTTP code    /api/status    -u 'admin:${ADMIN_PASS}'
    Should Be Equal    ${code}    200
    ${code} =    HTTP code    /api/status    -u 'acme:${ACME_PASS}'
    Should Be Equal    ${code}    200
    ${code} =    HTTP code    /api/status    -u 'acme:wrong-password-1234'
    Should Be Equal    ${code}    401
    ${code} =    HTTP code    /grafana/api/health
    Should Be Equal    ${code}    401

Check if a backup snapshot is taken
    ${output}  ${err}  ${rc} =    Execute Command    runagent -m ${module_id} module-dump-state
    ...    return_rc=True    return_stderr=True
    Should Be Equal As Integers    ${rc}  0    ${output} ${err}
    ${output} =    Module python    import parsedmarc_ns8 as p; print(p.latest_snapshot())
    Should Start With    ${output}    backup-

Check if disabling the metrics withdraws them
    Run action    configure-module    {"host":"${TEST_HOST}","metrics_enabled":false}
    ${rules} =    Redis hash field    module/${module_id}/metrics_alert_rules    parsedmarc
    Should Be Empty    ${rules}
    ${dash} =    Redis hash field    module/${module_id}/metrics_dashboards    parsedmarc
    Should Be Empty    ${dash}
    ${output} =    Execute Command    runagent -m ${module_id} export-metrics
    Should Be Empty    ${output}
    Run action    configure-module    {"host":"${TEST_HOST}","metrics_enabled":true}
    ${rules} =    Redis hash field    module/${module_id}/metrics_alert_rules    parsedmarc
    Should Contain    ${rules}    ParsedmarcStorageDown

Check if parsedmarc is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${output} =    Execute Command    runagent redis-exec EXISTS module/${module_id}/metrics_alert_rules module/${module_id}/metrics_dashboards
    Should Be Equal As Integers    ${output}    0
