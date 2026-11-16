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

Check if parsedmarc is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
