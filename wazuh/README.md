# Wazuh integration

Files that live on the Wazuh manager, kept here in version control.

## Install

    sudo cp wazuh/integrations/custom-agentic-soc /var/ossec/integrations/
    sudo chown root:wazuh /var/ossec/integrations/custom-agentic-soc
    sudo chmod 750 /var/ossec/integrations/custom-agentic-soc

Add the block in `ossec.conf.snippet.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`, set `<api_key>` to the service's shared secret,
then restart the manager:

    sudo systemctl restart wazuh-manager

The hook forwards level-9+ alerts to the service, signed with HMAC-SHA256.
It is fire-and-forget: it never waits on analysis and never crashes the
integrator.

## Verdict writeback

Install the verdict rules and point Wazuh at the verdict log:

    sudo cp wazuh/rules/agentic_soc_rules.xml /var/ossec/etc/rules/
    sudo chown wazuh:wazuh /var/ossec/etc/rules/agentic_soc_rules.xml
    sudo chmod 660 /var/ossec/etc/rules/agentic_soc_rules.xml

Add the block in `ossec.conf.verdict-localfile.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`, then restart the manager. Verdict rules map
risk_level to Wazuh level (false_positive 3, low 5, medium 8, high 12,
critical 14) and sit in group `agentic_soc`, which the hook and API both drop
so a verdict is never re-analysed.

Verdict alerts use `no_full_log`. Every field is already decoded under
`agentic_soc.*`, so the raw JSON line would only repeat it in the dashboard.
