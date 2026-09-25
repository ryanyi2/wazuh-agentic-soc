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
