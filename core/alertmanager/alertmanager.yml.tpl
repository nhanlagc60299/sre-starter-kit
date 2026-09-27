global:
  resolve_timeout: 5m

route:
  receiver: warning
  group_by: [alertname, service, instance]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers: [ 'severity="critical"' ]
      receiver: critical
      group_wait: 10s
      repeat_interval: 1h
      continue: true
    - matchers: [ 'severity="critical"' ]
      receiver: webhook-triage
    - matchers: [ 'severity="warning"' ]
      receiver: warning
      group_interval: 30m
      repeat_interval: 24h

inhibit_rules:
  # Node is down: silence everything else from that instance.
  - source_matchers: [ 'alertname="NodeDown"' ]
    target_matchers: [ 'module="infra"' ]
    equal: [instance]
  # Disk is already critical on this mount: the warning adds nothing.
  - source_matchers: [ 'alertname="DiskFull"' ]
    target_matchers: [ 'alertname="DiskLow"' ]
    equal: [instance, mountpoint]
  # Same pair for error rate.
  - source_matchers: [ 'alertname="HighErrorRate"' ]
    target_matchers: [ 'alertname="ElevatedErrorRate"' ]
    equal: [service]

# ${SANITIZE} is a fixed pipe chain (defined once in scripts/render.sh) substituted the same way as
# ${PROJECT_NAME} above. It must follow every action that interpolates CommonLabels/Labels/
# GroupLabels/Annotations/CommonAnnotations below and in the receiver blocks scripts/render.sh adds,
# because those values can come from a lower-trust producer (an AWS Name tag, a Pushgateway push, a
# StatsD packet, a postgres_exporter identifier -- Pro modules, but this template is shared) and
# reach Slack/Discord/Teams/Telegram/email with the operator's webhook identity. ${PROJECT_NAME},
# ${GRAFANA_EXTERNAL_URL} etc. are operator-authored and never need it.
receivers:
  - name: critical
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        send_resolved: true
        link_names: false # never resolve @name into a Slack ID; defense in depth, the text below is already sanitized
        title: ':red_circle: [${PROJECT_NAME}] {{ .CommonLabels.alertname | ${SANITIZE} }}'
        text: >-
          {{ range .Alerts }}*{{ .Annotations.summary | ${SANITIZE} }}*
          <{{ .Annotations.runbook_url | ${SANITIZE} }}|runbook> · <${GRAFANA_EXTERNAL_URL}/d/{{ .Annotations.dashboard | ${SANITIZE} }}|dashboard>
          {{ end }}
    # RECEIVERS_CRITICAL_EXTRA
  - name: warning
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        send_resolved: true
        link_names: false # see the critical receiver above
        title: ':large_yellow_circle: [${PROJECT_NAME}] {{ .CommonLabels.alertname | ${SANITIZE} }}'
        text: >-
          {{ range .Alerts }}{{ .Annotations.summary | ${SANITIZE} }} <{{ .Annotations.runbook_url | ${SANITIZE} }}|runbook> · <${GRAFANA_EXTERNAL_URL}/d/{{ .Annotations.dashboard | ${SANITIZE} }}|dashboard>
          {{ end }}
    # RECEIVERS_WARNING_EXTRA
  - name: webhook-triage
    # Reserved: point TRIAGE_WEBHOOK_URL at an AI triage service to receive a copy of every critical alert.
    # With TRIAGE_WEBHOOK_TOKEN set, render.sh adds http_config.authorization at the marker.
    webhook_configs:
      - url: ${TRIAGE_WEBHOOK_URL}
        send_resolved: false
        # TRIAGE_WEBHOOK_AUTH
