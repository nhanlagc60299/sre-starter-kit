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

receivers:
  - name: critical
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        send_resolved: true
        title: ':red_circle: [${PROJECT_NAME}] {{ .CommonLabels.alertname }}'
        text: >-
          {{ range .Alerts }}*{{ .Annotations.summary }}*
          <{{ .Annotations.runbook_url }}|runbook>
          {{ end }}
    # RECEIVERS_CRITICAL_EXTRA
  - name: warning
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        send_resolved: true
        title: ':large_yellow_circle: [${PROJECT_NAME}] {{ .CommonLabels.alertname }}'
        text: >-
          {{ range .Alerts }}{{ .Annotations.summary }} <{{ .Annotations.runbook_url }}|runbook>
          {{ end }}
    # RECEIVERS_WARNING_EXTRA
  - name: webhook-triage
    # Reserved: point TRIAGE_WEBHOOK_URL at an AI triage service to receive a copy of every critical alert.
    webhook_configs:
      - url: ${TRIAGE_WEBHOOK_URL}
        send_resolved: false
