global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    project: ${PROJECT_NAME}

rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

scrape_configs:
  - job_name: prometheus
    static_configs: [{ targets: ['localhost:9090'] }]
  - job_name: alertmanager
    static_configs: [{ targets: ['alertmanager:9093'] }]
  - job_name: loki
    static_configs: [{ targets: ['loki:3100'] }]
  - job_name: alloy
    static_configs: [{ targets: ['alloy:12345'] }]
  # node-exporter runs in the host network namespace and so has no compose-network DNS name.
  # NODE_EXPORTER_TARGET is how Prometheus reaches it; the default works on Docker via the
  # host-gateway alias in compose/docker-compose.yml. See README "Exposure".
  - job_name: node
    static_configs: [{ targets: ['${NODE_EXPORTER_TARGET}'] }]
  - job_name: cadvisor
    static_configs: [{ targets: ['cadvisor:8080'] }]
  # The exporter's OWN /metrics, which exists whether or not SERVICES lists anything.
  # BlackboxExporterDown reads this job, not blackbox-http: blackbox-http has one `up` series
  # per probe target, so with SERVICES empty -- the shipped default -- it has none at all and
  # an alert on it can never fire.
  - job_name: blackbox
    static_configs: [{ targets: ['blackbox:9115'] }]
  - job_name: blackbox-http
    metrics_path: /probe
    params: { module: [http_2xx] }
    file_sd_configs:
      - files: ['/etc/prometheus/targets/services.json']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox:9115
