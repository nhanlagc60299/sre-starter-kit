auth_enabled: false
server:
  http_listen_port: 3100
common:
  path_prefix: /loki
  storage: { filesystem: { chunks_directory: /loki/chunks, rules_directory: /loki/rules-tmp } }
  replication_factor: 1
  ring: { kvstore: { store: inmemory } }
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index: { prefix: index_, period: 24h }
limits_config:
  retention_period: ${LOKI_RETENTION_PERIOD}
  ingestion_rate_mb: 8
  ingestion_burst_size_mb: 16
  max_query_series: 5000
compactor:
  working_directory: /loki/compactor
  retention_enabled: true
  delete_request_store: filesystem
ruler:
  storage: { type: local, local: { directory: /etc/loki/rules } }
  rule_path: /loki/rules-tmp
  alertmanager_url: http://alertmanager:9093
  enable_api: true
