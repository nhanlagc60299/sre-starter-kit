// Grafana Alloy: ship docker container logs + host auth log to Loki.

loki.write "default" {
  endpoint { url = "http://loki:3100/loki/api/v1/push" }
  external_labels = { project = "${PROJECT_NAME}" }
}

// --- Docker container logs ---
discovery.docker "containers" {
  host = "unix:///var/run/docker.sock"
}
discovery.relabel "containers" {
  targets = discovery.docker.containers.targets
  rule {
    source_labels = ["__meta_docker_container_name"]
    regex         = "/?(.*)"
    target_label  = "container"
  }
  rule {
    source_labels = ["__meta_docker_container_label_com_docker_compose_service"]
    target_label  = "service"
  }
}
loki.source.docker "containers" {
  host       = "unix:///var/run/docker.sock"
  targets    = discovery.relabel.containers.output
  forward_to = [loki.write.default.receiver]
}

// --- Host auth log (security module) ---
local.file_match "authlog" {
  path_targets = [{ __path__ = "${AUTH_LOG_PATH}", job = "authlog" }]
}
loki.source.file "authlog" {
  targets    = local.file_match.authlog.targets
  forward_to = [loki.write.default.receiver]
}
