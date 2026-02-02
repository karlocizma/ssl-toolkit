output "kubeconfig" {
  value = data.local_file.kubeconfig.content
}

output "client_certificate" {
  value = base64decode(yamldecode(data.local_file.kubeconfig.content)["users"][0]["user"]["client-certificate-data"])
}

output "client_key" {
  value = base64decode(yamldecode(data.local_file.kubeconfig.content)["users"][0]["user"]["client-key-data"])
}

output "cluster_ca_certificate" {
  value = base64decode(yamldecode(data.local_file.kubeconfig.content)["clusters"][0]["cluster"]["certificate-authority-data"])
}
