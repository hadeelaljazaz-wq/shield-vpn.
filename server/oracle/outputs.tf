locals {
  enrollment = {
    v    = 1
    api  = "https://${oci_core_instance.gw.public_ip}:8443"
    ip   = oci_core_instance.gw.public_ip
    tok  = random_password.enroll_token.result
    pin  = sha256(tls_self_signed_cert.api.cert_pem)
    name = var.server_name
  }
}

output "server_ip" {
  value = oci_core_instance.gw.public_ip
}

output "enrollment_code" {
  description = "Copy this once into the app (Servers → Add server). Treat it like a password."
  value       = "SHIELD1:${base64encode(jsonencode(local.enrollment))}"
  sensitive   = true
}

output "next_step" {
  value = "Wait ~4 minutes for the server to finish installing, then open the Outputs tab, reveal enrollment_code, copy it and paste it into the app."
}
