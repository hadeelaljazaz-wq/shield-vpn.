# Smart Ad Shield VPN — Oracle Cloud "Always Free" gateway.
# Deploy with Oracle Resource Manager (one click from the README button),
# then press "Apply". Output `enrollment_code` is pasted once into the app.

terraform {
  required_version = ">= 1.2"
  required_providers {
    oci    = { source = "oracle/oci" }
    tls    = { source = "hashicorp/tls" }
    random = { source = "hashicorp/random" }
  }
}

provider "oci" {
  region = var.region
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

locals {
  compartment = var.compartment_ocid != "" ? var.compartment_ocid : var.tenancy_ocid
  ad_name     = data.oci_identity_availability_domains.ads.availability_domains[min(var.availability_domain_number, length(data.oci_identity_availability_domains.ads.availability_domains)) - 1].name
  is_flex     = length(regexall("Flex$", var.instance_shape)) > 0
}

data "oci_core_images" "ubuntu" {
  compartment_id           = local.compartment
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

# ---------------- secrets generated inside Oracle (never in git) -------------
resource "random_password" "enroll_token" {
  length  = 48
  special = false
}

resource "tls_private_key" "api" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "api" {
  private_key_pem       = tls_private_key.api.private_key_pem
  validity_period_hours = 87600
  allowed_uses          = ["server_auth", "digital_signature", "key_encipherment"]
  subject {
    common_name = "shieldvpn"
  }
}

# ---------------- network ----------------
resource "oci_core_vcn" "vpn" {
  compartment_id = local.compartment
  cidr_blocks    = ["10.42.0.0/16"]
  display_name   = "shieldvpn-vcn"
  dns_label      = "shieldvpn"
  is_ipv6enabled = false
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = local.compartment
  vcn_id         = oci_core_vcn.vpn.id
  display_name   = "shieldvpn-igw"
}

resource "oci_core_route_table" "rt" {
  compartment_id = local.compartment
  vcn_id         = oci_core_vcn.vpn.id
  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.igw.id
  }
}

resource "oci_core_security_list" "sl" {
  compartment_id = local.compartment
  vcn_id         = oci_core_vcn.vpn.id
  display_name   = "shieldvpn-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }
  ingress_security_rules { # WireGuard
    protocol = "17"
    source   = "0.0.0.0/0"
    udp_options {
      min = var.wg_port
      max = var.wg_port
    }
  }
  ingress_security_rules { # Xray VLESS-REALITY
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }
  ingress_security_rules { # provisioning API
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 8443
      max = 8443
    }
  }
  dynamic "ingress_security_rules" {
    for_each = var.ssh_public_key != "" ? [1] : []
    content {
      protocol = "6"
      source   = "0.0.0.0/0"
      tcp_options {
        min = 22
        max = 22
      }
    }
  }
  ingress_security_rules { # path-MTU discovery
    protocol = "1"
    source   = "0.0.0.0/0"
    icmp_options {
      type = 3
      code = 4
    }
  }
}

resource "oci_core_subnet" "pub" {
  compartment_id    = local.compartment
  vcn_id            = oci_core_vcn.vpn.id
  cidr_block        = "10.42.1.0/24"
  display_name      = "shieldvpn-subnet"
  dns_label         = "pub"
  route_table_id    = oci_core_route_table.rt.id
  security_list_ids = [oci_core_security_list.sl.id]
}

# ---------------- instance ----------------
resource "oci_core_instance" "gw" {
  compartment_id      = local.compartment
  availability_domain = local.ad_name
  display_name        = "shieldvpn-gateway"
  shape               = var.instance_shape

  dynamic "shape_config" {
    for_each = local.is_flex ? [1] : []
    content {
      ocpus         = var.ocpus
      memory_in_gbs = var.memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.pub.id
    assign_public_ip = true
  }

  metadata = merge(
    {
      user_data = base64gzip(templatefile("${path.module}/cloud-init.sh.tftpl", {
        token        = random_password.enroll_token.result
        cert_b64     = base64encode(tls_self_signed_cert.api.cert_pem)
        key_b64      = base64encode(tls_private_key.api.private_key_pem)
        install_b64  = base64encode(file("${path.module}/install.sh"))
        provision_b64 = base64encode(file("${path.module}/provision.py"))
        server_name  = var.server_name
        country_code = var.country_code
        wg_port      = var.wg_port
      }))
    },
    var.ssh_public_key != "" ? { ssh_authorized_keys = var.ssh_public_key } : {}
  )

  lifecycle {
    ignore_changes = [source_details[0].source_id]
  }
}
