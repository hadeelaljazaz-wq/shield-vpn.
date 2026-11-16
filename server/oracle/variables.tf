variable "tenancy_ocid" { type = string }
variable "region" { type = string }
variable "compartment_ocid" {
  type    = string
  default = ""
}
variable "instance_shape" {
  description = "VM.Standard.A1.Flex (Arm, Always Free) or VM.Standard.E2.1.Micro (AMD, Always Free) if Arm capacity is unavailable."
  type        = string
  default     = "VM.Standard.A1.Flex"
}
variable "ocpus" {
  type    = number
  default = 1
}
variable "memory_gb" {
  type    = number
  default = 6
}
variable "availability_domain_number" {
  type    = number
  default = 1
}
variable "server_name" {
  type    = string
  default = "Oracle Cloud"
}
variable "country_code" {
  description = "ISO code shown in the app; the app replaces it with the country measured from the real exit IP."
  type        = string
  default     = ""
}
variable "wg_port" {
  type    = number
  default = 51820
}
variable "ssh_public_key" {
  description = "Optional. Leave empty to keep SSH closed."
  type        = string
  default     = ""
}
