variable "region" {
  description = "Región de AWS"
  type        = string
  default     = "us-east-1"
}

variable "email" {
  description = "Email que recibe las alertas"
  type        = string
  sensitive   = true
}

variable "prefijo_remediacion" {
  description = "La Lambda solo corrige buckets cuyo nombre empiece con este prefijo"
  type        = string
  default     = "prueba-seguridad-"
}