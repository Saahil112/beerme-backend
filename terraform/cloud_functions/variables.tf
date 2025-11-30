variable "project_id" { type = string }
variable "region" { type = string }
variable "function_name" { type = string }
variable "runtime" { type = string }
variable "service_account_email" { type = string }
variable "dataset_id" { type = string }
variable "bucket_name" { type = string }

# Decouple deploy name from source layout
variable "source_dir" {
  type        = string
  description = "Directory under this module containing the Cloud Function source"
}

variable "source_main_py" {
  type        = string
  description = "Python file to rename to main.py during staging (relative to source_dir)"
}

variable "entry_point" {
  type        = string
  description = "Cloud Function entry point (python function name)"
  default     = "main"
}

variable "extra_env" {
  type        = map(string)
  description = "Additional environment variables to inject into the function"
  default     = {}
}
