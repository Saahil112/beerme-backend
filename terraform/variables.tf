variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "region" {
  type        = string
  description = "Region for Cloud Function and services"
  default     = "us-east1"
}

variable "dataset_id" {
  type        = string
  description = "BigQuery dataset ID"
  default     = "innerbeer"
}

variable "function_name" {
  type        = string
  description = "Cloud Function name"
  default     = "beer-recommender"
}

variable "function_runtime" {
  type        = string
  description = "Cloud Function runtime"
  default     = "python310"
}

variable "service_account_id" {
  type        = string
  description = "Service account ID (short name)"
  default     = "innerbeer-sa"
}
