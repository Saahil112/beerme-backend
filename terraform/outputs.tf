output "function_url" {
  value = module.cloud_function.function_url
}

output "auth_function_url" {
  value = module.auth_function.function_url
}

output "service_account_email" {
  value = module.iam.service_account_email
}

output "dataset_id" {
  value = module.bigquery.dataset_id
}
