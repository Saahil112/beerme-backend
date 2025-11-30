data "google_bigquery_dataset" "dataset" {
  project    = var.project_id
  dataset_id = var.dataset_id
}

output "dataset_id" {
  value = data.google_bigquery_dataset.dataset.dataset_id
}
