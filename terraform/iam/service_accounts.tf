variable "project_id" { type = string }
variable "service_account_id" { type = string }

resource "google_service_account" "innerbeer" {
  account_id   = var.service_account_id
  display_name = "InnerBeer Service Account"
}

# Assign roles
resource "google_project_iam_member" "sa_bigquery_user" {
  project = var.project_id
  role    = "roles/bigquery.user"
  member  = "serviceAccount:${google_service_account.innerbeer.email}"
}

resource "google_project_iam_member" "sa_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.innerbeer.email}"
}

resource "google_project_iam_member" "sa_cf_invoker" {
  project = var.project_id
  role    = "roles/cloudfunctions.invoker"
  member  = "serviceAccount:${google_service_account.innerbeer.email}"
}

resource "google_project_iam_member" "sa_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.innerbeer.email}"
}

output "service_account_email" {
  value = google_service_account.innerbeer.email
}
