provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "services" {
  for_each = toset([
    "bigquery.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com"
  ])
  project = var.project_id
  service = each.key
  disable_on_destroy = false
}

# Shared storage bucket for all function sources
resource "google_storage_bucket" "function_source" {
  name                        = "innerbeer-function-source-${var.project_id}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
}

# Reference JWT secret from Secret Manager
data "google_secret_manager_secret_version" "jwt_secret" {
  secret  = "jwt_secret"
  project = var.project_id
}

# OAuth client credentials
data "google_secret_manager_secret_version" "oauth_client_id" {
  secret  = "oauth_client_id"
  project = var.project_id
}

data "google_secret_manager_secret_version" "oauth_client_secret" {
  secret  = "oauth_client_secret"
  project = var.project_id
}

module "bigquery" {
  source = "./bigquery"
  project_id = var.project_id
  dataset_id = var.dataset_id
}

module "iam" {
  source = "./iam"
  project_id = var.project_id
  service_account_id = var.service_account_id
}

module "cloud_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = var.function_name
  runtime               = var.function_runtime
  service_account_email = module.iam.service_account_email
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "fetch_recommendations"
  source_main_py        = "fetch_recommendations.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET = data.google_secret_manager_secret_version.jwt_secret.secret_data
  }
  depends_on = [google_project_service.services, module.bigquery, module.iam]
}

module "source_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "fetch-source"
  runtime               = var.function_runtime
  service_account_email = module.iam.service_account_email
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "fetch_source"
  source_main_py        = "fetch_source.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET = data.google_secret_manager_secret_version.jwt_secret.secret_data
  }
  depends_on = [google_project_service.services, module.bigquery, module.iam]
}

module "search_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "search-beer"
  runtime               = var.function_runtime
  service_account_email = module.iam.service_account_email
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "search_beer"
  source_main_py        = "search_beer.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET = data.google_secret_manager_secret_version.jwt_secret.secret_data
  }
  depends_on = [google_project_service.services, module.bigquery, module.iam]
}

module "beer_likes_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "beer-likes"
  runtime               = var.function_runtime
  service_account_email = "innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "beer_likes"
  source_main_py        = "beer_likes.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET = data.google_secret_manager_secret_version.jwt_secret.secret_data
  }
  depends_on = [google_project_service.services, module.bigquery]
}

module "get_beer_like_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "get-beer-like"
  runtime               = var.function_runtime
  service_account_email = "innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "get_beer_like"
  source_main_py        = "get_beer_like.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET = data.google_secret_manager_secret_version.jwt_secret.secret_data
  }
  depends_on = [google_project_service.services, module.bigquery]
}

module "auth_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "auth-issue-token"
  runtime               = var.function_runtime
  service_account_email = module.iam.service_account_email
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "auth_issue_token"
  source_main_py        = "auth_issue_token.py"
  entry_point           = "main"
  extra_env = {
    JWT_SECRET        = data.google_secret_manager_secret_version.jwt_secret.secret_data
    TOKEN_TTL_SECONDS = "3600"
    USER_CREDENTIALS  = jsonencode({
      "demo@example.com" = "changeme123"
    })
  }
  depends_on = [google_project_service.services, module.iam]
}

module "oauth_login_function" {
  source                = "./cloud_functions"
  project_id            = var.project_id
  region                = var.region
  function_name         = "oauth-login"
  runtime               = var.function_runtime
  service_account_email = "innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
  dataset_id            = var.dataset_id
  bucket_name           = google_storage_bucket.function_source.name
  source_dir            = "oauth_login"
  source_main_py        = "oauth_login.py"
  entry_point           = "main"
  extra_env = {
    OAUTH_CLIENT_ID     = data.google_secret_manager_secret_version.oauth_client_id.secret_data
    OAUTH_CLIENT_SECRET = data.google_secret_manager_secret_version.oauth_client_secret.secret_data
    PROJECT_ID          = var.project_id
    DATASET_ID          = var.dataset_id
  }
  depends_on = [google_project_service.services, module.bigquery]
}

# Grant table-level write on users to writer SA
resource "google_bigquery_table_iam_member" "users_writer" {
  project    = var.project_id
  dataset_id = var.dataset_id
  table_id   = "users"
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
}

# Secret Manager access for the writer SA
resource "google_project_iam_member" "writer_sa_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
}

# Allow writer SA to run BigQuery jobs
resource "google_project_iam_member" "writer_sa_bq_jobuser" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
}

# Grant dataset-level edit access for writes/merges
resource "google_bigquery_dataset_iam_member" "writer_sa_dataset_editor" {
  project    = var.project_id
  dataset_id = var.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:innerbeer-writer-sa@brewquest-analytics.iam.gserviceaccount.com"
}

# Ensure the function's service account can read the dataset
resource "google_bigquery_dataset_iam_member" "function_dataset_viewer" {
  project    = var.project_id
  dataset_id = "dbt_saahil"
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${module.iam.service_account_email}"
}
