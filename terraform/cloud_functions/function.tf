locals {
  src_dir        = "${path.module}/${var.source_dir}"
  staging_dir    = "${path.module}/.staging/${var.function_name}"
  staged_main_py = "${local.staging_dir}/main.py"
  zip_path       = "${path.module}/${var.function_name}.zip"
  build_version  = timestamp()
}

# Stage source: copy folder ${function_name}/ and rename <function_name>.py -> main.py
resource "null_resource" "stage_source" {
  triggers = {
    function_name = var.function_name
    src_mtime     = timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      mkdir -p "${local.staging_dir}"
      rsync -a --delete "${local.src_dir}/" "${local.staging_dir}/"
      if [ -f "${local.staging_dir}/${var.source_main_py}" ]; then
        mv "${local.staging_dir}/${var.source_main_py}" "${local.staged_main_py}"
      fi
    EOT
    interpreter = ["/bin/sh","-c"]
  }
}

data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = local.staging_dir
  output_path = local.zip_path
  depends_on  = [null_resource.stage_source]
}

resource "google_storage_bucket_object" "source_zip" {
  name   = "${var.function_name}.zip"
  bucket = var.bucket_name
  source = data.archive_file.function_zip.output_path
  content_type = "application/zip"
}

resource "google_cloudfunctions_function" "function" {
  name                  = var.function_name
  description           = "InnerBeer function: ${var.function_name} [${data.archive_file.function_zip.output_sha256}]"
  runtime               = var.runtime
  region                = var.region
  project               = var.project_id
  available_memory_mb   = 256
  service_account_email = var.service_account_email
  entry_point           = var.entry_point
  trigger_http          = true
  source_archive_bucket = var.bucket_name
  source_archive_object = google_storage_bucket_object.source_zip.name
  timeout               = 60
  environment_variables = merge({
    DATASET_ID    = "dbt_saahil"
    PROJECT_ID    = var.project_id
    BUILD_VERSION = local.build_version
  }, var.extra_env)
}

# Allow unauthenticated invocation (left enabled for app-level JWT auth)
resource "google_cloudfunctions_function_iam_member" "public_invoker" {
  project        = var.project_id
  region         = var.region
  cloud_function = google_cloudfunctions_function.function.name
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}

output "function_url" {
  value = google_cloudfunctions_function.function.https_trigger_url
}
