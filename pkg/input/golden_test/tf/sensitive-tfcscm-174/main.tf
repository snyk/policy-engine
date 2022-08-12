terraform {
  # define providers
  required_providers {
    circleci = {
      source  = "mrolla/circleci"
      version = "0.5.1"
    }
  }
}

resource "circleci_environment_variable" "admin_website_dev" {
  name    = "ADMIN_SERVICE_TOKEN_DEV"
  value   = sensitive("test")
  project = "project1"
}
