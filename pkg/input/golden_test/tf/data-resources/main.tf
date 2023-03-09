# © 2022-2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

provider "google" {}

resource "google_storage_bucket" "all_users" {
  name          = "invalid-public-all-users-iam"
  force_destroy = true
}

data "google_iam_policy" "all_users" {
  binding {
    role = "roles/storage.admin"
    members = [
      "user:jason@fugue.co"
    ]
  }

  binding {
    role = "roles/storage.objectViewer"
    members = [
      "allUsers"
    ]
  }
}

resource "google_storage_bucket_iam_policy" "all_users_policy" {
  bucket      = google_storage_bucket.all_users.name
  policy_data = data.google_iam_policy.all_users.policy_data
}

resource "google_storage_bucket" "all_authenticated_users" {
  name          = "invalid-public-all-authenticated-iam"
  force_destroy = true
}

data "google_iam_policy" "all_authenticated_users" {
  binding {
    role = "roles/storage.admin"
    members = [
      "user:jason@fugue.co"
    ]
  }

  binding {
    role = "roles/storage.objectViewer"
    members = [
      "allAuthenticatedUsers"
    ]
  }
}

resource "google_storage_bucket_iam_policy" "all_authenticated_users_policy" {
  bucket      = google_storage_bucket.all_authenticated_users.name
  policy_data = data.google_iam_policy.all_authenticated_users.policy_data
}
