# Copyright 2022-2023 Snyk Ltd
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

resource "kubernetes_pod" "multiple_containers" {
  metadata {
    name = "multiple-containers"
  }

  spec {
    init_container {
      image   = "nginx:1.7.9"
      name    = "example-denied-init"
      command = ["/bin/sh"]
      args    = ["-c", "exit", "0"]

      env {
        name  = "environment"
        value = "test"
      }
      security_context {
        privileged = true
      }
    }

    container {
      image = "nginx:1.7.9"
      name  = "example-allowed"

      env {
        name  = "environment"
        value = "test"
      }
    }

    container {
      image = "nginx:1.7.9"
      name  = "example-denied"

      env {
        name  = "environment"
        value = "test"
      }

      security_context {
        privileged = true
      }
    }

    container {
      image = "nginx:1.7.9"
      name  = "example-denied-2"

      env {
        name  = "environment"
        value = "test"
      }

      security_context {
        privileged = true
      }
    }
  }
}
