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
