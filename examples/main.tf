provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "bucket1" {
  bucket = "dumb-bucket"
}

resource "aws_s3_bucket" "bucket2" {
  bucket = "dumb"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket2" {
  bucket = aws_s3_bucket.bucket2.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket2" {
  bucket = aws_s3_bucket.bucket2.bucket

  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_kms_key" "key" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "bucket3" {
  bucket = "bucket3"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.key.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket3" {
  bucket = aws_s3_bucket.bucket3.bucket

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket" "aes_bucket" {
  bucket = "i-use-aes-encryption"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aes_bucket" {
  bucket = aws_s3_bucket.aes_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_cloudtrail" "cloudtrail1" {
  name                          = "cloudtrail1"
  s3_bucket_name                = aws_s3_bucket.bucket1.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
}

resource "kubernetes_pod" "multiple_containers" {
  metadata {
    name = "multiple-containers"
    labels = {
      app = "myapp-1"
    }
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


resource "kubernetes_service_v1" "service" {
  metadata {
    name = "myapp-1"
  }
  spec {
    selector = {
      app = kubernetes_pod.multiple_containers.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "NodePort"
  }
}

resource "kubernetes_ingress" "ingress" {
  metadata {
    name = "example-ingress"
  }

  spec {
    backend {
      service_name = kubernetes_service_v1.service.metadata.0.name
      service_port = 8080
    }

    rule {
      http {
        path {
          backend {
            service_name = kubernetes_service_v1.service.metadata.0.name
            service_port = 8080
          }

          path = "/app1/*"
        }
      }
    }

    tls {
      secret_name = "tls-secret"
    }
  }
}
