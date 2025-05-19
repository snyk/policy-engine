package examples.main

mock_input := {
	"format": "",
	"format_version": "",
	"input_type": "tf",
	"environment_provider": "iac",
	"meta": {"filepath": "examples/main.tf"},
	"resources": {
		"aws_cloudtrail": {"aws_cloudtrail.cloudtrail1": {
			"id": "aws_cloudtrail.cloudtrail1",
			"resource_type": "aws_cloudtrail",
			"namespace": "examples/main.tf",
			"attributes": {
				"_filepath": "examples/main.tf",
				"_provider": "aws",
				"_tags": {},
				"_type": "aws_cloudtrail",
				"id": "aws_cloudtrail.cloudtrail1",
				"include_global_service_events": true,
				"name": "cloudtrail1",
				"s3_bucket_name": "aws_s3_bucket.bucket1",
				"s3_key_prefix": "prefix",
			},
		}},
		"aws_kms_key": {"aws_kms_key.key": {
			"id": "aws_kms_key.key",
			"resource_type": "aws_kms_key",
			"namespace": "examples/main.tf",
			"attributes": {
				"_filepath": "examples/main.tf",
				"_provider": "aws",
				"_tags": {},
				"_type": "aws_kms_key",
				"deletion_window_in_days": 10,
				"description": "This key is used to encrypt bucket objects",
				"id": "aws_kms_key.key",
			},
		}},
		"aws_s3_bucket": {
			"aws_s3_bucket.bucket1": {
				"id": "aws_s3_bucket.bucket1",
				"resource_type": "aws_s3_bucket",
				"namespace": "examples/main.tf",
				"attributes": {
					"_filepath": "examples/main.tf",
					"_provider": "aws",
					"_tags": {},
					"_type": "aws_s3_bucket",
					"bucket": "dumb-bucket",
					"id": "aws_s3_bucket.bucket1",
				},
			},
			"aws_s3_bucket.bucket2": {
				"id": "aws_s3_bucket.bucket2",
				"resource_type": "aws_s3_bucket",
				"namespace": "examples/main.tf",
				"attributes": {
					"_filepath": "examples/main.tf",
					"_provider": "aws",
					"_tags": {},
					"_type": "aws_s3_bucket",
					"bucket": "dumb",
					"id": "aws_s3_bucket.bucket2",
				},
			},
			"aws_s3_bucket.bucket3": {
				"id": "aws_s3_bucket.bucket3",
				"resource_type": "aws_s3_bucket",
				"namespace": "examples/main.tf",
				"attributes": {
					"_filepath": "examples/main.tf",
					"_provider": "aws",
					"_tags": {},
					"_type": "aws_s3_bucket",
					"bucket": "bucket3",
					"id": "aws_s3_bucket.bucket3",
					"server_side_encryption_configuration": [{"rule": [{"apply_server_side_encryption_by_default": [{
						"kms_master_key_id": "aws_kms_key.key",
						"sse_algorithm": "aws:kms",
					}]}]}],
				},
			},
		},
		"aws_s3_bucket_server_side_encryption_configuration": {"aws_s3_bucket_server_side_encryption_configuration.bucket2": {
			"id": "aws_s3_bucket_server_side_encryption_configuration.bucket2",
			"resource_type": "aws_s3_bucket_server_side_encryption_configuration",
			"namespace": "examples/main.tf",
			"attributes": {
				"_filepath": "examples/main.tf",
				"_provider": "aws",
				"_tags": {},
				"_type": "aws_s3_bucket_server_side_encryption_configuration",
				"bucket": "dumb",
				"id": "aws_s3_bucket_server_side_encryption_configuration.bucket2",
				"rule": [{"apply_server_side_encryption_by_default": [{
					"kms_master_key_id": "aws_kms_key.key",
					"sse_algorithm": "aws:kms",
				}]}],
			},
		}},
		"kubernetes_pod": {"kubernetes_pod.multiple_containers": {
			"id": "kubernetes_pod.multiple_containers",
			"resource_type": "kubernetes_pod",
			"namespace": "examples/main.tf",
			"attributes": {
				"_filepath": "examples/main.tf",
				"_provider": "kubernetes",
				"_tags": {},
				"_type": "kubernetes_pod",
				"id": "kubernetes_pod.multiple_containers",
				"metadata": [{"name": "multiple-containers"}],
				"spec": [{
					"container": [
						{
							"env": [{
								"name": "environment",
								"value": "test",
							}],
							"image": "nginx:1.7.9",
							"name": "example-allowed",
						},
						{
							"env": [{
								"name": "environment",
								"value": "test",
							}],
							"image": "nginx:1.7.9",
							"name": "example-denied",
							"security_context": [{"privileged": true}],
						},
						{
							"env": [{
								"name": "environment",
								"value": "test",
							}],
							"image": "nginx:1.7.9",
							"name": "example-denied-2",
							"security_context": [{"privileged": true}],
						},
					],
					"init_container": [{
						"args": [
							"-c",
							"exit",
							"0",
						],
						"command": ["/bin/sh"],
						"env": [{
							"name": "environment",
							"value": "test",
						}],
						"image": "nginx:1.7.9",
						"name": "example-denied-init",
						"security_context": [{"privileged": true}],
					}],
				}],
			},
		}},
	},
}
