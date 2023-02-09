package rules.EXAMPLE_01.terraform

import data.lib.utils
import data.snyk

input_type := "tf"

resource_type := "MULTIPLE"

metadata := data.rules.EXAMPLE_01.metadata

buckets := snyk.resources("aws_s3_bucket")

deny[info] {
	bucket := buckets[_]
	utils.bucket_name_contains(bucket, "bucket")
	info := {"resource": bucket}
}

resources[info] {
	bucket := buckets[_]
	info := {"resource": bucket}
}
