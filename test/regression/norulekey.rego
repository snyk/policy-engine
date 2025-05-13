package rules.norulekey

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

bucket_name_contains(bucket, needle) if {
	is_string(bucket.bucket)
	contains(bucket.bucket, needle)
}

bucket_name_contains(bucket, needle) if {
	is_string(bucket.bucket_prefix)
	contains(bucket.bucket_prefix, needle)
}

make_deny(needle) := ret if {
	ret := {info |
		bucket := buckets[_]
		bucket_name_contains(bucket, needle)
		info := {
			"message": sprintf("Bucket names should not contain %s", [needle]),
			"resource": bucket,
		}
	}
}

deny := make_deny("bucket")
