package lib.utils

bucket_name_contains(bucket, query) {
	contains(bucket.bucket, "bucket")
}

bucket_name_contains(bucket, query) {
	contains(bucket.bucket_prefix, "bucket")
}
