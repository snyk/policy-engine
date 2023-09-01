variable "app" {
	type = string
}

variable "tags_1" {
	type = map
}

variable "tags_2" {
	type = map
	default = {"foo": "bar"}
}

resource "aws_s3_bucket" "main" {
	bucket_prefix = "store-${var.app}"
	tags          = merge(var.tags_1, var.tags_2)
}
