package snyk_test

import data.snyk
import future.keywords.every

check_relations {
	bucket_1 := snyk.resources("bucket")[_]
	bucket_1.id == "bucket_1"

	settings_1 := snyk.relates(bucket_1, "bucket_settings")
	count(settings_1) == 1

	settings_1_bucket := snyk.back_relates("bucket_settings", settings_1[_])
	count(settings_1_bucket) == 1
	settings_1_bucket[_] == bucket_1

	logging_1 := snyk.relates(bucket_1, "bucket_logging")
	count(logging_1) == 1

	logging_1_bucket := snyk.back_relates("bucket_logging", logging_1[_])
	count(logging_1_bucket) == 1
	logging_1_bucket[_] == bucket_1

	every _, acl in snyk.resources("bucket_acl") {
		acl_bucket := snyk.back_relates("bucket_acl", acl)
		count(acl_bucket) == 1

		acl_bucket_acl := snyk.relates(acl_bucket[_], "bucket_acl")
		count(acl_bucket_acl) == 1
		acl_bucket_acl[_] == acl
	}
}

test_relations {
	# See also `rego/snyk/internal/relations_example.rego` for the relations
	# definition.
	check_relations with input as mock_input_relations
}

mock_input_relations := ret {
	num_buckets := 1000
	num_bucket_settings := 1000 # Keyed and fast
	num_bucket_logging := 10 # Explicit and slow
	num_bucket_acl := 10

	buckets := {id: r |
		i := numbers.range(1, num_buckets)[_]
		id := sprintf("bucket_%d", [i])
		r := {
			"id": id,
			"type": "bucket",
			"namespace": "ns",
			"attributes": {"bucket": sprintf("bucket_%d_name", [i])},
		}
	}

	bucket_settings := {id: r |
		i := numbers.range(1, num_bucket_settings)[_]
		id := sprintf("bucket_settings_%d", [i])
		r := {
			"id": id,
			"type": "bucket_settings",
			"namespace": "ns",
			"attributes": {"bucket": sprintf("bucket_%d", [i])},
		}
	}

	bucket_logging := {id: r |
		i := numbers.range(1, num_bucket_logging)[_]
		id := sprintf("bucket_logging_%d", [i])
		r := {
			"id": id,
			"type": "bucket_logging",
			"namespace": "ns",
			"attributes": {"bucket": sprintf("bucket_%d", [i])},
		}
	}

	bucket_acl := {id: r |
		i := numbers.range(1, num_bucket_acl)[_]
		id := sprintf("bucket_acl_%d", [i])
		ref := [
			sprintf("bucket_%d", [i]),
			sprintf("bucket_%d_name", [i]),
		][i % 2]
		r := {
			"id": id,
			"type": "bucket_acl",
			"namespace": "ns",
			"attributes": {"bucket": ref},
		}
	}

	ret := {
		"snyk_relations_test": true,
		"resources": {
			"bucket": buckets,
			"bucket_settings": bucket_settings,
			"bucket_logging": bucket_logging,
			"bucket_acl": bucket_acl,
		},
	}
}
