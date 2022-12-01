package snyk_test

import data.snyk

check_relations {
	bucket_1 := snyk.resources("bucket")[_]
	bucket_1.id == "bucket_1"

	settings := snyk.relates(bucket_1, "bucket_settings")
	count(settings) == 1

	logging := snyk.relates(bucket_1, "bucket_logging")
	count(logging) == 1
}

test_relations {
	# See also `rego/snyk/internal/relations_example.rego` for the relations
	# definition.
	check_relations with input as mock_input_relations
}

mock_input_relations := ret {
	num_buckets := 2000
	num_bucket_settings := 2000  # Keyed and fast
	num_bucket_logging := 100  # Explicit and slow

	buckets := {id: r |
		i := numbers.range(1, num_buckets)[_]
		id := sprintf("bucket_%d", [i])
		r := {
			"id": id,
			"type": "bucket",
			"namespace": "ns",
			"attributes": {},
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

	ret := {
		"snyk_relations_test": true,
		"resources": {
			"bucket": buckets,
			"bucket_settings": bucket_settings,
			"bucket_logging": bucket_logging,
		},
	}
}