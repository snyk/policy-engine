package snyk_test

import data.snyk

check_relations {
	bucket_1 := snyk.resources("bucket")[_]
	bucket_1.id == "bucket_1"
	rels := snyk.relates(bucket_1, "bucket_settings")
	count(rels) == 1
}

test_relations {
	check_relations with input as {
		"snyk_relations_test": true,
		"resources": {
			"bucket": {"bucket_1": {
				"id": "bucket_1",
				"type": "bucket",
				"namespace": "ns",
				"attributes": {},
			}},
			"bucket_settings": {"bucket_settings_1": {
				"id": "bucket_settings_1",
				"type": "bucket_settings",
				"namespace": "ns",
				"attributes": {"bucket": "bucket_1"},
			}},
		},
	}
}
