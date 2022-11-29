package relations

import data.snyk

# Relations for unit tests.
relations[info] {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "bucket_settings",
		"keys": {
			"left": [[b, b.id] | b := snyk.resources("bucket")[_]],
			"right": [[l, l.bucket] | l := snyk.resources("bucket_settings")[_]],
		},
	}
}
