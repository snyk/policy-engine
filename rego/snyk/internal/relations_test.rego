# © 2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package snyk_test

import data.snyk

check_relations if {
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

	# Check that we return empty arrays when appropriate.
	non_existing_relation := snyk.relates(bucket_1, "bucket_foobar")
	is_array(non_existing_relation)
	count(non_existing_relation) == 0
}

check_annotated_relations if {
	sg1 := snyk.resources("security_group")[_]
	out := snyk.relates_with(sg1, "security_group")[_]

	[sg1_egress, sg1_egress_ann] := snyk.relates_with(sg1, "security_group")[_]
	sg1_egress.id == "security_group_2"
	sg1_egress_ann.type == "egress"
	sg1_egress_ann.port == 1

	[back_to_sg1, back_to_sg1_ann] := snyk.back_relates_with("security_group", sg1_egress)[_]
	back_to_sg1 == sg1
	back_to_sg1_ann.type == "egress"
	back_to_sg1_ann.port == 1

	[sg1_ingress, sg1_ingress_ann] := snyk.relates_with(sg1, "security_group")[_]
	sg1_ingress.id == "security_group_1000"
	sg1_ingress_ann.type == "ingress"
	sg1_ingress_ann.port == 1

	lb := snyk.resources("load_balancer")[_]
	[app, app_ann] := snyk.relates_with(lb, "forwards_to")[_]
	app_ann.port == 80
	app.id == "application_1"
}

test_relations if {
	# See also `rego/snyk/internal/relations_example.rego` for the relations
	# definition.
	check_relations with input as mock_input_relations
}

test_annotated_relations if {
	check_annotated_relations with input as mock_input_annotated_relations
}

mock_input_relations := ret if {
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

mock_input_annotated_relations := ret if {
	num_security_group := 1000

	security_group := {id: r |
		i := numbers.range(1, num_security_group)[_]
		id := sprintf("security_group_%d", [i])
		prev := sprintf("security_group_%d", [ring_prev(i, num_security_group)])
		next := sprintf("security_group_%d", [ring_next(i, num_security_group)])
		r := {
			"id": id,
			"type": "security_group",
			"namespace": "ns",
			"attributes": {
				"ingress": [{
					"port": i,
					"security_group_id": prev,
				}],
				"egress": [{
					"port": i,
					"security_group_id": next,
				}],
			},
		}
	}

	load_balancer := {"my_loadbalancer": {
		"id": "load_balancer",
		"type": "load_balancer",
		"namespace": "ns",
		"attributes": {"forward": [
			{
				"port": 80,
				"application": "application_1",
			},
			{
				"port": 443,
				"application": "application_2",
			},
		]},
	}}

	application := {
		"application_1": {
			"id": "application_1",
			"type": "application",
			"namespace": "ns",
			"attributes": {},
		},
		"application_2": {
			"id": "application_2",
			"type": "application",
			"namespace": "ns",
			"attributes": {},
		},
	}

	ret := {
		"snyk_relations_test": true,
		"resources": {
			"security_group": security_group,
			"load_balancer": load_balancer,
			"application": application,
		},
	}
}

ring_next(x, n) := ret if {
	x >= n
	ret := 1
} else := ret if {
	ret := x + 1
}

ring_prev(x, n) := ret if {
	x <= 1
	ret := n
} else := ret if {
	ret := x - 1
}
