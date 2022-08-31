# Enhanced mechanism to report secondary resources and their attributes

- [Enhanced mechanism to report secondary resources and their attributes](#enhanced-mechanism-to-report-secondary-resources-and-their-attributes)
  - [Background](#background)
  - [Proposed new output format](#proposed-new-output-format)
  - [New convention for deny rules](#new-convention-for-deny-rules)
  - [Example rule](#example-rule)
    - [Diff](#diff)

This document is a proposal for an enhancement to Policy Engine's output format
and a new convention for the `deny` rule that makes it possible.

## Background

The policy spec currently defines two rules that can return resources and
attributes:

* `deny`: used to report a failing primary resource
* `resources`: used to report all primary and secondary resources that the
  policy used in its evaluation

The resources and attributes returned from both of these rules gets combined
into the `resources` field in the output, e.g.:

```javascript
{
  // ...
  "resources": [
    {
      "id": "aws_s3_bucket.public3",
      "type": "aws_s3_bucket",
      "namespace": "invalid_via_multiple.tf",
      "location": [/*...*/],
      "attributes": [
        {
          "path": ["grant", 0, "uri"],
          "location": {/*..*/}
        }
      ]
    },
    {
      "id": "data.aws_iam_policy_document.policy3-policy",
      "type": "data.aws_iam_policy_document",
      "namespace": "invalid_via_multiple.tf",
      "location": [/*...*/],
      "attributes": [
        {
          "path": ["statement", 0, "principals"],
          "location": {/*..*/}
        }
      ]
    }
  ]
}
```

Some weaknesses in this approach:

* If a primary resource fails _because of_ an attribute on a secondary resource,
  there's not a good way to explicitly report that in the policy.
* It's unclear why you'd return `attributes` from a `deny` rule vs a `resources`
  rule or what the role of `attributes` is in each.
* The output does not distinguish between "good" attributes and "bad" attributes
* Consumers of this output require an extra processing step to pick out just the
  primary or secondary resource from `resources`

## Proposed new output format

In order to address these weaknesses, we propose a change to the output format
that separates:

* Primary and secondary resources
* Good and bad attributes

```javascript
{
  // ...
  "primary_resource": {
    "id": "aws_s3_bucket.public3",
    "type": "aws_s3_bucket",
    "namespace": "invalid_via_multiple.tf",
    "location": [/*...*/],
    "failed_attributes": [
      {
        "path": ["grant", 0, "uri"],
        "location": {/*..*/}
      }
    ],
    "tested_attributes": [
      {
        "path": ["grant", 0, "uri"],
        "location": {/*..*/}
      },
      {
        /*...*/
      }
    ]
  },
  "secondary_resources": [
    {
      "id": "data.aws_iam_policy_document.policy3-policy",
      "type": "data.aws_iam_policy_document",
      "namespace": "invalid_via_multiple.tf",
      "location": [/*...*/],
      "failed_attributes": [
        {
          "path": ["statement", 0, "principals"],
          "location": {/*..*/}
        }
      ],
      "tested_attributes": [
        {
          "path": ["statement", 0, "principals"],
          "location": {/*..*/}
        },
        {
          /*...*/
        }
      ]
    }
  ]
}
```

## New convention for deny rules

In order to make it possible for Policy Engine to distinguish between good and
bad attributes on both primary and secondary resources, we propose a new
convention for deny rules:

```open-policy-agent
# If a failure is caused by an attribute on a secondary resource, the deny rule
# should be written as:

deny[info] {
  # ... getting resources, relating them, conditions for failure
  info := {
    "primary_resource": bucket,
    "resource": bucket_policy,
    "attributes": [[<attribute path from secondary resource>]]
  }
}
```

Some advantages of this approach:

1. It enables us to consistently use `attributes` in the `deny` rule to report
   "bad" attributes.
2. It's likely that this uses a lot of the same code as the `resources` rules
   that return these secondary resources
3. It reduces the need for the `message` field.
   * The current convention for the message field is to clarify the cause of a
     failure when a rule has multiple failure conditions
   * It's often being used to distinguish between which resource caused the
     failure, for example:
     * `"A bucket policy allows public access to the bucket"` vs
     * `"A grant allows public access to the bucket"`
   * The proposed mechanism achieves this purpose in a more explicit and
     machine-readable way.

## Example rule

This is a modified version of [SNYK-CC-00172](https://github.com/snyk/opa-rules/blob/4602c181dba4db6a2e5678a4381f069fca2b882c/rego/rules/SNYK_CC_00172/terraform.rego).


Notice that we've removed the "existence checks" for all attributes, because
`deny` and `resources` now have clearer roles:

* `deny`: returns bad resources and bad attributes
* `resources`: returns all resources and all attributes used by the policy

```open-policy-agent
package rules.SNYK_CC_00172.terraform

import data.lib.tf.aws.s3.bucket as s3lib
import data.snyk

metadata := data.rules.SNYK_CC_00172.metadata

cloudtrails = snyk.resources("aws_cloudtrail")

buckets = snyk.resources("aws_s3_bucket")

# First collect buckets IDs that are the target for cloudtrail logging.
# Also store the corresponding trails.
cloudtrails_by_bucket := {bucket: trails |
	bucket := cloudtrails[_].s3_bucket_name
	trails := [trail |
		trail := cloudtrails[_]
		trail.s3_bucket_name == bucket
	]
}

# Now build a list of relevant buckets based on that.
relevant_buckets := [bucket |
	bucket := buckets[_]
	trails := cloudtrails_by_bucket[s3lib.bucket_name_or_id(bucket)]
	count(trails) > 0
]

# Set of "forbidden" ACLs.
public_acls := {"public-read", "public-read-write"}

deny[info] {
	bucket := relevant_buckets[_]
	public_acls[bucket.acl]
	info := {
		"resource": bucket,
		"attributes": [["acl"]]
	}
}

deny[info] {
	bucket := relevant_buckets[_]
	acl := s3lib.bucket_acls_by_bucket[s3lib.bucket_name_or_id(bucket)]
	public_acls[acl.acl]
	info := {
		"primary_resource": bucket,
		"resource": acl,
		"attributes": [["acl"]]
	}
}

resources[info] {
	bucket := relevant_buckets[_]
	info := {
		"resource": bucket,
		"attributes": [["acl"]],
	}
}

resources[info] {
	bucket := relevant_buckets[_]
	acl := s3lib.bucket_acls_by_bucket[s3lib.bucket_name_or_id(bucket)]
	info := {
		"primary_resource": bucket,
		"resource": acl,
		"attributes": [["acl"]],
	}
}

resources[info] {
	bucket := relevant_buckets[_]
	trails := cloudtrails_by_bucket[s3lib.bucket_name_or_id(bucket)]
	trail := trails[_]
	info := {
		"primary_resource": bucket,
		"resource": trail,
		"attributes": [["s3_bucket_name"]],
	}
}
```

### Diff

```diff
diff --git a/rego/rules/SNYK_CC_00172/terraform.rego b/rego/rules/SNYK_CC_00172/terraform.rego
index a2dfe045..7b50e750 100644
--- a/rego/rules/SNYK_CC_00172/terraform.rego
+++ b/rego/rules/SNYK_CC_00172/terraform.rego
@@ -29,22 +29,23 @@ relevant_buckets := [bucket |
 # Set of "forbidden" ACLs.
 public_acls := {"public-read", "public-read-write"}
 
-# Function to decide if a bucket has a bad ACL.
-bucket_public_acl(bucket) {
+deny[info] {
+	bucket := relevant_buckets[_]
 	public_acls[bucket.acl]
-}
-
-bucket_public_acl(bucket) {
-	acl := s3lib.bucket_acls_by_bucket[s3lib.bucket_name_or_id(bucket)]
-	public_acls[acl.acl]
+	info := {
+		"resource": bucket,
+		"attributes": [["acl"]]
+	}
 }
 
 deny[info] {
 	bucket := relevant_buckets[_]
-	bucket_public_acl(bucket)
+	acl := s3lib.bucket_acls_by_bucket[s3lib.bucket_name_or_id(bucket)]
+	public_acls[acl.acl]
 	info := {
-		"resource": bucket,
-		"message": "Bucket stores CloudTrail log files and has a public access ACL",
+		"primary_resource": bucket,
+		"resource": acl,
+		"attributes": [["acl"]]
 	}
 }
 
@@ -52,7 +53,7 @@ resources[info] {
 	bucket := relevant_buckets[_]
 	info := {
 		"resource": bucket,
-		"attributes": [["acl"] | _ = bucket.acl],
+		"attributes": [["acl"]],
 	}
 }
 
@@ -62,7 +63,7 @@ resources[info] {
 	info := {
 		"primary_resource": bucket,
 		"resource": acl,
-		"attributes": [["acl"] | _ = acl.acl],
+		"attributes": [["acl"]],
 	}
 }
 

```
