package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseMetadataReferences can be removed once we don't support the markdown
// format anymore.
func TestParseMetadataReferences(t *testing.T) {
	meta1 := Metadata{}
	err := json.Unmarshal([]byte(`{
	"references": "[Some doc](https://example.com)"
}`), &meta1)
	assert.NoError(t, err)
	assert.Equal(t,
		meta1.parseMetadataReferences(),
		map[string][]MetadataReference{
			"general": {
				{
					Title: "Some doc",
					URL:   "https://example.com",
				},
			},
		},
	)

	meta2 := Metadata{}
	err = json.Unmarshal([]byte(`{
	"references": {
		"general": [
			{
				"title": "Some doc",
				"url": "https://example.com"
			}
		]
	}
}`), &meta2)
	assert.NoError(t, err)
	assert.Equal(t,
		meta2.parseMetadataReferences(),
		map[string][]MetadataReference{
			"general": {
				{
					Title: "Some doc",
					URL:   "https://example.com",
				},
			},
		},
	)
}

// TestReferencesFor tests that we obtain only the expected references.
func TestReferencesFor(t *testing.T) {
	meta1 := Metadata{}
	err := json.Unmarshal([]byte(`{
	"references": {
		"general": [
			{
				"title": "Some doc",
				"url": "https://example.com"
			}
		],
		"terraform": [
			{
				"title": "Resource: aws_s3_bucket",
				"url": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket"
			}
		],
		"cloudformation": [
			{
				"title": "AWS::S3::Bucket",
				"url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
			}
		]
	}
}`), &meta1)
	assert.NoError(t, err)
	assert.Equal(t,
		meta1.ReferencesFor("cfn"),
		[]MetadataReference{
			{
				Title: "Some doc",
				URL:   "https://example.com",
			},
			{
				Title: "AWS::S3::Bucket",
				URL:   "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html",
			},
		},
	)
}
