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
