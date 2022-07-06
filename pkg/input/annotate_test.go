package input

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestAnnotate01(t *testing.T) {
	detector, err := DetectorByInputTypes(Types{Auto})
	assert.Nil(t, err)
	loader := NewLoader(detector)
	detectable, err := NewDetectable(afero.OsFs{}, "golden_test/cfn/annotate-01/main.yaml")
	assert.Nil(t, err)
	ok, err := loader.Load(detectable, DetectOptions{})
	assert.Nil(t, err)
	assert.True(t, ok)

	states := loader.ToStates()
	assert.Len(t, states, 1)
	state := states[0]
	results := &models.Results{
		Results: []models.Result{
			{
				Input: state,
			},
		},
	}

	AnnotateResults(loader, results)

	assert.Equal(t,
		[]models.SourceLocation{
			{
				Filepath: "golden_test/cfn/annotate-01/main.yaml",
				Line:     2,
				Column:   3,
			},
		},
		results.Results[0].Input.Resources["AWS::S3::Bucket"]["Foo"].Meta["location"],
	)

	assert.Equal(t,
		[]models.SourceLocation{
			{
				Filepath: "golden_test/cfn/annotate-01/main.yaml",
				Line:     6,
				Column:   3,
			},
		},
		results.Results[0].Input.Resources["AWS::S3::Bucket"]["Bar"].Meta["location"],
	)
}
