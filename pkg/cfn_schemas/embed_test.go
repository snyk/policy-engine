package cfn_schemas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetSchema(t *testing.T) {
	// This type is a good test since it contains a cycle.
	emrCluster := GetSchema("AWS::EMR::Cluster")
	assert.NotNil(t, emrCluster)
	assert.Equal(t, emrCluster.Type, Object)
	assert.Equal(t, emrCluster.Properties["Configurations"].Type, Array)
	assert.Equal(t, emrCluster.Properties["Configurations"].Items.Properties["Configurations"].Type, Array)
	assert.Equal(t, emrCluster.Properties["Configurations"].Items.Properties["Configurations"].Items.Properties["Configurations"].Type, Array)
}
