// Copyright 2022-2023 Snyk Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cfn

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input/schemas"
)

func Test_GetSchema(t *testing.T) {
	s3Bucket := GetSchema("AWS::S3::Bucket")
	assert.Equal(t, s3Bucket.Type, schemas.Object)
	assert.Equal(t, s3Bucket.Properties["BucketName"].Type, schemas.String)

	// This type is a good test since it contains a cycle.
	emrCluster := GetSchema("AWS::EMR::Cluster")
	assert.NotNil(t, emrCluster)
	assert.Equal(t, emrCluster.Type, schemas.Object)
	assert.Equal(t, emrCluster.Properties["Configurations"].Type, schemas.Array)
	assert.Equal(t, emrCluster.Properties["Configurations"].Items.Properties["Configurations"].Type, schemas.Array)
	assert.Equal(t, emrCluster.Properties["Configurations"].Items.Properties["Configurations"].Items.Properties["Configurations"].Type, schemas.Array)
}

func Test_ResourceTypes(t *testing.T) {
	for _, resourceType := range ResourceTypes() {
		schema := GetSchema(resourceType)
		assert.Equal(t, schema.Type, schemas.Object)
	}
}
