package legacyiac_test

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/legacyiac"
	"github.com/stretchr/testify/assert"
)

func TestRawK8sInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    *models.State
		expected []interface{}
	}{
		{
			name: "resources",
			state: &models.State{
				Resources: map[string]map[string]models.ResourceState{
					"Pod": {
						"invalid1": {
							Attributes: map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Pod",
								"metadata": map[string]interface{}{
									"name": "invalid1",
								},
								"spec": map[string]interface{}{
									"containers": []interface{}{
										map[string]interface{}{
											"name":  "pause1",
											"image": "k8s.gcr.io/pause",
										},
									},
								},
							},
						},
						"invalid2": {
							Attributes: map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Pod",
								"metadata": map[string]interface{}{
									"name": "invalid2",
									"annotations": map[string]interface{}{
										"seccomp.security.alpha.kubernetes.io/pod": "foo/default",
									},
								},
								"spec": map[string]interface{}{
									"containers": []interface{}{
										map[string]interface{}{
											"name":  "pause1",
											"image": "k8s.gcr.io/pause",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []interface{}{
				map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "invalid1",
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "pause1",
								"image": "k8s.gcr.io/pause",
							},
						},
					},
				},
				map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "invalid2",
						"annotations": map[string]interface{}{
							"seccomp.security.alpha.kubernetes.io/pod": "foo/default",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "pause1",
								"image": "k8s.gcr.io/pause",
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raws := []interface{}{}
			for _, input := range legacyiac.NewK8sInputs(tc.state) {
				raws = append(raws, input.Raw())
			}
			assert.Equal(t, tc.expected, raws)
		})
	}
}

func TestK8sParseMsg(t *testing.T) {
	input := legacyiac.NewK8sInputs(&models.State{
		Resources: map[string]map[string]models.ResourceState{
			"Pod": {
				"invalid1": {
					Id:           "invalid1",
					ResourceType: "Pod",
					Namespace:    "default",
					Attributes: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "Pod",
						"metadata": map[string]interface{}{
							"name": "invalid1",
						},
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "pause1",
									"image": "k8s.gcr.io/pause",
								},
							},
						},
					},
				},
			},
		},
	})[0]
	for _, tc := range []struct {
		msg      string
		expected legacyiac.ParsedMsg
	}{
		{
			msg: "input.spec.containers[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:        "invalid1",
				ResourceType:      "Pod",
				ResourceNamespace: "default",
				Path:              []interface{}{"spec", "containers", 0},
			},
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			output := input.ParseMsg(tc.msg)
			assert.Equal(t, tc.expected, output)
		})
	}
}
