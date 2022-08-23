// Copyright 2022 Snyk Ltd
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

package hcl_interpreter

import (
	"strings"
)

func PopulateTags(resource interface{}) {
	resourceObj := map[string]interface{}{}
	if obj, ok := resource.(map[string]interface{}); ok {
		resourceObj = obj
	}

	tagObj := map[string]interface{}{}

	if typeStr, ok := resourceObj["_type"].(string); ok {
		if typeStr == "aws_autoscaling_group" {
			if arr, ok := resourceObj["tag"].([]interface{}); ok {
				for i := range arr {
					if obj, ok := arr[i].(map[string]interface{}); ok {
						if key, ok := obj["key"].(string); ok {
							if value, ok := obj["value"]; ok {
								tagObj[key] = value
							}
						}
					}
				}
			}
		}
	}

	if providerStr, ok := resourceObj["_provider"].(string); ok {
		if provider := strings.SplitN(providerStr, ".", 2); len(provider) > 0 {
			switch provider[0] {
			case "google":
				if tags, ok := resourceObj["labels"].(map[string]interface{}); ok {
					for k, v := range tags {
						tagObj[k] = v
					}
				}
				if tags, ok := resourceObj["tags"].([]interface{}); ok {
					for _, key := range tags {
						if str, ok := key.(string); ok {
							tagObj[str] = nil
						}
					}
				}
			default:
				if tags, ok := resourceObj["tags"].(map[string]interface{}); ok {
					for k, v := range tags {
						tagObj[k] = v
					}
				}
			}
		}
	}

	// Keep only string and nil tags
	tags := map[string]interface{}{}
	for k, v := range tagObj {
		if str, ok := v.(string); ok {
			tags[k] = str
		} else if v == nil {
			tags[k] = nil
		}
	}

	resourceObj["_tags"] = tags
}
