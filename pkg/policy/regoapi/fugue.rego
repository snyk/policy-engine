# © 2022-2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package fugue

input_type := __current_input_type()

input_resource_types := __input_resource_types()

# Deprecated
resource_types_v0 := input_resource_types

# Internal
resource_types := input_resource_types

resources(resource_type) = ret {
  ret := __resources_by_type(resource_type)
}

allow_resource(resource) = ret {
  ret := allow({"resource": resource})
}

allow(params) = ret {
  ret := {
    "valid": true,
    "id": params.resource.id,
    "type": params.resource._type,
    "namespace": params.resource._namespace,
    "message": object.get(params, "message", ""),
  }
}

deny_resource(resource) = ret {
  ret := deny({"resource": resource})
}

deny_resource_with_message(resource, message) = ret {
  ret := deny({"resource": resource, "message": message})
}

deny(params) = ret {
  ret := {
    "valid": false,
    "id": params.resource.id,
    "type": params.resource._type,
    "namespace": params.resource._namespace,
    "message": object.get(params, "message", ""),
  }
}

missing_resource(resource_type) = ret {
  ret := missing({"resource_type": resource_type})
}

missing_resource_with_message(resource_type, message) = ret {
  ret := missing({"resource_type": resource_type, "message": message})
}

missing(params) = ret {
  ret := {
    "valid": false,
    "id": "",
    "type": params.resource_type,
    "message": object.get(params, "message", "invalid"),
  }
}
