# © 2023 Snyk Limited All rights reserved.
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

package snyk.internal.relations.cache

# This is a dummy pure Rego cache that just assigns the values.  When using
# policy-engine run, we use <pkg/policy/regoapi/snyk_relations_cache.rego>
# instead.

forward := data.snyk.internal.relations.forward

backward := data.snyk.internal.relations.backward
