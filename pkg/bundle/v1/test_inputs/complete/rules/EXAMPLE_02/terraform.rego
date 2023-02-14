# Copyright 2023 Snyk Ltd
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

package rules.EXAMPLE_02.terraform

import data.snyk

input_type := "tf"

resource_type := "MULTIPLE"

metadata := {
	"id": "EXAMPLE_02",
	"title": "Order includes cheeseburger pizza",
}

menu_items := snyk.resources("data.dominos_menu_item")

includes_cheeseburger(menu_item) {
	term := menu_item.query_string[_]
	lower(term) == "cheeseburger"
}

deny[info] {
	menu_item := menu_items[_]
	includes_cheeseburger(menu_item)
	info := {"resource": menu_item}
}

resources[info] {
	menu_item := menu_items[_]
	info := {"resource": menu_item}
}
