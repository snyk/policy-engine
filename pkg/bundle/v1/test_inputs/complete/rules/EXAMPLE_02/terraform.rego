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
	has_bucket_name(menu_item)
	info := {"resource": menu_item}
}

resources[info] {
	menu_item := menu_items[_]
	info := {"resource": menu_item}
}
