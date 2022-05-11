package fugue

input_type := __current_input_type()

resources(resource_type) = ret {
  resources := __resources_by_type(resource_type)
  ret := { r._uid: r |
    r := resources[_]
  }
}

allow_resource(resource) = ret {
  ret := allow({"resource": resource})
}

allow(params) = ret {
  ret := {
    "valid": true,
    "id": params.resource.id,
    "type": params.resource._type,
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
