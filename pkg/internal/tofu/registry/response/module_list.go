// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package response

// ModuleList is the response structure for a pageable list of modules.
type ModuleList struct {
	Meta    PaginationMeta `json:"meta"`
	Modules []*Module      `json:"modules"`
}
