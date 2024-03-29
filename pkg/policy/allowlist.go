// © 2023 Snyk Limited All rights reserved.
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

package policy

// We are a paranoid security company so we use an allowlist rather than a
// denylist.
var allowedBuiltins = map[string]struct{}{
	"abs":                     {},
	"all":                     {},
	"and":                     {},
	"any":                     {},
	"array.concat":            {},
	"array.reverse":           {},
	"array.slice":             {},
	"assign":                  {},
	"base64.decode":           {},
	"base64.encode":           {},
	"base64.is_valid":         {},
	"base64url.decode":        {},
	"base64url.encode":        {},
	"base64url.encode_no_pad": {},
	"bits.and":                {},
	"bits.lsh":                {},
	"bits.negate":             {},
	"bits.or":                 {},
	"bits.rsh":                {},
	"bits.xor":                {},
	"cast_array":              {},
	"cast_boolean":            {},
	"cast_null":               {},
	"cast_object":             {},
	"cast_set":                {},
	"cast_string":             {},
	"ceil":                    {},
	"concat":                  {},
	"contains":                {},
	"count":                   {},
	"crypto.hmac.md5":         {},
	"crypto.hmac.sha1":        {},
	"crypto.hmac.sha256":      {},
	"crypto.hmac.sha512":      {},
	"crypto.md5":              {},
	"crypto.sha1":             {},
	"crypto.sha256":           {},
	"crypto.x509.parse_and_verify_certificates": {},
	"crypto.x509.parse_certificate_request":     {},
	"crypto.x509.parse_certificates":            {},
	"crypto.x509.parse_rsa_private_key":         {},
	"div":                                       {},
	"endswith":                                  {},
	"eq":                                        {},
	"equal":                                     {},
	"floor":                                     {},
	"format_int":                                {},
	"glob.match":                                {},
	"glob.quote_meta":                           {},
	"graph.reachable":                           {},
	"graph.reachable_paths":                     {},
	"graphql.is_valid":                          {},
	"graphql.parse":                             {},
	"graphql.parse_and_verify":                  {},
	"graphql.parse_query":                       {},
	"graphql.parse_schema":                      {},
	"gt":                                        {},
	"gte":                                       {},
	"hex.decode":                                {},
	"hex.encode":                                {},
	"indexof":                                   {},
	"indexof_n":                                 {},
	"internal.member_2":                         {},
	"internal.member_3":                         {},
	"internal.print":                            {},
	"intersection":                              {},
	"io.jwt.decode":                             {},
	"io.jwt.decode_verify":                      {},
	"io.jwt.encode_sign":                        {},
	"io.jwt.encode_sign_raw":                    {},
	"io.jwt.verify_es256":                       {},
	"io.jwt.verify_es384":                       {},
	"io.jwt.verify_es512":                       {},
	"io.jwt.verify_hs256":                       {},
	"io.jwt.verify_hs384":                       {},
	"io.jwt.verify_hs512":                       {},
	"io.jwt.verify_ps256":                       {},
	"io.jwt.verify_ps384":                       {},
	"io.jwt.verify_ps512":                       {},
	"io.jwt.verify_rs256":                       {},
	"io.jwt.verify_rs384":                       {},
	"io.jwt.verify_rs512":                       {},
	"is_array":                                  {},
	"is_boolean":                                {},
	"is_null":                                   {},
	"is_number":                                 {},
	"is_object":                                 {},
	"is_set":                                    {},
	"is_string":                                 {},
	"json.filter":                               {},
	"json.is_valid":                             {},
	"json.marshal":                              {},
	"json.patch":                                {},
	"json.remove":                               {},
	"json.unmarshal":                            {},
	"lower":                                     {},
	"lt":                                        {},
	"lte":                                       {},
	"max":                                       {},
	"min":                                       {},
	"minus":                                     {},
	"mul":                                       {},
	"neq":                                       {},
	"net.cidr_contains":                         {},
	"net.cidr_contains_matches":                 {},
	"net.cidr_expand":                           {},
	"net.cidr_intersects":                       {},
	"net.cidr_merge":                            {},
	"net.cidr_overlap":                          {},
	"net.lookup_ip_addr":                        {},
	"numbers.range":                             {},
	"object.filter":                             {},
	"object.get":                                {},
	"object.remove":                             {},
	"object.subset":                             {},
	"object.union":                              {},
	"object.union_n":                            {},
	"opa.runtime":                               {},
	"or":                                        {},
	"plus":                                      {},
	"print":                                     {},
	"product":                                   {},
	"rand.intn":                                 {},
	"re_match":                                  {},
	"regex.find_all_string_submatch_n":          {},
	"regex.find_n":                              {},
	"regex.globs_match":                         {},
	"regex.is_valid":                            {},
	"regex.match":                               {},
	"regex.replace":                             {},
	"regex.split":                               {},
	"regex.template_match":                      {},
	"rego.metadata.chain":                       {},
	"rego.metadata.rule":                        {},
	"rego.parse_module":                         {},
	"rem":                                       {},
	"replace":                                   {},
	"round":                                     {},
	"semver.compare":                            {},
	"semver.is_valid":                           {},
	"set_diff":                                  {},
	"snapshot_testing.match":                    {},
	"sort":                                      {},
	"split":                                     {},
	"sprintf":                                   {},
	"startswith":                                {},
	"strings.any_prefix_match":                  {},
	"strings.any_suffix_match":                  {},
	"strings.replace_n":                         {},
	"strings.reverse":                           {},
	"substring":                                 {},
	"sum":                                       {},
	"time.add_date":                             {},
	"time.clock":                                {},
	"time.date":                                 {},
	"time.diff":                                 {},
	"time.now_ns":                               {},
	"time.parse_duration_ns":                    {},
	"time.parse_ns":                             {},
	"time.parse_rfc3339_ns":                     {},
	"time.weekday":                              {},
	"to_number":                                 {},
	"trace":                                     {},
	"trim":                                      {},
	"trim_left":                                 {},
	"trim_prefix":                               {},
	"trim_right":                                {},
	"trim_space":                                {},
	"trim_suffix":                               {},
	"type_name":                                 {},
	"union":                                     {},
	"units.parse":                               {},
	"units.parse_bytes":                         {},
	"upper":                                     {},
	"urlquery.decode":                           {},
	"urlquery.decode_object":                    {},
	"urlquery.encode":                           {},
	"urlquery.encode_object":                    {},
	"uuid.rfc4122":                              {},
	"walk":                                      {},
	"yaml.is_valid":                             {},
	"yaml.marshal":                              {},
	"yaml.unmarshal":                            {},
}
