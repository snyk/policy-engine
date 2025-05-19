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

package rules.playlist_guardrails

import data.snyk

input_type := "tf"

resource_type := "MULTIPLE"

metadata := {"title": "Playlist lacks cowbell"}

playlists := snyk.resources("spotify_playlist")

includes_boc(playlist) if {
	track := playlist.tracks[_]
	track == "5QTxFnGygVM4jFQiBovmRo"
}

deny contains info if {
	playlist := playlists[_]
	not includes_boc(playlist)
	info := {"resource": playlist}
}

resources contains info if {
	playlist := playlists[_]
	info := {"resource": playlist}
}
