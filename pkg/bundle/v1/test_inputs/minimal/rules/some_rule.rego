package rules.playlist_guardrails

import data.snyk

input_type := "tf"

resource_type := "MULTIPLE"

metadata := {"title": "Playlist lacks cowbell"}

playlists := snyk.resources("spotify_playlist")

includes_boc(playlist) {
	track := playlist.tracks[_]
	track == "5QTxFnGygVM4jFQiBovmRo"
}

deny[info] {
	playlist := playlists[_]
	not includes_boc(playlist)
	info := {"resource": playlist}
}

resources[info] {
	playlist := playlists[_]
	info := {"resource": playlist}
}
