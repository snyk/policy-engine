package main

import (
	// "log"
	// "net/http"
	// _ "net/http/pprof"

	// "github.com/felixge/fgprof"
	"github.com/snyk/policy-engine/cmd"
)

func main() {
	// http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())
	// go func() {
	// 	log.Println(http.ListenAndServe(":6060", nil))
	// }()
	cmd.Execute()
}
