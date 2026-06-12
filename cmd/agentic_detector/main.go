// Command agentic_detector is a cross-platform osquery extension that exposes
// read-only tables inventorying agentic software on the host: MCP servers,
// AI agent CLIs, AI desktop apps, IDE plugins, live AI/MCP network sockets, and
// agent instruction files — each annotated with security risk flags and a
// content hash.
//
// It speaks the osquery Thrift extension protocol over a UNIX socket / named
// pipe. osquery autoloads it (--extensions_autoload) and passes --socket,
// --timeout and --interval; it can also be run standalone against osqueryi via
//
//	osqueryi --extension ./agentic_detector.ext
package main

import (
	"flag"
	"log"
	"time"

	osquery "github.com/osquery/osquery-go"

	"github.com/karmine05/agentic-detector/tables"
)

func main() {
	socket := flag.String("socket", "", "path to the osquery extension socket (required)")
	timeout := flag.Int("timeout", 3, "seconds to wait for autoloaded extensions")
	interval := flag.Int("interval", 3, "seconds between extension health checks")
	flag.Bool("verbose", false, "verbose mode (accepted for osquery compatibility; ignored)")
	flag.Parse()

	if *socket == "" {
		log.Fatalln("agentic_detector: --socket is required")
	}

	server, err := osquery.NewExtensionManagerServer(
		"agentic_detector", *socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("agentic_detector: creating extension server: %v", err)
	}

	for _, p := range tables.All() {
		server.RegisterPlugin(p)
	}

	if err := server.Run(); err != nil {
		log.Fatalf("agentic_detector: running extension server: %v", err)
	}
}
