// Command vigil-server runs the Vigil manager: ingestion API, Sigma
// detection, correlation, vulnerability and compliance analysis, active
// response and the web dashboard.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/vigil-siem/vigil/internal/server"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("vigil-server: ")
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(server.Version)
		return
	}
	cfg, err := server.LoadConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
