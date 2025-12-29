package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"assurance_service/internal/audit"
)

func main() {
	dataDir := flag.String("data", "./data", "data directory")
	batch := flag.Int("batch", 100, "batch size")
	flag.Parse()

	if len(flag.Args()) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Args()[0]
	switch cmd {
	case "verify":
		events := filepath.Join(*dataDir, "events.log")
		roots := filepath.Join(*dataDir, "roots.log")
		report := audit.Verify(events, roots, *batch)
		if report.OK {
			fmt.Printf("OK: %d events, last index=%d\n", report.Total, report.LastIndex)
			os.Exit(0)
		}
		fmt.Printf("FAIL: %v\n", report.Errors)
		os.Exit(2)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Usage: assurectl [verify] --data ./data --batch 100")
}
