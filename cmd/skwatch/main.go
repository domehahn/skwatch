package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/domehahn/skwatch/pkg/drift"
	"github.com/domehahn/skwatch/pkg/vuln"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version":
		fmt.Printf("skwatch version %s\n", version)
	case "scan":
		handleScan(os.Args[2:])
	case "drift":
		handleDrift(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`skwatch — Continuous Vulnerability & Drift Monitor for AI Agent Skills

Usage:
  skwatch scan --path <dir>
  skwatch drift --path <dir> --expected <sha256:...>
  skwatch version`)
}

func handleScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	path := fs.String("path", ".", "Directory to scan")
	_ = fs.Parse(args)

	findings, err := vuln.ScanDirectory(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println(string(out))
	if len(findings) > 0 {
		os.Exit(2)
	}
}

func handleDrift(args []string) {
	fs := flag.NewFlagSet("drift", flag.ExitOnError)
	path := fs.String("path", ".", "Directory to inspect")
	expected := fs.String("expected", "", "Expected digest")
	_ = fs.Parse(args)

	report, err := drift.CheckDrift(*path, *expected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drift check error: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
	if report.HasDrift {
		os.Exit(2)
	}
}
