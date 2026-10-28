package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MIGUEL-MOSCOSO-DEV/tracehound/internal/capture"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	flags := flag.NewFlagSet("tracehound", flag.ContinueOnError)
	input := flags.String("pcap", "", "classic PCAP capture path")
	cancelFile := flags.String("cancel-file", "", "optional local cancellation marker path")
	output := flags.String("out", "", "output report JSON path")
	options := capture.Options{}
	flags.IntVar(&options.MaxFlows, "max-flows", 2000, "maximum tracked endpoint tuples")
	flags.IntVar(&options.MemoryMB, "memory-mb", 32, "TCP payload storage budget in MB")
	flags.IntVar(&options.StreamKB, "stream-kb", 64, "maximum captured payload per TCP direction in KB")
	flags.IntVar(&options.PortThreshold, "port-threshold", 20, "distinct destination ports within 60 seconds")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *input == "" || *output == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Provide --pcap and --out. Use --help for options.")
		return 2
	}
	a, _ := filepath.Abs(*input)
	b, _ := filepath.Abs(*output)
	if a == b {
		fmt.Fprintln(os.Stderr, "Capture and output must be different files.")
		return 2
	}
	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer file.Close()
	hash := sha256.New()
	reader := io.TeeReader(file, hash)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *cancelFile != "" {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(*cancelFile); err == nil {
						stop()
						return
					}
				}
			}
		}()
	}
	report, analyzeErr := capture.Analyze(ctx, reader, options, func(packets int) { fmt.Fprintf(os.Stderr, "Packets %d\n", packets) })
	report.CaptureSHA256 = hex.EncodeToString(hash.Sum(nil))
	if !report.Complete {
		report.CaptureSHA256 = ""
	}
	if err = os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	temporary, err := os.CreateTemp(filepath.Dir(*output), ".tracehound-*.tmp")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	name := temporary.Name()
	defer os.Remove(name)
	temporary.Chmod(0600)
	_, err = temporary.Write(data)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, *output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if analyzeErr != nil {
		fmt.Fprintln(os.Stderr, analyzeErr)
		return 2
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"complete": report.Complete, "packets": report.Coverage.Packets, "flows": len(report.Flows), "alerts": len(report.Alerts), "report": *output})
	return 0
}
