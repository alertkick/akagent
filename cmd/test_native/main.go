// test_native is a standalone test program for the native eBPF agent.
// Run with: sudo go run ./cmd/test_native
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"apagent/ebpf"
)

func main() {
	fmt.Println("=== Native eBPF Agent Test ===")
	fmt.Println()

	// Check kernel support
	support := ebpf.CheckKernelSupport()
	fmt.Printf("Kernel: %s\n", support.Version)
	fmt.Printf("Ring Buffer Support: %v\n", support.HasRingBuf)
	fmt.Printf("Tracepoint Support: %v\n", support.HasTracepoint)
	fmt.Printf("Can Load BPF: %v\n", support.CanLoadBPF)

	if !support.IsSupported() {
		fmt.Printf("\nError: %v\n", support.Error)
		fmt.Println("\nNote: This test requires root privileges and kernel 5.8+")
		os.Exit(1)
	}

	fmt.Println("\nKernel support OK, creating agent...")

	// Create the agent
	agent, err := ebpf.NewNativeAgent()
	if err != nil {
		fmt.Printf("Failed to create agent: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Start the agent (loads BPF programs)
	fmt.Println("Starting agent (loading BPF programs)...")
	if err := agent.Start(ctx); err != nil {
		fmt.Printf("Failed to start agent: %v\n", err)
		os.Exit(1)
	}
	defer agent.Stop(ctx)

	// Start the event listener
	fmt.Println("Starting event listener...")
	if err := agent.StartEventListener(ctx); err != nil {
		fmt.Printf("Failed to start event listener: %v\n", err)
		os.Exit(1)
	}
	defer agent.StopEventListener()

	fmt.Println("\n=== Listening for security events ===")
	fmt.Println("Monitoring: process execution, file operations, network, signals")
	fmt.Println("Run commands in another terminal to see events.")
	fmt.Println("Press Ctrl+C to stop.")

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Read events
	eventChan := agent.EventChannel()
	eventCount := 0

	// Track event counts by category
	categoryCounts := make(map[string]int)

	for {
		select {
		case <-sigChan:
			fmt.Printf("\n\nReceived shutdown signal.\n")
			fmt.Printf("Events received: %d\n", eventCount)
			fmt.Println("\nEvents by category:")
			for cat, count := range categoryCounts {
				fmt.Printf("  %s: %d\n", cat, count)
			}

			// Show filter statistics
			total, filtered := agent.GetFilterStats()
			fmt.Printf("\nFilter statistics:\n")
			fmt.Printf("  Total processed: %d\n", total)
			fmt.Printf("  Filtered out: %d\n", filtered)
			if total > 0 {
				pct := float64(filtered) / float64(total) * 100
				fmt.Printf("  Filter rate: %.1f%%\n", pct)
			}
			return

		case event := <-eventChan:
			eventCount++
			categoryCounts[event.Category]++

			timestamp := event.Timestamp.Format("15:04:05.000")

			// Color code by category
			var categoryColor string
			switch event.Category {
			case "process":
				categoryColor = "\033[32m" // Green
			case "file":
				categoryColor = "\033[34m" // Blue
			case "network":
				categoryColor = "\033[33m" // Yellow
			default:
				categoryColor = "\033[0m" // Reset
			}

			fmt.Printf("%s[%s] %-20s%s PID=%-6d %s\n",
				categoryColor,
				timestamp,
				event.Rule,
				"\033[0m",
				event.Process.PID,
				event.Process.Name)
			fmt.Printf("           %s\n", event.Output)
			fmt.Println()

		case <-time.After(60 * time.Second):
			fmt.Printf("(waiting for events... %d received so far)\n", eventCount)
		}
	}
}
