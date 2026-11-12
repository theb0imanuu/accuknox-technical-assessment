package main

import (
	"fmt"
	"sync"
)

// Fixed implementation:
// 1. Uses sync.WaitGroup to wait for all enqueued tasks to complete.
// 2. Closes the channel when done producing, allowing workers to gracefully exit.
// 3. Uses a second sync.WaitGroup to wait for all worker goroutines to terminate cleanly (preventing goroutine leaks).
func main() {
	// Buffered channel for up to 10 executable task closures
	cnp := make(chan func(), 10)

	// WaitGroup to track task execution completion
	var taskWg sync.WaitGroup

	// WaitGroup to track worker lifecycle for clean shutdown
	var workerWg sync.WaitGroup

	// Spin up 4 concurrent worker goroutines
	const numWorkers = 4
	for i := 0; i < numWorkers; i++ {
		workerWg.Add(1)
		go func(workerID int) {
			defer workerWg.Done()
			for f := range cnp {
				f()
			}
		}(i)
	}

	// Enqueue task and track its completion
	taskWg.Add(1)
	cnp <- func() {
		defer taskWg.Done()
		fmt.Println("HERE1")
	}

	fmt.Println("Hello")

	// Wait for all enqueued tasks to complete execution before proceeding
	taskWg.Wait()

	// Close channel to signal workers that no more tasks will be submitted
	close(cnp)

	// Wait for all worker goroutines to exit gracefully
	workerWg.Wait()
}

