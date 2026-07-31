package broadcast

import (
	"fmt"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func contentJob(id string, output string) Job {
	return Job{
		Destinations: []trustedrouter.BroadcastDestination{{
			ID:             "destination-1",
			IncludeContent: true,
		}},
		Generation: Generation{ID: id, RequestID: "request-" + id},
		Input:      nil,
		Output:     output,
	}
}

func TestContentQueueDropsOldestToStayWithinByteBudget(t *testing.T) {
	queue := NewQueue(QueueOptions{
		Size:        4,
		Workers:     1,
		MaxBytes:    12,
		MaxJobBytes: 12,
	})

	if !queue.Enqueue(contentJob("first", "123456")) {
		t.Fatal("first enqueue failed")
	}
	if !queue.Enqueue(contentJob("second", "abcdef")) {
		t.Fatal("second enqueue failed")
	}

	if len(queue.jobs) != 1 {
		t.Fatalf("queued jobs = %d, want 1", len(queue.jobs))
	}
	queued := <-queue.jobs
	if queued.Generation.ID != "second" {
		t.Fatalf("remaining generation = %q, want second", queued.Generation.ID)
	}
}

func TestContentQueueRejectsJobOverByteBudget(t *testing.T) {
	queue := NewQueue(QueueOptions{
		Size:        4,
		Workers:     1,
		MaxBytes:    16,
		MaxJobBytes: 8,
	})

	if queue.Enqueue(contentJob("oversized", "123456789")) {
		t.Fatal("oversized content job was accepted")
	}
	if len(queue.jobs) != 0 {
		t.Fatalf("queued jobs = %d, want 0", len(queue.jobs))
	}
}

func TestContentQueueIgnoresMetadataOnlyDestinations(t *testing.T) {
	queue := NewQueue(QueueOptions{Size: 1, Workers: 1, MaxBytes: 1, MaxJobBytes: 1})
	job := contentJob("metadata", "private output")
	job.Destinations[0].IncludeContent = false

	if !queue.Enqueue(job) {
		t.Fatal("metadata-only destination should be a successful no-op")
	}
	if len(queue.jobs) != 0 {
		t.Fatalf("queued jobs = %d, want 0", len(queue.jobs))
	}
}

func TestContentQueueConcurrentEnqueueStaysBounded(t *testing.T) {
	queue := NewQueue(QueueOptions{
		Size:        8,
		Workers:     1,
		MaxBytes:    80,
		MaxJobBytes: 20,
	})
	var workers sync.WaitGroup
	for index := range 100 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			queue.Enqueue(contentJob(fmt.Sprintf("job-%d", index), "123456"))
		}()
	}
	workers.Wait()

	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.jobs) > cap(queue.jobs) {
		t.Fatalf("queued jobs = %d, capacity = %d", len(queue.jobs), cap(queue.jobs))
	}
	if queue.queuedBytes > queue.maxBytes {
		t.Fatalf("queued bytes = %d, max = %d", queue.queuedBytes, queue.maxBytes)
	}
}
