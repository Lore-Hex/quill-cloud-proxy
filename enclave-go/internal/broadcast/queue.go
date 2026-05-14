package broadcast

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const (
	defaultContentQueueSize    = 256
	defaultContentQueueWorkers = 2
)

// Job carries opt-in prompt/output export material. It is intentionally
// memory-only and bounded by Queue capacity.
type Job struct {
	Cache        *byokcache.Cache
	Destinations []trustedrouter.BroadcastDestination
	Generation   Generation
	Input        any
	Output       string
}

type QueueOptions struct {
	Size       int
	Workers    int
	HTTPClient *http.Client
}

type Queue struct {
	jobs    chan Job
	workers int
	httpc   *http.Client
}

func NewQueueFromEnv() *Queue {
	return NewQueue(QueueOptions{
		Size:    envInt("QUILL_BROADCAST_CONTENT_QUEUE_SIZE", defaultContentQueueSize),
		Workers: envInt("QUILL_BROADCAST_CONTENT_WORKERS", defaultContentQueueWorkers),
	})
}

func NewQueue(options QueueOptions) *Queue {
	if options.Size <= 0 {
		return &Queue{}
	}
	if options.Workers <= 0 {
		options.Workers = defaultContentQueueWorkers
	}
	httpc := options.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 5 * time.Second}
	}
	return &Queue{
		jobs:    make(chan Job, options.Size),
		workers: options.Workers,
		httpc:   httpc,
	}
}

func (q *Queue) Enabled() bool {
	return q != nil && q.jobs != nil
}

func (q *Queue) Start(ctx context.Context) {
	if !q.Enabled() {
		return
	}
	for i := 0; i < q.workers; i++ {
		go q.run(ctx)
	}
}

func (q *Queue) Enqueue(job Job) bool {
	job.Destinations = contentDestinations(job.Destinations)
	if len(job.Destinations) == 0 {
		return true
	}
	if !q.Enabled() {
		logContentDrop("queue_disabled", job)
		return false
	}
	select {
	case q.jobs <- job:
		return true
	default:
	}

	select {
	case dropped := <-q.jobs:
		logContentDrop("drop_oldest", dropped)
	default:
	}

	select {
	case q.jobs <- job:
		return true
	default:
		logContentDrop("queue_full", job)
		return false
	}
}

func (q *Queue) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-q.jobs:
			DeliverContent(
				ctx,
				q.httpc,
				job.Cache,
				job.Destinations,
				job.Generation,
				job.Input,
				job.Output,
			)
		}
	}
}

func contentDestinations(destinations []trustedrouter.BroadcastDestination) []trustedrouter.BroadcastDestination {
	if len(destinations) == 0 {
		return nil
	}
	filtered := make([]trustedrouter.BroadcastDestination, 0, len(destinations))
	for _, destination := range destinations {
		if destination.IncludeContent {
			filtered = append(filtered, destination)
		}
	}
	return filtered
}

func logContentDrop(reason string, job Job) {
	fmt.Fprintf(
		os.Stderr,
		"broadcast.content_drop reason=%q generation_id=%q request_id=%q destination_count=%d\n",
		reason,
		job.Generation.ID,
		job.Generation.RequestID,
		len(job.Destinations),
	)
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}
