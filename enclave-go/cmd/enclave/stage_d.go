package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	defaultHeartbeatBudget          = 5 * time.Second
	defaultSettleBeforeTerminal     = 2 * time.Second
	stageDHeartbeatInterval         = 10 * time.Second
	stageDHeartbeatOutputTokenDelta = 256
)

type stageDConfig struct {
	usageHeartbeat       bool
	terminateAtCap       bool
	heartbeatBudget      time.Duration
	settleBeforeTerminal time.Duration
}

func stageDConfigFromEnv() stageDConfig {
	return stageDConfig{
		usageHeartbeat:       stageDFlagEnabled("QUILL_USAGE_HEARTBEAT"),
		terminateAtCap:       stageDFlagEnabled("QUILL_TERMINATE_AT_CAP"),
		heartbeatBudget:      envDurationMS("QUILL_HEARTBEAT_BUDGET_MS", defaultHeartbeatBudget),
		settleBeforeTerminal: envDurationMS("QUILL_SETTLE_BEFORE_TERMINAL_MS", defaultSettleBeforeTerminal),
	}
}

func stageDFlagEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func stageDStreamEligible(config stageDConfig, auth *trustedrouter.Authorization, req *types.OpenAIChatRequest, routeType string) bool {
	if !config.usageHeartbeat || auth == nil || req == nil || !auth.StageD.Eligible || !req.Stream {
		return false
	}
	return routeType == "chat.completions" || routeType == "responses"
}

type stageDMeter struct {
	promptTokens         int
	semanticBytes        int
	reasoningBytes       int
	toolArgBytes         int
	cacheReadTokens      int
	cacheCreationTokens  int
	priceTierInputTokens int
}

func (m *stageDMeter) admit(delta adapter.StreamDelta) {
	if m == nil {
		return
	}
	size := len([]byte(delta.Text))
	m.semanticBytes += size
	switch delta.Type {
	case "thinking_delta":
		m.reasoningBytes += size
	case "input_json_delta":
		m.toolArgBytes += size
	}
}

func (m *stageDMeter) outputTokens() int {
	if m == nil {
		return 0
	}
	return m.semanticBytes / 4
}

func (m *stageDMeter) reasoningTokens() int {
	if m == nil {
		return 0
	}
	return m.reasoningBytes / 4
}

func (m *stageDMeter) heartbeatUsage() trustedrouter.HeartbeatUsage {
	return trustedrouter.HeartbeatUsage{
		InputTokens: m.promptTokens, OutputTokens: m.outputTokens(),
		CacheReadInputTokens: m.cacheReadTokens, CacheCreationInputTokens: m.cacheCreationTokens,
		PriceTierInputTokens: m.priceTierInputTokens, ReasoningTokens: m.reasoningTokens(),
	}
}

type stageDController struct {
	mu sync.Mutex

	ctx                 context.Context
	gateway             *trustedrouter.Client
	auth                *trustedrouter.Authorization
	cancel              context.CancelFunc
	closeProvider       func(error)
	config              stageDConfig
	started             time.Time
	now                 func() time.Time
	endpointID          string
	meter               stageDMeter
	seq                 int64
	lastAccepted        time.Time
	lastOutput          int
	capMicro            int64
	price               trustedrouter.CandidatePrice
	hasPrice            bool
	heartbeatLostReason trustedrouter.HeartbeatRejectionReason
	heartbeatLost       bool
	sliceInFlight       bool
	stopOnce            sync.Once
	stopCh              chan struct{}
	background          sync.WaitGroup
}

func newStageDController(
	ctx context.Context,
	gateway *trustedrouter.Client,
	auth *trustedrouter.Authorization,
	cancel context.CancelFunc,
	closeProvider func(error),
	config stageDConfig,
	started time.Time,
	endpointID string,
	promptTokens int,
) *stageDController {
	price, ok := auth.CandidatePrice(endpointID)
	return &stageDController{
		ctx: ctx, gateway: gateway, auth: auth, cancel: cancel, closeProvider: closeProvider, config: config,
		started: started, now: time.Now, endpointID: endpointID, meter: stageDMeter{promptTokens: promptTokens},
		capMicro: auth.CapMicro, price: price, hasPrice: ok,
		stopCh: make(chan struct{}),
	}
}

func (c *stageDController) currentTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *stageDController) preHeader() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.sendHeartbeatLocked(1); err != nil {
		return err
	}
	if c.config.terminateAtCap && (!c.hasPrice || c.capMicro <= 0 || c.price.Rounding != "half_up_per_million") {
		return fmt.Errorf("stage_d: cap enforcement pricing unavailable for endpoint %q", c.endpointID)
	}
	c.startCadenceLocked()
	return nil
}

func (c *stageDController) startCadenceLocked() {
	c.background.Add(1)
	go func() {
		defer c.background.Done()
		ticker := time.NewTicker(stageDHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.mu.Lock()
				if !c.heartbeatLost && !c.sliceInFlight && time.Since(c.lastAccepted) >= stageDHeartbeatInterval {
					if err := c.sendHeartbeatLocked(c.seq + 1); err != nil {
						c.markHeartbeatLostLocked(err)
					}
				}
				c.mu.Unlock()
			}
		}
	}()
}

func (c *stageDController) stopCadence() {
	c.stopOnce.Do(func() { close(c.stopCh) })
	c.background.Wait()
}

func (c *stageDController) beforeSlice(delta adapter.StreamDelta) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.heartbeatLost {
		return &adapter.ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
	}
	if now.Sub(c.lastAccepted) >= stageDHeartbeatInterval || c.meter.outputTokens()-c.lastOutput >= stageDHeartbeatOutputTokenDelta {
		if err := c.sendHeartbeatLocked(c.seq + 1); err != nil {
			c.markHeartbeatLostLocked(err)
			return &adapter.ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
		}
	}
	if c.config.terminateAtCap && c.wouldExceedCapLocked(delta.Text) {
		termination := &adapter.ControlledTermination{FinishReason: "length", TRFinishReason: "cap_reached"}
		if c.cancel != nil {
			c.cancel()
		}
		if c.closeProvider != nil {
			c.closeProvider(termination)
		}
		fmt.Fprintf(os.Stderr, "enclave.stage_d_cap_reached auth_id=%q output_tokens=%d cap_micro=%d\n", c.auth.AuthorizationID, c.meter.outputTokens(), c.capMicro)
		return termination
	}
	// Keep the cadence goroutine from beginning a heartbeat between this
	// admission decision and the corresponding client write/flush.
	c.sliceInFlight = true
	return nil
}

func (c *stageDController) markHeartbeatLostLocked(err error) {
	if c.heartbeatLost {
		return
	}
	c.heartbeatLost = true
	if c.cancel != nil {
		c.cancel()
	}
	if c.closeProvider != nil {
		c.closeProvider(err)
	}
	fmt.Fprintf(os.Stderr, "enclave.stage_d_heartbeat_lost auth_id=%q err=%q\n", c.auth.AuthorizationID, errorClass(err))
}

func (c *stageDController) termination() *adapter.ControlledTermination {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.heartbeatLost {
		return nil
	}
	return &adapter.ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
}

func (c *stageDController) afterSlice(delta adapter.StreamDelta) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sliceInFlight = false
	c.meter.admit(delta)
	// Complete any cadence that became due while this slice was being written
	// synchronously here, so the next visible slice cannot overtake the durable
	// snapshot.
	if !c.heartbeatLost && (time.Since(c.lastAccepted) >= stageDHeartbeatInterval || c.meter.outputTokens()-c.lastOutput >= stageDHeartbeatOutputTokenDelta) {
		if err := c.sendHeartbeatLocked(c.seq + 1); err != nil {
			c.markHeartbeatLostLocked(err)
			return &adapter.ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
		}
	}
	return nil
}

func (c *stageDController) observeUsage(usage *adapter.StreamUsage) {
	if usage == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if usage.InputTokens > 0 || usage.CacheReadInputTokens > 0 || usage.CacheCreationInputTokens > 0 {
		providerPromptTokens := usage.InputTokens
		if usage.InputExcludesCache {
			providerPromptTokens += usage.CacheReadInputTokens + usage.CacheCreationInputTokens
		}
		c.meter.promptTokens = max(c.meter.promptTokens, providerPromptTokens)
		c.meter.cacheReadTokens = max(c.meter.cacheReadTokens, usage.CacheReadInputTokens)
		c.meter.cacheCreationTokens = max(c.meter.cacheCreationTokens, usage.CacheCreationInputTokens)
	}
	if usage.PriceTierInputTokens > 0 {
		c.meter.priceTierInputTokens = max(c.meter.priceTierInputTokens, usage.PriceTierInputTokens)
	}
}

func (c *stageDController) sendHeartbeatLocked(seq int64) error {
	request := trustedrouter.HeartbeatRequest{
		AuthorizationID:    c.auth.AuthorizationID,
		Seq:                seq,
		StartedAtMS:        c.started.UnixMilli(),
		SelectedEndpointID: c.endpointID,
		Usage:              c.meter.heartbeatUsage(),
		ElapsedMS:          max(c.currentTime().Sub(c.started).Milliseconds(), int64(0)),
		Stream:             true,
	}
	heartbeatCtx, cancel := context.WithTimeout(c.ctx, c.config.heartbeatBudget)
	defer cancel()
	fmt.Fprintf(os.Stderr, "enclave.stage_d_heartbeat_sent auth_id=%q seq=%d output_tokens=%d\n", c.auth.AuthorizationID, seq, request.Usage.OutputTokens)
	response, err := c.gateway.Heartbeat(heartbeatCtx, c.auth, request)
	if err != nil {
		if reason, ok := trustedrouter.HeartbeatRejection(err); ok {
			c.heartbeatLostReason = reason
			fmt.Fprintf(os.Stderr, "enclave.stage_d_heartbeat_rejected auth_id=%q seq=%d reason=%q\n", c.auth.AuthorizationID, seq, reason)
		} else {
			fmt.Fprintf(os.Stderr, "enclave.stage_d_heartbeat_lost auth_id=%q seq=%d err=%q\n", c.auth.AuthorizationID, seq, errorClass(err))
		}
		return err
	}
	if response == nil || !response.Accepted || response.Seq != seq {
		return fmt.Errorf("stage_d: invalid heartbeat acknowledgement")
	}
	c.seq = seq
	c.lastAccepted = c.currentTime()
	c.lastOutput = c.meter.outputTokens()
	if response.CapMicro > 0 && c.capMicro <= 0 {
		c.capMicro = response.CapMicro
	} else if c.capMicro > 0 && response.CapMicro != c.capMicro {
		fmt.Fprintf(os.Stderr, "enclave.stage_d_cap_reply_mismatch auth_id=%q seq=%d cap_micro=%d reply_cap_micro=%d\n", c.auth.AuthorizationID, seq, c.capMicro, response.CapMicro)
	}
	fmt.Fprintf(os.Stderr, "enclave.stage_d_heartbeat_accepted auth_id=%q seq=%d cap_micro=%d running_micro=%d\n", c.auth.AuthorizationID, seq, c.capMicro, response.RunningMicro)
	return nil
}

func (c *stageDController) wouldExceedCapLocked(text string) bool {
	if c.capMicro <= 0 || !c.hasPrice {
		return false
	}
	prospective := c.meter
	prospective.semanticBytes += len([]byte(text))
	tierPrompt := c.meter.promptTokens
	if c.meter.priceTierInputTokens > 0 {
		tierPrompt = c.meter.priceTierInputTokens
	}
	rates := c.price.RatesForPrompt(tierPrompt)
	return stageDUsageMicro(c.price, rates, prospective.promptTokens, prospective.outputTokens(), prospective.cacheReadTokens, prospective.cacheCreationTokens) > c.capMicro
}

func stageDUsageMicro(price trustedrouter.CandidatePrice, rates trustedrouter.PriceRates, input, output, cached, cacheCreation int) int64 {
	uncached := max(input-cached-cacheCreation, 0)
	total := price.RequestFeeMicro +
		halfUpPerMillion(uncached, rates.InputMicroPerMillion) +
		halfUpPerMillion(output, rates.OutputMicroPerMillion) +
		halfUpPerMillion(cached, rates.CachedInputMicroPerMillion) +
		halfUpPerMillion(cacheCreation, rates.CacheCreationMicroPerMillion)
	positive := (uncached > 0 && rates.InputMicroPerMillion > 0) ||
		(output > 0 && rates.OutputMicroPerMillion > 0) ||
		(cached > 0 && rates.CachedInputMicroPerMillion > 0) ||
		(cacheCreation > 0 && rates.CacheCreationMicroPerMillion > 0)
	if total == 0 && positive {
		return 1
	}
	return total
}

func halfUpPerMillion(tokens int, rate int64) int64 {
	if tokens <= 0 || rate <= 0 {
		return 0
	}
	return (int64(tokens)*rate + 500_000) / 1_000_000
}

func (c *stageDController) terminalUsage(terminal adapter.StreamTerminal, requestID, routeType, selectedModel string, req *types.OpenAIChatRequest, firstTokenSeconds float64) trustedrouter.Usage {
	c.mu.Lock()
	meteredInput, meteredOutput, meteredReasoning := c.meter.promptTokens, c.meter.outputTokens(), c.meter.reasoningTokens()
	c.mu.Unlock()
	input, output, estimated := meteredInput, meteredOutput, true
	providerExact := terminal.Result.Usage != nil && terminal.Result.Usage.OutputTokens > 0
	if providerExact {
		input, output, estimated = realOrEstimatedTokens(terminal.Result, meteredInput, meteredOutput)
	}
	finishReason := terminal.FinishReason
	if terminal.TRFinishReason != "" {
		finishReason = terminal.TRFinishReason
	}
	usage := trustedrouter.Usage{
		RequestID: requestID, InputTokens: input, OutputTokens: output,
		ElapsedSeconds:    maxDurationSeconds(time.Since(c.started), 0.001),
		FirstTokenSeconds: firstTokenSeconds, UsageEstimated: estimated,
		ReasoningTokens: meteredReasoning, FinishReason: finishReason, Streamed: true,
		RouteType: routeType, SelectedModel: selectedModel, SelectedEndpoint: c.endpointID,
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
		ServiceTier: requestedServiceTierForSettlement(req),
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, terminal.Result)
	if providerExact {
		usage.ReasoningTokens = terminal.Result.Usage.ReasoningTokens
	} else {
		// A message_start usage object may exist even though cap/heartbeat
		// termination prevented terminal provider usage. In that case the
		// canonical semantic meter, including reasoning, remains authoritative.
		usage.ReasoningTokens = meteredReasoning
	}
	return usage
}

func stageDDispositionLost(result *trustedrouter.SettleResult) bool {
	return result != nil && (result.Disposition == trustedrouter.DispositionReapedSnapshot || (result.AlreadySettled && !result.Settled))
}

func logStageDSettleLost(auth *trustedrouter.Authorization, result *trustedrouter.SettleResult, source string) {
	disposition := ""
	if result != nil {
		disposition = result.Disposition
	}
	fmt.Fprintf(os.Stderr, "enclave.stage_d_settle_lost auth_id=%q disposition=%q source=%q\n", authorizationID(auth), disposition, source)
}

func stageDTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
