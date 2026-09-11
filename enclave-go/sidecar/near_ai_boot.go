package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// Derived offline from the reviewed OS files and VM configuration, never from
// the endpoint's self-reported tcb_info. RTMR3 is replayed per request because
// it includes the guest's instance ID.
type nearAIBootMeasurements struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

func (p *nearAIBootMeasurements) values() []string {
	return []string{p.MRTD, p.RTMR0, p.RTMR1, p.RTMR2}
}

func (p *nearAIBootMeasurements) validate() error {
	if p == nil {
		return errors.New("NEAR AI boot measurements have not been independently reviewed")
	}
	for _, value := range p.values() {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 48 || value != strings.ToLower(value) {
			return errors.New("NEAR AI boot measurement must be 48 lowercase hex bytes")
		}
	}
	return nil
}

func verifyNearAIBoot(body *tdxpb.TDQuoteBody, pins *nearAIBootMeasurements, rtmr3 []byte) error {
	if err := pins.validate(); err != nil {
		return err
	}
	if body == nil || len(body.GetRtmrs()) != 4 {
		return errors.New("NEAR AI quote is missing boot registers")
	}
	actual := append([][]byte{body.GetMrTd()}, body.GetRtmrs()[:3]...)
	for index, expected := range pins.values() {
		if hex.EncodeToString(actual[index]) != expected {
			return fmt.Errorf("NEAR AI boot measurement %d is outside the reviewed policy", index)
		}
	}
	if len(rtmr3) != 48 || !bytes.Equal(body.GetRtmrs()[3], rtmr3) {
		return errors.New("NEAR AI quote does not bind the runtime event log")
	}
	return nil
}

type nearAIRuntimeEvent struct {
	IMR          uint32 `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

func replayNearAIRuntimeEvents(events []nearAIRuntimeEvent, compose, osImage string) ([]byte, error) {
	if len(events) == 0 || len(events) > 1024 {
		return nil, errors.New("NEAR AI runtime event log is missing or oversized")
	}
	// dstack 0.5.x SHA384(type_le || ':' || name || ':' || payload), then
	// SHA384(previous_register || event_digest). Ignore claimed event digests.
	// Source: Dstack-TEE/dstack cc-eventlog/src/runtime_events.rs.
	register := make([]byte, 48)
	seen := make(map[string]bool)
	ready := false
	for _, event := range events {
		if event.IMR > 3 {
			return nil, errors.New("NEAR AI event log has an invalid register")
		}
		if event.IMR != 3 {
			continue // Boot registers are checked against independently calculated pins.
		}
		if ready || event.EventType != 0x08000001 || event.Event == "" {
			return nil, errors.New("NEAR AI runtime event sequence is invalid")
		}
		payload, err := hex.DecodeString(event.EventPayload)
		if err != nil {
			return nil, errors.New("NEAR AI runtime event payload is not hex")
		}
		switch event.Event {
		case "compose-hash", "os-image-hash", "system-ready":
			if seen[event.Event] {
				return nil, errors.New("NEAR AI runtime identity event is duplicated")
			}
			seen[event.Event] = true
			if (event.Event == "compose-hash" && event.EventPayload != compose) ||
				(event.Event == "os-image-hash" && event.EventPayload != osImage) ||
				(event.Event == "system-ready" && len(payload) != 0) {
				return nil, errors.New("NEAR AI runtime identity is outside the reviewed policy")
			}
			ready = event.Event == "system-ready"
		}
		hash := sha512.New384()
		var eventType [4]byte
		binary.LittleEndian.PutUint32(eventType[:], event.EventType)
		hash.Write(eventType[:])
		hash.Write([]byte(":" + event.Event + ":"))
		hash.Write(payload)
		digest := sha512.Sum384(append(register, hash.Sum(nil)...))
		register = digest[:]
	}
	if !seen["compose-hash"] || !seen["os-image-hash"] || !ready {
		return nil, errors.New("NEAR AI runtime identity events are incomplete")
	}
	return register, nil
}
