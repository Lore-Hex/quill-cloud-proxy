package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestNearAIBootRejectsEveryChangedQuoteRegister(t *testing.T) {
	for _, stage := range []string{"model", "manager"} {
		for register := 0; register < 5; register++ {
			t.Run(fmt.Sprintf("%s/%d", stage, register), func(t *testing.T) {
				c := newNearAITestCase(t)
				body := c.modelBody
				if stage == "manager" {
					body = c.managerBody
				}
				if register == 0 {
					body.MrTd[0] ^= 1
				} else {
					body.Rtmrs[register-1][0] ^= 1
				}
				if _, err := c.verifier.verify(context.Background(), c.request); err == nil {
					t.Fatal("accepted an unreviewed quote register")
				}
			})
		}
	}
}

func TestNearAIBootMissingPinsFailClosedPerRoute(t *testing.T) {
	c := newNearAITestCase(t)
	c.policy.BootMeasurements = nil
	var err error
	c.verifier.policies, err = validateNearAIPolicies([]nearAIPolicy{c.policy})
	if err != nil {
		t.Fatalf("held old policies must not disable the whole sidecar: %v", err)
	}
	if _, err := c.verifier.verify(context.Background(), c.request); err == nil || !strings.Contains(err.Error(), "not been independently reviewed") {
		t.Fatalf("missing pins did not fail closed: %v", err)
	}
}

func TestNearAIBootMalformedPinsAreRejected(t *testing.T) {
	for _, value := range []string{"", "zz", strings.Repeat("11", 47), strings.Repeat("11", 49), strings.Repeat("AA", 48)} {
		c := newNearAITestCase(t)
		c.policy.BootMeasurements.MRTD = value
		if _, err := validateNearAIPolicies([]nearAIPolicy{c.policy}); err == nil {
			t.Fatal("accepted malformed boot pin")
		}
	}
}

func TestNearAIRuntimeEventLogRejectsMutations(t *testing.T) {
	cases := map[string]func(*nearAITestCase){
		"missing":           func(c *nearAITestCase) { c.report.EventLog = nil },
		"compose":           func(c *nearAITestCase) { c.report.EventLog[0].EventPayload = strings.Repeat("ff", 32) },
		"OS":                func(c *nearAITestCase) { c.report.EventLog[1].EventPayload = strings.Repeat("ff", 32) },
		"type":              func(c *nearAITestCase) { c.report.EventLog[0].EventType++ },
		"invalid hex":       func(c *nearAITestCase) { c.report.EventLog[0].EventPayload = "xy" },
		"register":          func(c *nearAITestCase) { c.report.EventLog[0].IMR = 4 },
		"missing compose":   func(c *nearAITestCase) { c.report.EventLog = c.report.EventLog[1:] },
		"duplicate compose": func(c *nearAITestCase) { c.report.EventLog[1] = c.report.EventLog[0] },
		"missing ready":     func(c *nearAITestCase) { c.report.EventLog = c.report.EventLog[:2] },
		"after ready":       func(c *nearAITestCase) { c.report.EventLog = append(c.report.EventLog, c.report.EventLog[0]) },
		"valid but unbound event": func(c *nearAITestCase) {
			c.report.EventLog = append([]nearAIRuntimeEvent{{IMR: 3, EventType: 0x08000001, Event: "instance-id", EventPayload: "abcd"}}, c.report.EventLog...)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := newNearAITestCase(t)
			mutate(c)
			c.encodeReport(t)
			if _, err := c.verifier.verify(context.Background(), c.request); err == nil {
				t.Fatal("accepted an invalid or unbound runtime event log")
			}
		})
	}
}
