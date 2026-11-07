// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// finalDrainTimeout bounds the attempt to deliver the final marker at
// shutdown; anything unsent stays staged and is replayed by the next epoch.
const finalDrainTimeout = 5 * time.Second

// ringDrainTimeout bounds reading what the BPF ring still holds at shutdown;
// past it the epoch declares unknown upstream loss before its final marker.
const ringDrainTimeout = 5 * time.Second

// printSourceID returns the s- id of the configured label under the id key
// (the value an operator puts in the Node's group as sourceId).
func printSourceID(label, keyFile string) (string, error) {
	if label == "" || keyFile == "" {
		return "", fmt.Errorf("print-source-id needs EMIT_SOURCE_LABEL and EMIT_ID_KEY_FILE")
	}
	key, err := hostrecords.ReadIDKeyFile(keyFile)
	if err != nil {
		return "", err
	}
	return hostrecords.LabelPseudonym("s-", label, key), nil
}

// readProductionKeys reads both key files before anything is loaded.
func readProductionKeys(cfg *Config) (idKey, stateKey []byte, err error) {
	if idKey, err = hostrecords.ReadIDKeyFile(cfg.IDKeyFile); err != nil {
		return nil, nil, err
	}
	if stateKey, err = hostrecords.ReadStateKeyFile(cfg.StateKeyFile); err != nil {
		return nil, nil, err
	}
	return idKey, stateKey, nil
}

// sourceConfig is the library configuration of this emitter.
func sourceConfig(cfg *Config, idKey, stateKey []byte) hostrecords.Config {
	return hostrecords.Config{
		Kind:        hostrecords.KindEBPF,
		Version:     version,
		TenantID:    cfg.TenantID,
		SourceLabel: cfg.SourceLabel,
		HostLabel:   cfg.HostLabel,
		IDKey:       idKey,
		StateKey:    stateKey,
		StateDir:    cfg.StateDir,
		Digests:     cfg.Digests == "permitted",
		Classes:     cfg.eventClasses(),
	}
}

// eventSource is the BPF runtime as the production loop reads it.
type eventSource interface {
	next() (*event, error)
	lossCount() (uint64, error)
	// stop ends production into the ring and wakes next, which then returns
	// every record still in the ring followed by an error.
	stop() error
}

// runProduction exports host records as traces (053 §6.2.9).
func runProduction(cfg *Config) error {
	idKey, stateKey, err := readProductionKeys(cfg)
	if err != nil {
		return err
	}
	var kube *kubeClient
	if cfg.AgentPodSelector != "" {
		if kube, err = newInClusterClient(cfg.NodeName, cfg.AgentPodSelector); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	exp, err := newExporter(ctx, cfg)
	if err != nil {
		return err
	}
	defer exp.close()
	rt, err := loadBPF(cfg)
	if err != nil {
		return err
	}
	defer rt.close()
	src, err := hostrecords.Open(sourceConfig(cfg, idKey, stateKey))
	if err != nil {
		return err
	}
	prod := newProduction(src, exp)
	log.Printf("fabric-host-emitter: production mode, bpf loaded, source %s, exporting to %s (agent_roots=%d sandbox_roots=%d pod_selector=%v all_host=%v)",
		src.SourceID(), cfg.Endpoint, len(cfg.AgentCgroupRoots), len(cfg.SandboxCgroupRoots), cfg.AgentPodSelector != "", cfg.AllHost)

	var pods *podScope
	if kube != nil {
		pods = newPodScope(cfg.CgroupRoot, rt, cgroupIDFromPath,
			func() { prod.upstreamLoss(lossScopeLate, -1) },
			func() { prod.upstreamLoss(lossUnknown, -1) })
		go kube.run(ctx, pods)
		go pods.watchSlices(ctx, 2*time.Second)
	}
	return productionLoop(ctx, cfg, rt, prod, pods)
}

// productionLoop reads events, stages them, and stages heartbeats until ctx
// ends; it then stops the ring, stages what it and the event queue still
// hold (or declares unknown upstream loss when it cannot), stages the final
// marker and tries once to deliver it.
func productionLoop(ctx context.Context, cfg *Config, rt eventSource, prod *production, pods *podScope) error {
	drainCtx, stopDrain := context.WithCancel(ctx)
	drainErr := make(chan error, 1)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		drainErr <- prod.drain(drainCtx)
	}()
	defer func() {
		stopDrain()
		<-drainDone
	}()

	bucket := newTokenBucket(cfg.MaxEventsPerSec)
	evCh := make(chan *event, 4096)
	// The reader runs until the ring ends (stop, or a reader error), not until
	// ctx ends: at shutdown the queue and the ring are read to the end.
	abandon := make(chan struct{})
	defer close(abandon)
	go func() {
		defer close(evCh)
		for {
			e, err := rt.next()
			if err != nil {
				return
			}
			select {
			case evCh <- e:
			case <-abandon:
				return
			}
		}
	}()

	batchTick := time.NewTicker(250 * time.Millisecond)
	defer batchTick.Stop()
	heartbeatTick := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTick.Stop()
	statusTick := time.NewTicker(30 * time.Second)
	defer statusTick.Stop()

	var pending []hostrecords.Event
	var rateLimited int64
	var lastKernelLoss uint64
	flush := func() error {
		total, err := rt.lossCount()
		if err != nil {
			return fmt.Errorf("read BPF ring loss counter: %w", err)
		}
		if total < lastKernelLoss {
			return fmt.Errorf("BPF ring loss counter moved backwards")
		}
		prod.upstreamLoss(lossRingBufferFull, int64(total-lastKernelLoss))
		lastKernelLoss = total
		prod.upstreamLoss(lossRateLimited, rateLimited)
		rateLimited = 0
		for len(pending) > 0 {
			n := min(len(pending), stageBatchMax)
			if err := prod.stage(pending[:n]); err != nil {
				return err
			}
			pending = pending[n:]
		}
		pending = nil
		return nil
	}
	declareClock := func(tsNs uint64) error { return prod.declareClockFor(sensorClock, tsNs, flush) }
	add := func(e *event) error {
		if !bucket.allow(time.Now()) {
			rateLimited++
			return nil
		}
		// Re-derive wall time (CLOCK_REALTIME may have stepped), then declare
		// what this record needs.
		sensorClock.refresh(clockRefreshEvery)
		if err := declareClock(e.TsNs); err != nil {
			return err
		}
		ev, ok := hostEvent(e)
		if !ok {
			return nil
		}
		pending = append(pending, ev)
		if len(pending) >= stageBatchMax {
			return flush()
		}
		return nil
	}
	// drainRing stages every event still queued or in the ring. Whatever it
	// cannot read is declared, so a sealed epoch never hides a loss.
	drainRing := func() error {
		if err := rt.stop(); err != nil {
			log.Printf("fabric-host-emitter: cannot stop the BPF ring at shutdown (%v); declared unknown upstream loss", err)
			prod.upstreamLoss(lossUnknown, -1)
			return nil
		}
		timeout := time.NewTimer(ringDrainTimeout)
		defer timeout.Stop()
		for {
			select {
			case e, ok := <-evCh:
				if !ok {
					return nil
				}
				if err := add(e); err != nil {
					return err
				}
			case <-timeout.C:
				log.Printf("fabric-host-emitter: BPF ring not drained within %s at shutdown; declared unknown upstream loss", ringDrainTimeout)
				prod.upstreamLoss(lossUnknown, -1)
				return nil
			}
		}
	}
	shutdown := func() error {
		if err := drainRing(); err != nil {
			return err
		}
		if err := flush(); err != nil {
			return err
		}
		if err := prod.close(); err != nil {
			return err
		}
		stopDrain()
		<-drainDone
		finalCtx, cancel := context.WithTimeout(context.Background(), finalDrainTimeout)
		defer cancel()
		for finalCtx.Err() == nil {
			ok, err := prod.sendPending(finalCtx)
			if err != nil {
				return err
			}
			if ok && !prod.hasPending() {
				return nil
			}
			select {
			case <-finalCtx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
		log.Printf("fabric-host-emitter: shutdown before every staged batch was acknowledged; they replay at the next start")
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return shutdown()
		case err := <-drainErr:
			if ctx.Err() != nil {
				return shutdown()
			}
			if err != nil {
				return fmt.Errorf("host-records sender stopped: %w", err)
			}
			return fmt.Errorf("host-records sender stopped unexpectedly")
		case e, ok := <-evCh:
			if !ok {
				if ctx.Err() != nil {
					// The reader ended on its own error, not on stop: what the
					// ring still held is unknown.
					prod.upstreamLoss(lossUnknown, -1)
					return shutdown()
				}
				return fmt.Errorf("ringbuf closed")
			}
			if err := add(e); err != nil {
				return err
			}
		case <-batchTick.C:
			sensorClock.refresh(0)
			if err := declareClock(sensorClock.nowMono()); err != nil {
				return err
			}
			if err := flush(); err != nil {
				return err
			}
		case <-heartbeatTick.C:
			// Records first, so the heartbeat's last sequence covers them.
			if err := flush(); err != nil {
				return err
			}
			if err := prod.heartbeat(); err != nil {
				return err
			}
		case <-statusTick.C:
			partialBatches, partialRejected := prod.status()
			line := fmt.Sprintf("fabric-host-emitter: health partial_quarantined_batches=%d partial_rejected_records=%d clock_steps=%d clock_small_steps=%d clock_uncertainty_ns=%d",
				partialBatches, partialRejected, sensorClock.stepCount(), sensorClock.smallStepCount(), prod.clockUncertainty())
			if pods != nil {
				line += fmt.Sprintf(" pod_roots=%d pod_roots_installed=%d pod_roots_removed=%d pod_roots_late=%d pod_api_errors=%d",
					pods.installedCount(), pods.rootsInstalled.Load(), pods.rootsRemoved.Load(), pods.rootsLate.Load(), pods.apiErrors.Load())
			}
			log.Print(line)
		}
	}
}
