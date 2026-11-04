// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// rootTable is the BPF scope-root map (bpf.go) as the pod watcher sees it.
type rootTable interface {
	setRoot(cgroupID uint64, scope uint32) error
	deleteRoot(cgroupID uint64) error
}

// podInfo is what the watcher keeps of one matching pod.
type podInfo struct {
	uid string
	// containers holds the container ids the API server reported as created
	// (status containerID of app, init and ephemeral containers).
	containers map[string]bool
}

// installedRoot is one pod slice installed as an agent root.
type installedRoot struct {
	path     string
	cgroupID uint64
}

// podScope installs the pod slice of every pod on this node that matches
// EMIT_AGENT_POD_SELECTOR as an agent root when the slice appears, and
// removes it when the pod is deleted (spec 056 §4.3, §7.3.3 (c); OD-12).
// It only reads the API server and cgroupfs; it never changes a pod.
type podScope struct {
	cgroupRoot string
	roots      rootTable
	statID     func(path string) (uint64, error)
	// late reports upstream loss scope_late: a root installed after a
	// non-sandbox container cgroup already existed in its slice.
	late func()
	// overLimit reports a matching pod refused because maxPodRoots are
	// already installed (its events are not captured).
	overLimit func()

	mu        sync.Mutex
	pods      map[string]*podInfo
	installed map[string]installedRoot
	refused   map[string]bool

	// Health counters, logged with the emitter's status line.
	apiErrors      atomic.Uint64
	rootsInstalled atomic.Uint64
	rootsRemoved   atomic.Uint64
	rootsLate      atomic.Uint64
}

func newPodScope(cgroupRoot string, roots rootTable, statID func(string) (uint64, error), late, overLimit func()) *podScope {
	return &podScope{
		cgroupRoot: cgroupRoot,
		roots:      roots,
		statID:     statID,
		late:       late,
		overLimit:  overLimit,
		pods:       make(map[string]*podInfo),
		installed:  make(map[string]installedRoot),
		refused:    make(map[string]bool),
	}
}

// sliceCandidates lists where the kubelet places a pod's slice under either
// cgroup driver and every QoS class (056 §4.3 "Kubernetes sandbox roots").
func sliceCandidates(uid string) []string {
	u := strings.ReplaceAll(uid, "-", "_")
	return []string{
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + u + ".slice",
		"kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + u + ".slice",
		"kubepods.slice/kubepods-pod" + u + ".slice",
		"kubepods/burstable/pod" + uid,
		"kubepods/besteffort/pod" + uid,
		"kubepods/pod" + uid,
	}
}

// qosDirs are the directories a new pod slice appears in; the slice watcher
// listens on them.
func qosDirs(cgroupRoot string) []string {
	var dirs []string
	for _, d := range []string{
		"kubepods.slice", "kubepods.slice/kubepods-burstable.slice", "kubepods.slice/kubepods-besteffort.slice",
		"kubepods", "kubepods/burstable", "kubepods/besteffort",
	} {
		dirs = append(dirs, filepath.Join(cgroupRoot, d))
	}
	return dirs
}

// replace sets the full list of matching pods (after a list call).
func (s *podScope) replace(pods []*podInfo) {
	s.mu.Lock()
	keep := make(map[string]bool, len(pods))
	for _, p := range pods {
		keep[p.uid] = true
		s.pods[p.uid] = p
	}
	var gone []string
	for uid := range s.pods {
		if !keep[uid] {
			gone = append(gone, uid)
		}
	}
	s.mu.Unlock()
	for _, uid := range gone {
		s.remove(uid)
	}
	s.resync()
}

// upsert records an added or modified matching pod.
func (s *podScope) upsert(p *podInfo) {
	s.mu.Lock()
	s.pods[p.uid] = p
	s.mu.Unlock()
	s.resync()
}

// remove forgets a pod and removes its root.
func (s *podScope) remove(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pods, uid)
	delete(s.refused, uid)
	root, ok := s.installed[uid]
	if !ok {
		return
	}
	if err := s.roots.deleteRoot(root.cgroupID); err != nil {
		log.Printf("fabric-host-emitter: pod scope root removal failed error_type=%T", err)
		return
	}
	delete(s.installed, uid)
	s.rootsRemoved.Add(1)
}

// resync installs the root of every known pod whose slice now exists.
func (s *podScope) resync() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for uid, pod := range s.pods {
		if _, ok := s.installed[uid]; ok {
			continue
		}
		path := s.findSlice(uid)
		if path == "" {
			continue
		}
		if len(s.installed) >= maxPodRoots {
			if !s.refused[uid] {
				s.refused[uid] = true
				log.Printf("fabric-host-emitter: pod scope limit reached (%d roots); a matching pod is not captured", maxPodRoots)
				if s.overLimit != nil {
					s.overLimit()
				}
			}
			continue
		}
		id, err := s.statID(path)
		if err != nil {
			continue
		}
		late := s.sliceIsLate(path, pod)
		if err := s.roots.setRoot(id, scopeAgent); err != nil {
			log.Printf("fabric-host-emitter: pod scope root install failed error_type=%T", err)
			continue
		}
		s.installed[uid] = installedRoot{path: path, cgroupID: id}
		s.rootsInstalled.Add(1)
		if late {
			s.rootsLate.Add(1)
			if s.late != nil {
				s.late()
			}
		}
	}
}

func (s *podScope) findSlice(uid string) string {
	for _, rel := range sliceCandidates(uid) {
		path := filepath.Join(s.cgroupRoot, rel)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path
		}
	}
	return ""
}

// sliceIsLate reports whether a container other than the pod's sandbox
// container may already have run when its root is installed: the slice
// holds more than one container cgroup, or a container cgroup the API
// server lists as one of the pod's own containers, or the API server already
// lists a created container (an init container's cgroup may be gone).
func (s *podScope) sliceIsLate(path string, pod *podInfo) bool {
	if len(pod.containers) > 0 {
		return true
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return true
	}
	containers := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id, _ := hostrecords.SandboxIDs(filepath.Base(path) + "/" + entry.Name())
		if id == "" {
			continue
		}
		containers++
		if pod.containers[id] {
			return true
		}
	}
	return containers > 1
}

func (s *podScope) installedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.installed)
}

// --- API server watch -------------------------------------------------------

// kubeClient lists and watches this node's pods over plain HTTPS with the
// mounted service-account token and CA; no client library.
type kubeClient struct {
	base      string
	tokenPath string
	http      *http.Client
	node      string
	selector  string
	terms     map[string]string
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// newInClusterClient builds the client from the in-cluster environment.
func newInClusterClient(node, selector string) (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("EMIT_AGENT_POD_SELECTOR needs the in-cluster API server (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT)")
	}
	return newKubeClient("https://"+net.JoinHostPort(host, port),
		filepath.Join(serviceAccountDir, "token"), filepath.Join(serviceAccountDir, "ca.crt"), node, selector)
}

func newKubeClient(base, tokenPath, caPath, node, selector string) (*kubeClient, error) {
	terms, err := parseSelector(selector)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("service-account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("service-account CA holds no certificate")
	}
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	return &kubeClient{
		base:      strings.TrimRight(base, "/"),
		tokenPath: tokenPath,
		node:      node,
		selector:  selector,
		terms:     terms,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// apiPod is the part of a Pod object the watcher reads.
type apiPod struct {
	Metadata struct {
		UID             string            `json:"uid"`
		Labels          map[string]string `json:"labels"`
		ResourceVersion string            `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses          []apiContainerStatus `json:"containerStatuses"`
		InitContainerStatuses      []apiContainerStatus `json:"initContainerStatuses"`
		EphemeralContainerStatuses []apiContainerStatus `json:"ephemeralContainerStatuses"`
	} `json:"status"`
}

type apiContainerStatus struct {
	ContainerID string `json:"containerID"`
}

type apiPodList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []apiPod `json:"items"`
}

type apiWatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// errWatchExpired is a 410 Gone: the resource version is too old; relist.
var errWatchExpired = errors.New("watch resource version expired")

// matches checks the selector and the node on the client side too, so a pod
// is installed only when both hold, whatever the server returned.
func (k *kubeClient) matches(p *apiPod) bool {
	if p.Spec.NodeName != k.node || p.Metadata.UID == "" {
		return false
	}
	for key, value := range k.terms {
		if got, ok := p.Metadata.Labels[key]; !ok || got != value {
			return false
		}
	}
	return true
}

func toPodInfo(p *apiPod) *podInfo {
	info := &podInfo{uid: p.Metadata.UID, containers: make(map[string]bool)}
	for _, list := range [][]apiContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, c := range list {
			if _, id, ok := strings.Cut(c.ContainerID, "://"); ok && id != "" {
				info.containers[id] = true
			}
		}
	}
	return info
}

func (k *kubeClient) query(watch bool, resourceVersion string) string {
	q := url.Values{}
	q.Set("fieldSelector", "spec.nodeName="+k.node)
	q.Set("labelSelector", k.selector)
	if watch {
		q.Set("watch", "1")
		q.Set("allowWatchBookmarks", "true")
		q.Set("timeoutSeconds", "300")
		if resourceVersion != "" {
			q.Set("resourceVersion", resourceVersion)
		}
	}
	return k.base + "/api/v1/pods?" + q.Encode()
}

func (k *kubeClient) get(ctx context.Context, target string) (*http.Response, error) {
	// The bound service-account token rotates; read it for every request.
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("service-account token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusGone {
		resp.Body.Close()
		return nil, errWatchExpired
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("API server answered status %d", resp.StatusCode)
	}
	return resp, nil
}

// list returns the matching pods and the list's resource version.
func (k *kubeClient) list(ctx context.Context) ([]*podInfo, string, error) {
	resp, err := k.get(ctx, k.query(false, ""))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var list apiPodList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&list); err != nil {
		return nil, "", fmt.Errorf("decode pod list: %w", err)
	}
	var pods []*podInfo
	for i := range list.Items {
		if k.matches(&list.Items[i]) {
			pods = append(pods, toPodInfo(&list.Items[i]))
		}
	}
	return pods, list.Metadata.ResourceVersion, nil
}

// watch streams changes after resourceVersion into scope and returns the
// last resource version seen when the stream ends.
func (k *kubeClient) watch(ctx context.Context, resourceVersion string, scope *podScope) (string, error) {
	resp, err := k.get(ctx, k.query(true, resourceVersion))
	if err != nil {
		return resourceVersion, err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	for {
		var ev apiWatchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return resourceVersion, nil
			}
			return resourceVersion, fmt.Errorf("decode watch event: %w", err)
		}
		switch ev.Type {
		case "ERROR":
			var status struct {
				Code int `json:"code"`
			}
			if json.Unmarshal(ev.Object, &status) == nil && status.Code == http.StatusGone {
				return "", errWatchExpired
			}
			return resourceVersion, fmt.Errorf("watch error event")
		case "ADDED", "MODIFIED", "DELETED", "BOOKMARK":
		default:
			continue
		}
		var pod apiPod
		if err := json.Unmarshal(ev.Object, &pod); err != nil {
			return resourceVersion, fmt.Errorf("decode watched pod: %w", err)
		}
		if pod.Metadata.ResourceVersion != "" {
			resourceVersion = pod.Metadata.ResourceVersion
		}
		switch ev.Type {
		case "BOOKMARK":
		case "DELETED":
			scope.remove(pod.Metadata.UID)
		default:
			if k.matches(&pod) {
				scope.upsert(toPodInfo(&pod))
			} else {
				scope.remove(pod.Metadata.UID)
			}
		}
	}
}

// run lists, then watches, until ctx ends. API errors are retried with
// backoff and counted; they never touch the roots already installed.
func (k *kubeClient) run(ctx context.Context, scope *podScope) {
	backoff := time.Second
	resourceVersion := ""
	for ctx.Err() == nil {
		var err error
		if resourceVersion == "" {
			var pods []*podInfo
			pods, resourceVersion, err = k.list(ctx)
			if err == nil {
				scope.replace(pods)
			}
		}
		if err == nil {
			resourceVersion, err = k.watch(ctx, resourceVersion, scope)
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = time.Second
			continue
		}
		if errors.Is(err, errWatchExpired) {
			resourceVersion = ""
		}
		scope.apiErrors.Add(1)
		// API status bodies are not logged: they may echo request details.
		log.Printf("fabric-host-emitter: pod watch retry pending error_type=%T", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// watchSlices re-checks pod slices whenever a QoS directory changes, and at
// least every interval (inotify where available, slicewatch_*.go).
func (s *podScope) watchSlices(ctx context.Context, interval time.Duration) {
	changes := sliceChanges(ctx, qosDirs(s.cgroupRoot))
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-tick.C:
		}
		s.resync()
	}
}
