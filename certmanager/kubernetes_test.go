package certmanager

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeKubernetesAPI serves /api/v1/secrets as a list and as a watch whose
// events the test sends.
type fakeKubernetesAPI struct {
	t      *testing.T
	server *httptest.Server
	token  string

	mu       sync.Mutex
	secrets  []kubernetesSecret
	pageSize int
	lists    int
	events   chan kubernetesWatchEvent
	// expired makes the next watch fail with 410 Gone.
	expired bool
}

func newFakeKubernetesAPI(t *testing.T) *fakeKubernetesAPI {
	t.Helper()

	api := &fakeKubernetesAPI{t: t, token: "test-token", events: make(chan kubernetesWatchEvent, 8)}
	api.server = httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(api.server.Close)
	return api
}

func (a *fakeKubernetesAPI) config(t *testing.T) *KubernetesConfig {
	t.Helper()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(a.token+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return &KubernetesConfig{APIServer: a.server.URL, TokenPath: tokenPath}
}

func (a *fakeKubernetesAPI) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/secrets" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(kubernetesStatus{Code: http.StatusUnauthorized, Message: "Unauthorized"})
		return
	}
	if got := r.URL.Query().Get("fieldSelector"); got != "type=kubernetes.io/tls" {
		a.t.Errorf("fieldSelector = %q", got)
	}

	if r.URL.Query().Get("watch") == "true" {
		a.watch(w, r)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.lists++

	start := 0
	if next := r.URL.Query().Get("continue"); next != "" {
		fmt.Sscan(next, &start)
	}
	end := len(a.secrets)
	var list kubernetesSecretList
	if a.pageSize > 0 && start+a.pageSize < end {
		end = start + a.pageSize
		list.Metadata.Continue = fmt.Sprint(end)
	}
	list.Metadata.ResourceVersion = "100"
	list.Items = a.secrets[start:end]
	_ = json.NewEncoder(w).Encode(list)
}

func (a *fakeKubernetesAPI) watch(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	expired := a.expired
	a.expired = false
	a.mu.Unlock()
	if expired {
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(kubernetesStatus{Code: http.StatusGone, Message: "too old resource version"})
		return
	}

	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	for {
		select {
		case event := <-a.events:
			_ = json.NewEncoder(w).Encode(event)
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (a *fakeKubernetesAPI) send(eventType string, secret kubernetesSecret) {
	object, _ := json.Marshal(secret)
	a.events <- kubernetesWatchEvent{Type: eventType, Object: object}
}

func testTLSSecret(t *testing.T, namespace, name, hostname string) kubernetesSecret {
	t.Helper()

	chain := createTestCertificateChain(t, hostname, time.Now().Add(90*24*time.Hour), false)
	return kubernetesSecret{
		Metadata: kubernetesObjectMeta{Namespace: namespace, Name: name, ResourceVersion: "101"},
		Type:     kubernetesTLSSecretType,
		Data:     map[string][]byte{"tls.crt": chain.CertificatePEM, "tls.key": chain.KeyPEM},
	}
}

func waitForCertificates(t *testing.T, manager *Manager, present, absent []string) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, hostname := range present {
			ready = ready && manager.GetCertificateForHostname(hostname) != nil
		}
		for _, hostname := range absent {
			ready = ready && manager.GetCertificateForHostname(hostname) == nil
		}
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for certificates: present %v, absent %v", present, absent)
}

func TestKubernetesSecretsLoadAtStartupAcrossPages(t *testing.T) {
	api := newFakeKubernetesAPI(t)
	api.pageSize = 1
	api.secrets = []kubernetesSecret{
		testTLSSecret(t, "shop", "shop-tls", "shop.example.com"),
		testTLSSecret(t, "blog", "blog-tls", "blog.example.com"),
		{
			Metadata: kubernetesObjectMeta{Namespace: "blog", Name: "empty"},
			Type:     kubernetesTLSSecretType,
			Data:     map[string][]byte{"tls.crt": nil, "tls.key": nil},
		},
	}

	manager := New(Config{Kubernetes: api.config(t)})
	t.Cleanup(manager.Stop)

	if !manager.KubernetesSynced() {
		t.Fatal("KubernetesSynced() = false after a successful list")
	}
	for _, hostname := range []string{"shop.example.com", "blog.example.com"} {
		certificate := manager.GetCertificateForHostname(hostname)
		if certificate == nil {
			t.Fatalf("no certificate for %s", hostname)
		}
		if len(certificate.Certificate) != 2 {
			t.Errorf("%s: served %d certificates, want the leaf and its intermediate", hostname, len(certificate.Certificate))
		}
	}
	if got := manager.HostnameCount(); got != 2 {
		t.Errorf("HostnameCount() = %d, want 2", got)
	}
}

func TestKubernetesSecretsFollowWatchEvents(t *testing.T) {
	api := newFakeKubernetesAPI(t)
	first := testTLSSecret(t, "shop", "shop-tls", "first.example.com")
	api.secrets = []kubernetesSecret{first}

	manager := New(Config{Kubernetes: api.config(t)})
	t.Cleanup(manager.Stop)
	waitForCertificates(t, manager, []string{"first.example.com"}, nil)

	// A new Secret, such as a certificate cert-manager just issued.
	api.send("ADDED", testTLSSecret(t, "blog", "blog-tls", "second.example.com"))
	waitForCertificates(t, manager, []string{"first.example.com", "second.example.com"}, nil)

	// A renewal that changes the hostname replaces the old certificate.
	api.send("MODIFIED", testTLSSecret(t, "shop", "shop-tls", "renewed.example.com"))
	waitForCertificates(t, manager, []string{"renewed.example.com", "second.example.com"}, []string{"first.example.com"})

	api.send("DELETED", testTLSSecret(t, "blog", "blog-tls", "second.example.com"))
	waitForCertificates(t, manager, []string{"renewed.example.com"}, []string{"second.example.com"})
}

func TestKubernetesSecretsListAgainWhenWatchExpires(t *testing.T) {
	api := newFakeKubernetesAPI(t)
	api.secrets = []kubernetesSecret{testTLSSecret(t, "shop", "shop-tls", "first.example.com")}
	api.expired = true

	manager := New(Config{Kubernetes: api.config(t)})
	t.Cleanup(manager.Stop)

	// The Secret changes while no watch is open; only a new list sees it.
	api.mu.Lock()
	api.secrets = []kubernetesSecret{testTLSSecret(t, "shop", "shop-tls", "second.example.com")}
	api.mu.Unlock()

	waitForCertificates(t, manager, []string{"second.example.com"}, []string{"first.example.com"})
}

func TestKubernetesSecretsUnreadableAtStartup(t *testing.T) {
	api := newFakeKubernetesAPI(t)
	config := api.config(t)
	api.token = "another-token"

	manager := New(Config{Kubernetes: config})
	t.Cleanup(manager.Stop)

	if manager.KubernetesSynced() {
		t.Fatal("KubernetesSynced() = true although the API rejected the token")
	}
	if got := manager.HostnameCount(); got != 0 {
		t.Errorf("HostnameCount() = %d, want 0", got)
	}
}

func TestKubernetesApplyIgnoresUnchangedCertificates(t *testing.T) {
	secrets, err := newKubernetesSecrets(KubernetesConfig{APIServer: "https://kubernetes.invalid"})
	if err != nil {
		t.Fatalf("newKubernetesSecrets: %v", err)
	}
	secret := testTLSSecret(t, "shop", "shop-tls", "shop.example.com")

	if !secrets.apply("ADDED", secret) {
		t.Error("a new Secret did not count as a change")
	}
	secret.Metadata.ResourceVersion = "202"
	if secrets.apply("MODIFIED", secret) {
		t.Error("a Secret with the same certificate counted as a change")
	}
	if secrets.resourceVersion != "202" {
		t.Errorf("resourceVersion = %q, want 202", secrets.resourceVersion)
	}
	if secrets.apply("BOOKMARK", kubernetesSecret{Metadata: kubernetesObjectMeta{ResourceVersion: "303"}}) {
		t.Error("a bookmark counted as a change")
	}
	if secrets.resourceVersion != "303" {
		t.Errorf("resourceVersion = %q, want 303", secrets.resourceVersion)
	}
}
