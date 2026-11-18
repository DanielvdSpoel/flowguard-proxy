package certmanager

import (
	"bytes"
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
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	kubernetesServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	kubernetesTLSSecretType     = "kubernetes.io/tls"
	kubernetesListPageSize      = "200"
	kubernetesListTimeout       = 30 * time.Second
	kubernetesWatchTimeout      = 5 * time.Minute
	kubernetesRetryMin          = time.Second
	kubernetesRetryMax          = 30 * time.Second
	kubernetesReloadDebounce    = 100 * time.Millisecond
)

// KubernetesConfig says how to reach the Kubernetes API to read the cluster's
// TLS Secrets, such as the ones cert-manager writes for Ingresses.
type KubernetesConfig struct {
	// APIServer is the base URL of the API server, such as https://10.0.0.1:443.
	APIServer string
	// TokenPath is the service account token file. It is read for each
	// request, because the kubelet rotates it.
	TokenPath string
	// CAPath is the CA bundle that signs the API server's certificate.
	CAPath string
}

// InClusterKubernetesConfig returns the configuration of the pod FlowGuard
// runs in, from the environment and files the kubelet gives every pod.
func InClusterKubernetesConfig() (*KubernetesConfig, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set; FlowGuard is not running in a Kubernetes pod")
	}

	return &KubernetesConfig{
		APIServer: "https://" + net.JoinHostPort(host, port),
		TokenPath: kubernetesServiceAccountDir + "/token",
		CAPath:    kubernetesServiceAccountDir + "/ca.crt",
	}, nil
}

// kubernetesTLSSecret is the certificate material of one TLS Secret.
type kubernetesTLSSecret struct {
	// id is "namespace/name".
	id          string
	certificate []byte
	key         []byte
}

// kubernetesSecrets keeps the cluster's TLS Secrets in memory, from one list
// request followed by a watch.
type kubernetesSecrets struct {
	config KubernetesConfig
	client *http.Client

	mu              sync.RWMutex
	secrets         map[string]kubernetesTLSSecret
	synced          bool
	resourceVersion string
}

type kubernetesObjectMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion"`
}

type kubernetesSecret struct {
	Metadata kubernetesObjectMeta `json:"metadata"`
	Type     string               `json:"type"`
	// encoding/json decodes the base64 values.
	Data map[string][]byte `json:"data"`
}

type kubernetesSecretList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []kubernetesSecret `json:"items"`
}

type kubernetesWatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

type kubernetesStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// errKubernetesResourceExpired means the watch's resource version is too old
// for the API server, so the Secrets must be listed again.
var errKubernetesResourceExpired = errors.New("resource version expired")

func newKubernetesSecrets(config KubernetesConfig) (*kubernetesSecrets, error) {
	if _, err := url.Parse(config.APIServer); err != nil || config.APIServer == "" {
		return nil, fmt.Errorf("invalid Kubernetes API server %q", config.APIServer)
	}

	// The default transport would use HTTP_PROXY for the in-cluster address
	// and trust the public roots instead of the cluster's CA.
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if config.CAPath != "" {
		caPEM, err := os.ReadFile(config.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes CA bundle: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("Kubernetes CA bundle %s holds no certificates", config.CAPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}

	return &kubernetesSecrets{
		config:  config,
		client:  &http.Client{Transport: transport},
		secrets: make(map[string]kubernetesTLSSecret),
	}, nil
}

// isSynced reports whether the Secrets were listed successfully at least once.
func (k *kubernetesSecrets) isSynced() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.synced
}

// snapshot returns the known TLS Secrets, ordered by namespace and name.
func (k *kubernetesSecrets) snapshot() []kubernetesTLSSecret {
	k.mu.RLock()
	defer k.mu.RUnlock()

	secrets := make([]kubernetesTLSSecret, 0, len(k.secrets))
	for _, secret := range k.secrets {
		secrets = append(secrets, secret)
	}
	slices.SortFunc(secrets, func(a, b kubernetesTLSSecret) int {
		return strings.Compare(a.id, b.id)
	})
	return secrets
}

func (k *kubernetesSecrets) get(ctx context.Context, query url.Values) (*http.Response, error) {
	query.Set("fieldSelector", "type="+kubernetesTLSSecretType)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(k.config.APIServer, "/")+"/api/v1/secrets?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if k.config.TokenPath != "" {
		token, err := os.ReadFile(k.config.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("read service account token: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(token)))
	}

	response, err := k.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return response, nil
	}

	defer response.Body.Close()
	if response.StatusCode == http.StatusGone {
		return nil, errKubernetesResourceExpired
	}
	var status kubernetesStatus
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if json.Unmarshal(body, &status) == nil && status.Message != "" {
		return nil, fmt.Errorf("Kubernetes API returned %d: %s", response.StatusCode, status.Message)
	}
	return nil, fmt.Errorf("Kubernetes API returned %s", response.Status)
}

// list replaces the known Secrets with the cluster's current TLS Secrets.
func (k *kubernetesSecrets) list(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, kubernetesListTimeout)
	defer cancel()

	secrets := make(map[string]kubernetesTLSSecret)
	resourceVersion := ""
	next := ""
	for {
		query := url.Values{"limit": {kubernetesListPageSize}}
		if next != "" {
			query.Set("continue", next)
		}

		response, err := k.get(ctx, query)
		if err != nil {
			return err
		}
		var page kubernetesSecretList
		err = json.NewDecoder(response.Body).Decode(&page)
		response.Body.Close()
		if err != nil {
			return fmt.Errorf("parse Secret list: %w", err)
		}

		for _, item := range page.Items {
			if secret, ok := tlsSecretFrom(item); ok {
				secrets[secret.id] = secret
			}
		}
		resourceVersion = page.Metadata.ResourceVersion
		next = page.Metadata.Continue
		if next == "" {
			break
		}
	}

	k.mu.Lock()
	k.secrets = secrets
	k.synced = true
	k.resourceVersion = resourceVersion
	k.mu.Unlock()
	return nil
}

// watch applies changes to the known Secrets until the API server ends the
// watch, which it does regularly, or the watch fails. It calls changed after
// each change to the certificate material.
func (k *kubernetesSecrets) watch(ctx context.Context, changed func()) error {
	k.mu.RLock()
	resourceVersion := k.resourceVersion
	k.mu.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, kubernetesWatchTimeout+30*time.Second)
	defer cancel()

	response, err := k.get(ctx, url.Values{
		"watch":               {"true"},
		"allowWatchBookmarks": {"true"},
		"resourceVersion":     {resourceVersion},
		"timeoutSeconds":      {fmt.Sprint(int(kubernetesWatchTimeout.Seconds()))},
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()

	decoder := json.NewDecoder(response.Body)
	for {
		var event kubernetesWatchEvent
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if event.Type == "ERROR" {
			var status kubernetesStatus
			_ = json.Unmarshal(event.Object, &status)
			if status.Code == http.StatusGone {
				return errKubernetesResourceExpired
			}
			return fmt.Errorf("watch failed: %s", status.Message)
		}

		var item kubernetesSecret
		if err := json.Unmarshal(event.Object, &item); err != nil {
			return fmt.Errorf("parse watch event: %w", err)
		}
		if k.apply(event.Type, item) {
			changed()
		}
	}
}

// apply records one watch event and reports whether certificate material
// changed.
func (k *kubernetesSecrets) apply(eventType string, item kubernetesSecret) bool {
	k.mu.Lock()
	defer k.mu.Unlock()

	if item.Metadata.ResourceVersion != "" {
		k.resourceVersion = item.Metadata.ResourceVersion
	}

	id := item.Metadata.Namespace + "/" + item.Metadata.Name
	previous, known := k.secrets[id]

	switch eventType {
	case "ADDED", "MODIFIED":
		secret, ok := tlsSecretFrom(item)
		if !ok {
			// The Secret lost its certificate or key.
			delete(k.secrets, id)
			return known
		}
		if known && bytes.Equal(previous.certificate, secret.certificate) && bytes.Equal(previous.key, secret.key) {
			return false
		}
		k.secrets[id] = secret
		return true
	case "DELETED":
		delete(k.secrets, id)
		return known
	}

	// BOOKMARK only moves the resource version forward.
	return false
}

// run keeps the Secrets up to date until stop is closed.
func (k *kubernetesSecrets) run(stop <-chan struct{}, changed func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	retry := kubernetesRetryMin
	relist := !k.isSynced()
	for ctx.Err() == nil {
		var err error
		if relist {
			if err = k.list(ctx); err == nil {
				relist = false
				changed()
			}
		} else {
			err = k.watch(ctx, changed)
		}

		if err == nil {
			retry = kubernetesRetryMin
			continue
		}
		if ctx.Err() != nil {
			return
		}

		// A watch that failed may have missed events, so list again.
		relist = true
		if errors.Is(err, errKubernetesResourceExpired) {
			continue
		}

		log.Printf("[cert_manager] Reading Kubernetes TLS Secrets failed, retrying in %s: %v", retry, err)
		select {
		case <-time.After(retry):
		case <-ctx.Done():
			return
		}
		retry = min(retry*2, kubernetesRetryMax)
	}
}

func tlsSecretFrom(item kubernetesSecret) (kubernetesTLSSecret, bool) {
	certificate := item.Data["tls.crt"]
	key := item.Data["tls.key"]
	if item.Type != kubernetesTLSSecretType || len(certificate) == 0 || len(key) == 0 {
		return kubernetesTLSSecret{}, false
	}

	return kubernetesTLSSecret{
		id:          item.Metadata.Namespace + "/" + item.Metadata.Name,
		certificate: certificate,
		key:         key,
	}, true
}

// loadKubernetesSecret parses one TLS Secret. It returns nil when the Secret
// cannot be parsed, is expired, or names no valid hostname.
func (cm *Manager) loadKubernetesSecret(secret kubernetesTLSSecret, verbose bool) (*certificateWithMetadata, []string) {
	source := "kubernetes:" + secret.id

	combinedPEM := slices.Concat(secret.certificate, []byte("\n"), secret.key)
	cert, err := cm.parseCombinedPEM(combinedPEM)
	if err != nil {
		if verbose {
			log.Printf("[cert_manager] Failed to parse certificate in Secret %s: %v", secret.id, err)
		}
		return nil, nil
	}
	if cert.Leaf == nil {
		return nil, nil
	}

	if time.Now().After(cert.Leaf.NotAfter) {
		if verbose {
			log.Printf("[cert_manager] Skipping expired certificate in Secret %s (expired %s)", secret.id, cert.Leaf.NotAfter.Format("2006-01-02"))
		}
		return nil, nil
	}

	hostnames := cm.getCertificateHostnames(cert.Leaf)
	if len(hostnames) == 0 {
		return nil, nil
	}

	return cm.extractCertificateMetadata(cert, source, hostnames), hostnames
}

// watchKubernetes reloads the certificates when a TLS Secret changes.
func (cm *Manager) watchKubernetes() {
	changes := make(chan struct{}, 1)
	go cm.kubernetes.run(cm.stopChan, func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	})

	for {
		select {
		case <-changes:
			// cert-manager and similar tools change several Secrets at once.
			select {
			case <-time.After(kubernetesReloadDebounce):
			case <-cm.stopChan:
				return
			}
			select {
			case <-changes:
			default:
			}
			cm.loadAllCertificates(false)
		case <-cm.stopChan:
			return
		}
	}
}
