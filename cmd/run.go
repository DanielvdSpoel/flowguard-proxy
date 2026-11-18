package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/logfile"
	"go.chief.tools/flowguard-proxy/proxy"
	"go.chief.tools/flowguard-proxy/systemdnotify"
	"go.chief.tools/flowguard-proxy/updater"

	"github.com/spf13/cobra"
)

var (
	// Run command specific flags
	bindAddrs            string
	httpPort             string
	httpsPort            string
	noRedirect           bool
	upstreamClientIPMode string
	upstreamAddress      string
	upstreamHTTPPort     string
	upstreamHTTPSPort    string
	kubernetesCerts      bool
	shutdownTimeout      time.Duration
	logFile              string
)

// hostKeyEnv holds the host key on hosts that are not set up with
// `flowguard setup`, such as containers.
const hostKeyEnv = "FLOWGUARD_KEY"

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the proxy server",
	Long: `Start the FlowGuard reverse proxy server.

The proxy will intercept HTTP/HTTPS traffic and apply security filtering based on
the configured rules. By default, it sets up iptables rules to redirect traffic from
ports 80/443 to the proxy ports (11080/11443).

When FLOWGUARD_KEY holds a host key and the configuration file does not exist
yet, or belongs to another host key, the configuration is downloaded first.
This replaces "flowguard setup" in containers.`,
	Run: func(cmd *cobra.Command, args []string) {
		runProxy()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Run-specific flags
	runCmd.Flags().StringVar(&bindAddrs, "bind", "", "Comma-separated list of IP addresses to bind to (default: server.bind_addresses, else auto-detect public IPs)")
	runCmd.Flags().StringVar(&httpPort, "http-port", "11080", "Port for HTTP proxy server")
	runCmd.Flags().StringVar(&httpsPort, "https-port", "11443", "Port for HTTPS proxy server")
	runCmd.Flags().BoolVar(&noRedirect, "no-redirect", false, "Skip iptables port redirection setup")
	runCmd.Flags().StringVar(&upstreamClientIPMode, "upstream-client-ip-mode", "", "Override upstream client IP mode (headers or transparent)")
	runCmd.Flags().StringVar(&upstreamAddress, "upstream-address", "", "Address of the backend, such as 127.0.0.1 (default: the bind address); headers mode only")
	runCmd.Flags().StringVar(&upstreamHTTPPort, "upstream-http-port", "", "Port of the backend for HTTP (default: 80)")
	runCmd.Flags().StringVar(&upstreamHTTPSPort, "upstream-https-port", "", "Port of the backend for HTTPS (default: 443)")
	runCmd.Flags().BoolVar(&kubernetesCerts, "kubernetes-certificates", false, "Load certificates from the cluster's TLS Secrets, using the pod's service account")
	runCmd.Flags().DurationVar(&shutdownTimeout, "shutdown-timeout", proxy.DefaultShutdownTimeout, "How long to let in-flight requests finish on shutdown before closing remaining connections, including WebSockets")
	runCmd.Flags().StringVar(&logFile, "log-file", "", "Log to this file with size-capped rotation instead of stderr (for hosts without systemd)")
}

func runProxy() {
	var processLog *logfile.RotatingFile
	if logFile != "" {
		var err error
		if processLog, err = logfile.Setup(logFile); err != nil {
			log.Fatalf("Failed to open log file %s: %v", logFile, err)
		}
		defer processLog.Close()
	}

	log.Printf("FlowGuard version %s", GetVersion())

	if err := validateUpstreamFlags(); err != nil {
		log.Fatalf("[proxy] %v", err)
	}

	// Download the configuration on hosts that are set up with a host key in
	// the environment instead of `flowguard setup`
	if hostKey := strings.TrimSpace(os.Getenv(hostKeyEnv)); hostKey != "" {
		if err := config.Bootstrap(configFile, hostKey, GetUserAgent()); err != nil {
			log.Printf("[config] Failed to download the configuration for the host key in %s: %v", hostKeyEnv, err)
			os.Exit(1)
		}
	}

	// Load configuration
	configMgr, err := config.NewManager(configFile, GetUserAgent(), GetVersion(), cacheDir, verbose)
	if err != nil {
		log.Printf("[config] Failed to load configuration from %s: %v", configFile, err)
		os.Exit(1)
	}

	err = configMgr.RefreshFromAPI(false)
	if err != nil {
		log.Printf("[config] Warning: Failed to refresh configuration from API: %v", err)
	}

	// Check for post-upgrade state (rollback if previous upgrade failed)
	u, uErr := updater.New(GetVersion(), cacheDir, verbose)
	if uErr != nil {
		if verbose {
			log.Printf("[updater] Package upgrades unavailable: %v", uErr)
		}
	} else {
		if err := u.CheckPostUpgrade(); err != nil {
			log.Printf("[updater] Post-upgrade check failed: %v", err)
		}
	}

	// Create and start proxy manager
	proxyManager, err := proxy.NewManager(configMgr, &proxy.Config{
		Verbose:              verbose,
		Version:              GetVersion(),
		HTTPPort:             httpPort,
		HTTPSPort:            httpsPort,
		BindAddrs:            parseBindAddrsList(bindAddrs),
		UserAgent:            GetUserAgent(),
		NoRedirect:           noRedirect,
		UpstreamClientIPMode: upstreamClientIPMode,
		UpstreamAddress:      upstreamAddress,
		UpstreamHTTPPort:     upstreamHTTPPort,
		UpstreamHTTPSPort:    upstreamHTTPSPort,

		KubernetesCertificates: kubernetesCerts,

		Updater:         u,
		ShutdownTimeout: shutdownTimeout,
	})
	if err != nil {
		log.Fatalf("[proxy] Failed to initialize: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// systemd's ExecReload sends SIGHUP. Without a handler SIGHUP terminates the
	// process without removing the port redirects, so reload configuration the
	// same way startup loads it instead.
	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)
	go func() {
		for range reloadChan {
			// SIGHUP also follows a log file that was rotated away
			if processLog != nil {
				if err := processLog.Reopen(); err != nil {
					log.Printf("Failed to reopen log file %s: %v", logFile, err)
				}
			}

			log.Println("[config] Received SIGHUP, reloading configuration...")
			if err := configMgr.RefreshFromAPI(false); err != nil {
				log.Printf("[config] Warning: Failed to refresh configuration from API: %v", err)
			}
			if err := configMgr.Load(); err != nil {
				log.Printf("[config] Failed to reload configuration: %v", err)
				continue
			}
			log.Println("[config] Configuration reloaded successfully")
		}
	}()

	if err := proxyManager.Start(); err != nil {
		// If we fail to start, attempt to shut down any started servers
		if shutdownErr := proxyManager.Shutdown(); shutdownErr != nil {
			log.Printf("[proxy] Shutdown error: %v", shutdownErr)
		}

		log.Fatalf("[proxy] Failed to start: %v", err)
	}

	status := proxyManager.StatusMessage()
	if err := systemdnotify.NotifyReady(status); err != nil && verbose {
		log.Printf("[systemd] Failed to notify readiness: %v", err)
	}

	log.Println(status)

	select {
	case sig := <-sigChan:
		if err := systemdnotify.NotifyStopping("Received signal: " + sig.String()); err != nil && verbose {
			log.Printf("[systemd] Failed to notify stopping state: %v", err)
		}
	case err := <-proxyManager.Errors():
		if notifyErr := systemdnotify.NotifyStopping("Proxy runtime failure: " + err.Error()); notifyErr != nil && verbose {
			log.Printf("[systemd] Failed to notify stopping state: %v", notifyErr)
		}
		if shutdownErr := proxyManager.Shutdown(); shutdownErr != nil {
			log.Printf("[proxy] Shutdown error: %v", shutdownErr)
		}
		log.Fatalf("[proxy] Runtime failure: %v", err)
	}

	if err := proxyManager.Shutdown(); err != nil {
		log.Printf("[proxy] Shutdown error: %v", err)
	}
}

func parseBindAddrsList(list string) []string {
	if list == "" {
		return nil
	}

	addrs := strings.Split(list, ",")
	for i, addr := range addrs {
		addrs[i] = strings.TrimSpace(addr)
	}

	return addrs
}

// validateUpstreamFlags checks the backend address and ports given on the
// command line.
func validateUpstreamFlags() error {
	if upstreamAddress != "" && net.ParseIP(upstreamAddress) == nil {
		return fmt.Errorf("--upstream-address must be an IP address, got %q", upstreamAddress)
	}

	for flag, port := range map[string]string{
		"--upstream-http-port":  upstreamHTTPPort,
		"--upstream-https-port": upstreamHTTPSPort,
	} {
		if port == "" {
			continue
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("%s must be a port number between 1 and 65535, got %q", flag, port)
		}
	}

	return nil
}
