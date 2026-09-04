package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/raygj/ssf-relay/actions"
	"github.com/raygj/ssf-relay/config"
	"github.com/raygj/ssf-relay/relay"
	"github.com/raygj/ssf-relay/sources"

	// Blank imports trigger init() registrations.
	_ "github.com/raygj/ssf-relay/actions/k8scordon"
	_ "github.com/raygj/ssf-relay/actions/opapolicy"
	_ "github.com/raygj/ssf-relay/actions/vault"
	_ "github.com/raygj/ssf-relay/actions/webhook"
	_ "github.com/raygj/ssf-relay/sources/k8s"
	_ "github.com/raygj/ssf-relay/sources/opa"
	_ "github.com/raygj/ssf-relay/sources/vault"
)

func main() {
	log := hclog.New(&hclog.LoggerOptions{
		Name:  "ssf-relay",
		Level: hclog.Info,
	})

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: ssf-relay <config.yaml>\n")
		os.Exit(1)
	}

	cfg, err := config.Load(os.Args[1])
	if err != nil {
		log.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Load signing key if configured; nil means unsigned delivery (backward compat).
	var signingKey *relay.SigningKey
	pemData, err := cfg.SSF.ResolveSigningKeyPEM()
	if err != nil {
		log.Error("failed to read signing key", "error", err)
		os.Exit(1)
	}
	if pemData != nil {
		signingKey, err = relay.LoadSigningKeyFromPEM(pemData)
		if err != nil {
			log.Error("failed to parse signing key", "error", err)
			os.Exit(1)
		}
		log.Info("SSF signing enabled", "kid", signingKey.KID)

		// Optional JWKS endpoint so trust receivers can fetch our public key.
		if cfg.SSF.JWKSAddr != "" {
			jwksBody := fmt.Sprintf(`{"keys":[%s]}`, signingKey.PublicJWK)
			go func() {
				mux := http.NewServeMux()
				mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, jwksBody)
				})
				log.Info("JWKS endpoint listening", "addr", cfg.SSF.JWKSAddr)
				if serveErr := http.ListenAndServe(cfg.SSF.JWKSAddr, mux); serveErr != nil {
					log.Error("JWKS server error", "error", serveErr)
				}
			}()
		}
	} else {
		log.Warn("SSF signing not configured — SETs will be delivered unsigned")
	}

	emitter := relay.NewEmitter(cfg.SSF.ReceiverURL, cfg.SSF.Issuer, cfg.SSF.TimeoutSecs, signingKey)

	mgr := relay.NewManager(cfg, log, emitter, func(typeName string, srcCfg map[string]interface{}) (relay.Source, error) {
		return sources.Build(typeName, srcCfg)
	})

	// Inbound subscriber — build action adapters from sinks config, register with router.
	router := relay.NewRouter(log)
	seen := map[string]bool{}
	for _, sink := range cfg.Sinks {
		if seen[sink.Action] {
			continue // one adapter instance per action type
		}
		seen[sink.Action] = true
		adapter, err := actions.Build(sink.Action, sink.Config)
		if err != nil {
			log.Error("failed to build action adapter", "action", sink.Action, "error", err)
			os.Exit(1)
		}
		router.Register(adapter)
	}
	sub := relay.NewSubscriber(cfg.SSF.ReceiverURL, router, log)

	log.Info("starting ssf-relay",
		"sources", len(cfg.Sources),
		"sinks", len(cfg.Sinks),
		"receiver", cfg.SSF.ReceiverURL,
	)

	// Run outbound manager and inbound subscriber concurrently.
	// Both are expected to run until ctx is cancelled; a non-nil error from
	// either is fatal. A nil return (e.g. manager with zero sources) is not
	// fatal — we keep running until the other goroutine exits.
	errCh := make(chan error, 2)
	go func() { errCh <- mgr.Run(ctx) }()
	go func() { errCh <- sub.Run(ctx) }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			log.Error("relay error", "error", err)
			os.Exit(1)
		}
	}

	log.Info("ssf-relay stopped")
}
