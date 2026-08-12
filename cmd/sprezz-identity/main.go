package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	httpadapter "sprezz-identity/internal/adapters/in/http"
	"sprezz-identity/internal/adapters/out/clock"
	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/adapters/out/logout"
	"sprezz-identity/internal/adapters/out/postgres"
	"sprezz-identity/internal/adapters/out/state"
	"sprezz-identity/internal/config"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

type dependencies struct {
	cfg     *config.Config
	storage *postgres.PostgresStorage
}

func main() {
	log.Println("Starting Sprezz Identity server...")
	deps := initDependencies()

	logLevel := slog.LevelInfo
	if deps.cfg.AppEnv == "local" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})))
	sysClock := clock.NewSystemClock()

	bootstrap := service.NewTenantBootstrapService(deps.storage, sysClock)
	adminTenant, err := bootstrap.BootstrapAdminTenant(context.Background(), deps.cfg.IdentityServer.AdminTenantDomain)
	if err != nil {
		log.Fatalf("Admin tenant bootstrap failed: %v", err)
	}

	signer, err := jwtcrypto.NewJWTSigner(deps.storage, deps.cfg.MasterKey)
	if err != nil {
		log.Fatalf("Failed to initialize cryptographic boundaries: %v", err)
	}

	// Start the background token and session pruning worker (15-Minute Ticks)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startTokenPruningWorker(ctx, deps.storage, deps.cfg.IdentityServer.TokenPruningInterval)
	startKeyRotationWorker(ctx, signer, deps.cfg.IdentityServer.AdminTenantDomain, deps.cfg.IdentityServer.KeyRotationInterval)

	decryptedSecret := loadOrInitializeAdminSecret(deps, adminTenant, deps.cfg.MasterKey)

	var ephemeralStore *state.EphemeralStore
	if decryptedSecret != "" {
		ephemeralStore = state.NewEphemeralStoreWithSecret(decryptedSecret)
	} else {
		ephemeralStore, err = state.NewEphemeralStore()
		if err != nil {
			log.Fatalf("Failed to generate ephemeral secret store: %v", err)
		}
	}

	notifier := logout.NewLogoutHttpClient()
	oauthService := service.NewOAuthService(deps.storage, signer, nil, notifier, sysClock)
	handler := httpadapter.NewHttpAdapter(oauthService, deps.storage, signer, sysClock, ephemeralStore)
	server := &http.Server{
		Addr:    ":" + deps.cfg.Port,
		Handler: handler.Router(),
	}
	log.Printf("Sprezz Identity server listening on :%s", deps.cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Token server terminated: %v", err)
	}
}

func loadOrInitializeAdminSecret(deps *dependencies, adminTenant *model.Tenant, masterKey string) string {
	secret := adminTenant.Config.EncryptedAdminSecret
	if masterKey != "" && secret != "" {
		decVal, err := state.DecryptAESGCM(secret, masterKey)
		if err != nil {
			log.Fatalf("Failed to decrypt administrative secret with SPREZZ_MASTER_KEY: %v", err)
		}
		return decVal
	} else if masterKey != "" && secret == "" {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			log.Fatalf("Failed to generate random secret: %v", err)
		}
		plaintextSecret := hex.EncodeToString(bytes)
		encVal, err := state.EncryptAESGCM(plaintextSecret, masterKey)
		if err != nil {
			log.Fatalf("Failed to encrypt administrative secret: %v", err)
		}
		adminTenant.Config.EncryptedAdminSecret = encVal
		if err := deps.storage.CreateTenant(context.Background(), *adminTenant); err != nil {
			log.Fatalf("Failed to save encrypted admin secret to tenant: %v", err)
		}
		return plaintextSecret
	}
	return ""
}

func startTokenPruningWorker(ctx context.Context, storage *postgres.PostgresStorage, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		log.Printf("Starting background pruning worker for expired tokens and stale sessions (interval: %v)...", interval)
		for {
			select {
			case <-ticker.C:
				if err := storage.PruneExpiredTokens(ctx); err != nil {
					log.Printf("Error during background token/session pruning: %v", err)
				} else {
					log.Println("Successfully pruned expired revoked tokens and stale sessions from database.")
				}
			case <-ctx.Done():
				ticker.Stop()
				log.Println("Pruning worker stopped.")
				return
			}
		}
	}()
}

func startKeyRotationWorker(ctx context.Context, signer port.Crypto, domain string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		log.Printf("Starting background key rotation worker (interval: %v)...", interval)
		for {
			select {
			case <-ticker.C:
				log.Printf("Triggering periodic cryptographic key rotation for tenant: %s", domain)
				if err := signer.RotateKeys(domain); err != nil {
					log.Printf("Error during background key rotation: %v", err)
				} else {
					log.Printf("Cryptographic keys successfully rotated for tenant: %s. New active key is published to JWKS.", domain)
				}
			case <-ctx.Done():
				ticker.Stop()
				log.Println("Key rotation worker stopped.")
				return
			}
		}
	}()
}

func initDependencies() *dependencies {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration bootstrap error: %v", err)
	}

	dbConfig, err := pgxpool.ParseConfig(cfg.GetDSN())
	if err != nil {
		log.Fatalf("Failed to parse postgres configuration: %v", err)
	}
	dbConfig.MaxConns = 25
	dbConfig.MinConns = 10
	dbConfig.MaxConnLifetime = 5 * time.Minute

	timeoutMs := cfg.Database.StatementTimeout.Milliseconds()
	if timeoutMs > 0 {
		dbConfig.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", timeoutMs)
	}

	log.Println("Connecting to database...")
	db, err := pgxpool.NewWithConfig(context.Background(), dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to postgres: %v", err)
	}

	if err := db.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping postgres: %v", err)
	}

	log.Println("Executing database schema migration hooks...")
	if err := postgres.RunDatabaseMigrations(context.Background(), db); err != nil {
		log.Fatalf("Critical database schema migration failure: %v", err)
	}
	log.Println("Database schemas are synchronized and verified.")

	return &dependencies{
		cfg:     cfg,
		storage: postgres.NewPostgresStorage(db),
	}
}
