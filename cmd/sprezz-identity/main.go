package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	httpadapter "sprezz-identity/internal/adapters/in/http"
	"sprezz-identity/internal/adapters/out/clock"
	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/adapters/out/logout"
	"sprezz-identity/internal/adapters/out/postgres"
	"sprezz-identity/internal/config"
	"sprezz-identity/internal/domain/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

type dependencies struct {
	cfg     *config.Config
	storage *postgres.PostgresStorage
}

func main() {
	log.Println("Starting Sprezz token server...")

	deps := initDependencies()
	sysClock := clock.NewSystemClock()

	bootstrap := service.NewTenantBootstrapService(deps.storage, sysClock)
	if _, err := bootstrap.BootstrapAdminTenant(context.Background(), deps.cfg.IdentityServer.AdminTenantDomain); err != nil {
		log.Fatalf("Admin tenant bootstrap failed: %v", err)
	}

	// Start the background token and session pruning worker (15-Minute Ticks)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startTokenPruningWorker(ctx, deps.storage, deps.cfg.IdentityServer.TokenPruningInterval)

	signer := jwtcrypto.NewJWTSigner()
	notifier := logout.NewLogoutHttpClient()
	oauthService := service.NewOAuthService(deps.storage, signer, nil, notifier, sysClock)
	handler := httpadapter.NewHttpAdapter(oauthService, deps.storage, signer, sysClock)
	server := &http.Server{
		Addr:    ":" + deps.cfg.Port,
		Handler: handler.Router(),
	}
	log.Printf("Token server listening on :%s", deps.cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Token server terminated: %v", err)
	}
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
