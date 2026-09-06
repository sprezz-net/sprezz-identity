package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	httpadapter "sprezz-identity/internal/adapters/in/http"
	"sprezz-identity/internal/adapters/out/clock"
	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/adapters/out/federation"
	"sprezz-identity/internal/adapters/out/logout"
	"sprezz-identity/internal/adapters/out/postgres"
	"sprezz-identity/internal/config"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

type dependencies struct {
	cfg                     *config.Config
	storage                 port.Storage
	adminStorage            port.AdminStorage
	signer                  *jwtcrypto.JWTSigner
	sysClock                port.Clock
	tenantUseCase           port.TenantUseCase
	oauthService            port.AuthUseCase
	federatedLoginService   port.FederatedLoginUseCase
	adminLogonUseCase       port.AdminLogonUseCase
	ssoService              port.SSOSessionUseCase
	userProfileUseCase      port.UserProfileUseCase
	userRegistrationUseCase port.UserRegistrationUseCase
	localAuthUseCase        port.LocalAuthUseCase
	adminApplicationUseCase port.AdminApplicationUseCase
	idpService              port.IdentityProviderUseCase
}

func main() {
	log.Println("Starting Sprezz Identity server...")

	// Create a cancelable root application context for background workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. PURE ENCAPSULATION: Load configuration, connect DB, run migrations, bootstrap tenants, and spin up workers
	deps := initDependencies(ctx)

	// 2. DECLARATIVE WIRING: Build central HttpAdapter using fully prepared dependencies
	handler := httpadapter.NewHttpAdapter(
		deps.tenantUseCase,
		deps.oauthService,
		deps.federatedLoginService,
		deps.adminLogonUseCase,
		deps.ssoService,
		deps.userProfileUseCase,
		deps.userRegistrationUseCase,
		deps.localAuthUseCase,
		deps.adminApplicationUseCase,
		deps.adminStorage,
		deps.idpService,
		deps.storage,
		deps.signer,
		deps.cfg.AppEnv,
		deps.cfg.IdentityServer.AdminTenantDomain,
	)

	server := &http.Server{
		Addr:    ":" + deps.cfg.Port,
		Handler: handler.Router(),
	}

	log.Printf("Sprezz Identity server listening on :%s", deps.cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Token server terminated: %v", err)
	}
}

func initDependencies(ctx context.Context) *dependencies {
	// 1. Load configuration file fragments
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration bootstrap error: %v", err)
	}

	// 2. Configure structured system logging parameters
	logLevel := slog.LevelInfo
	if cfg.AppEnv == "local" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})))

	sysClock := clock.NewSystemClock()

	// 3. Establish connection pool properties for PostgreSQL
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
	db, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to postgres: %v", err)
	}

	if err := db.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping postgres: %v", err)
	}

	// 4. Run database migrations to ensure table schemas match perfectly
	log.Println("Executing database schema migration hooks...")
	if err := postgres.RunDatabaseMigrations(ctx, db); err != nil {
		log.Fatalf("Critical database schema migration failure: %v", err)
	}
	log.Println("Database schemas are synchronized and verified.")

	storage := postgres.NewPostgresStorage(db, cfg.AppEnv)

	// Needed for resolution and cross-layered bootstrapping references
	idpService := service.NewIdentityProviderService(storage, storage, sysClock)
	tenantUseCase := service.NewTenantService(storage, storage, sysClock, idpService, cfg.AppEnv, cfg.IdentityServer.AdminTenantDomain)

	// 5. Execute system master data bootstrapping scripts
	bootstrap := service.NewTenantBootstrapService(storage, storage, tenantUseCase, sysClock, cfg.AppEnv)
	_, err = bootstrap.BootstrapAdminTenant(ctx, cfg.IdentityServer.AdminTenantDomain)
	if err != nil {
		log.Fatalf("Admin tenant bootstrap failed: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 6. Initialize cluster-resilient JWTSigner passing master encryption keys
	signer, err := jwtcrypto.NewJWTSigner(
		storage,
		sysClock,
		httpClient,
		cfg.MasterKey,
		cfg.IdentityServer.AdminTenantDomain,
		cfg.AppEnv,
	)
	if err != nil {
		log.Fatalf("Failed to initialize cryptographic boundaries: %v", err)
	}

	// 7. Start the continuous asynchronous background loop worker instances
	startTokenPruningWorker(ctx, storage, cfg.IdentityServer.TokenPruningInterval)
	startKeyRotationWorker(ctx, signer, cfg.IdentityServer.AdminTenantDomain, cfg.IdentityServer.KeyRotationInterval)

	notifier := logout.NewLogoutHttpClient(cfg.AppEnv)
	validator := service.NewOAuthValidatorService()

	// 8. Instantiate core domain use cases
	userProfileUseCase := service.NewUserProfileService(storage, signer, sysClock)
	userRegistrationUseCase := service.NewUserRegistrationService(storage, userProfileUseCase, sysClock)

	ssoService := service.NewSSOSessionService(storage, cfg.AppEnv)

	fedClient := federation.NewFederationHTTPAdapter(http.DefaultClient, cfg.AppEnv)
	federatedLoginService := service.NewFederationService(
		storage,
		fedClient,
		signer,
		sysClock,
	)

	oauthService := service.NewOAuthService(
		storage,
		signer,
		nil,
		notifier,
		sysClock,
		ssoService,
		validator,
	)

	localAuthService := service.NewLocalAuthService(storage, signer, sysClock)
	appService := service.NewApplicationService(storage, storage, sysClock, signer)

	adminLogonService := service.NewAdminLogonService(
		storage,
		storage,
		oauthService,
		signer,
		fedClient,
		federatedLoginService,
		sysClock,
		cfg.AppEnv,
		cfg.IdentityServer.AdminTenantDomain,
	)

	return &dependencies{
		cfg:                     cfg,
		storage:                 storage,
		adminStorage:            storage,
		signer:                  signer,
		sysClock:                sysClock,
		tenantUseCase:           tenantUseCase,
		oauthService:            oauthService,
		federatedLoginService:   federatedLoginService,
		adminLogonUseCase:       adminLogonService,
		ssoService:              ssoService,
		userProfileUseCase:      userProfileUseCase,
		userRegistrationUseCase: userRegistrationUseCase,
		localAuthUseCase:        localAuthService,
		adminApplicationUseCase: appService,
		idpService:              idpService,
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

func startKeyRotationWorker(ctx context.Context, signer port.Crypto, domain string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		log.Printf("Starting background key rotation worker (interval: %v)...", interval)
		for {
			select {
			case <-ticker.C:
				log.Printf("Triggering periodic cryptographic key rotation for tenant: %s", domain)
				if err := signer.RotateKeys(ctx, domain); err != nil {
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
