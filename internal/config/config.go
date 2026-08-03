package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type DatabaseConfig struct {
	Host             string        `yaml:"host" env:"POSTGRES_HOST" env-default:"localhost"`
	Port             string        `yaml:"port" env:"POSTGRES_PORT" env-default:"5433"`
	User             string        `yaml:"user" env:"POSTGRES_USER" env-default:"sprezz_user"`
	Password         string        `yaml:"password" env:"POSTGRES_PASSWORD"`
	DBName           string        `yaml:"dbname" env:"POSTGRES_DB" env-default:"sprezz"`
	SSLMode          string        `yaml:"sslmode" env:"POSTGRES_SSLMODE" env-default:"disable"`
	StatementTimeout time.Duration `yaml:"statement_timeout" env:"POSTGRES_STATEMENT_TIMEOUT" env-default:"5s"`
}

type IdentityServerConfig struct {
	AdminTenantDomain    string        `yaml:"admin_tenant_domain" env:"ADMIN_TENANT_DOMAIN" env-default:"localhost:8100"`
	TokenPruningInterval time.Duration `yaml:"token_pruning_interval" env:"TOKEN_PRUNING_INTERVAL" env-default:"15m"`
	KeyRotationInterval  time.Duration `yaml:"key_rotation_interval" env:"KEY_ROTATION_INTERVAL" env-default:"24h"`
}

type Config struct {
	AppEnv         string               `yaml:"app_env" env:"APP_ENV" env-default:"local"`
	Port           string               `yaml:"port" env:"PORT" env-default:"8080"`
	Database       DatabaseConfig       `yaml:"database"`
	IdentityServer IdentityServerConfig `yaml:"identity_server"`
	DatabaseURL    string               `env:"DATABASE_URL"`
}

// GetDSN dynamically builds the connection string or prioritizes a raw DATABASE_URL override.
func (c *Config) GetDSN() string {
	if c.DatabaseURL != "" {
		return c.DatabaseURL
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.DBName,
		c.Database.SSLMode,
	)
}

// LoadConfig parses flags, reads the targeted YAML file, and applies system environment overrides.
func LoadConfig() (*Config, error) {
	var cfg Config

	// 1. Check for command-line parameter first (-env=dev)
	var envFlag string
	flag.StringVar(&envFlag, "env", "", "Target environment profile (e.g. local, dev, production)")
	flag.Parse()

	// 2. Fall back to the APP_ENV environment variable if the CLI flag is blank
	targetEnv := envFlag
	if targetEnv == "" {
		targetEnv = os.Getenv("APP_ENV")
	}
	if targetEnv == "" {
		targetEnv = "local" // Default baseline profile
	}

	// Construct the canonical YAML file path name.
	yamlPath := fmt.Sprintf("%s.yaml", targetEnv)

	// 3. Execute CleanEnv hierarchy processing:
	// It reads the yaml file first, then scans active environment variables to override values.
	if _, err := os.Stat(yamlPath); err == nil {
		if err := cleanenv.ReadConfig(yamlPath, &cfg); err != nil {
			return nil, fmt.Errorf("failed to process config file %s: %w", yamlPath, err)
		}
	} else {
		// If the specific file is missing, fallback to scanning environment variables directly.
		if err := cleanenv.ReadEnv(&cfg); err != nil {
			return nil, fmt.Errorf("failed to process system environment fields: %w", err)
		}
	}

	// 4. Assert core cryptographic safety rules established in the Sprezz-IDP spec.
	if cfg.Database.Password == "" && cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("invalid configuration: either POSTGRES_PASSWORD or DATABASE_URL must be explicitly set")
	}

	return &cfg, nil
}
