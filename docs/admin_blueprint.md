# Functional Design & Specification: Sprezz Identity Admin Interface

This document establishes the definitive functional and architectural design for the **Sprezz Identity Admin Interface**. This system operates as a secure, built-in administrative dashboard utilizing the **GOTTH stack** (Go, Templ, HTMX, Tailwind, Alpine.js) and adheres strictly to **Hexagonal Architecture (Ports and Adapters)**.

The Admin UI functions as an internal OIDC client executing the Authorization Code Flow with PKCE against the root `admin` tenant of the Sprezz Identity server itself.

---

## 1. Architectural Topology & Authentication Loop

The Admin UI is fully self-contained within the Sprezz Identity Go binary, acting as an internal OpenID Connect (OIDC) client. Rather than relying on separate infrastructure or specialized backdoors, it uses standard OIDC authorization channels to authenticate its administrators.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator (Browser)
    participant AdminUI as Admin HTTP Handler (Client)
    participant IdPEngine as Sprezz IDP Engine (Provider)
    database DB as PostgreSQL DB

    Admin->>AdminUI: GET /admin
    Note over AdminUI: No active session cookie?
    AdminUI->>Admin: Redirect to /oauth/authorize (OIDC flow, PKCE, admin tenant)
    IdPEngine->>Admin: Render Login Form
    Admin->>IdPEngine: Enter Credentials
    IdPEngine->>DB: Verify & couple user profile
    IdPEngine->>Admin: 302 Redirect with Auth Code
    Admin->>AdminUI: Callback /admin/callback?code=xxx
    AdminUI->>IdPEngine: POST /oauth/token (Exchange Code + Ephemeral Secret + PKCE verifier)
    Note over IdPEngine: Authenticates "admin_ui" client<br/>using transient in-memory secret
    IdPEngine-->>AdminUI: Returns Token Set (Access, ID, Refresh)
    AdminUI->>AdminUI: Save session cookie (encrypted/secured)
    AdminUI->>Admin: Redirect to /admin/dashboard
```

---

## 2. Bootstrapping Strategy & Chicken-and-Egg Resolution

To resolve the chicken-and-egg problem of a completely empty, newly deployed instance, the server implements an automatic first-boot and in-memory lifecycle routine.

### 2.1 First-Boot Detection

On application startup, before accepting external traffic, the bootstrapping layer executes:

1. **Tenant Count Check**: Query the persistence layer to see if any tenants exist.
2. **Admin Tenant Seeding**: If no tenants exist, seed the root `admin` tenant with a domain matching the admin domain (e.g., `admin.identity.local`) and configure `allow_signup = true` in the JSONB config block.
3. **Internal Ephemeral Client Registration**: Register the `admin_ui` client with the following specific configuration:
   - `client_type = 'internal_ephemeral'`
   - `client_secret_hash = NULL` (not persisted to the database)
   - `redirect_uris = ['https://<admin-domain>/admin/callback']`
   - `allowed_scopes = ['openid', 'profile', 'email']`

### 2.2 Ephemeral Secret Lifecycle

On every single server boot (regardless of whether it is the first boot or subsequent boots):

1. **Generate Plaintext Secret**: Generate a cryptographically secure, random 32-byte hex-encoded string (64 characters) in memory.
2. **Keep Transient**: Do NOT save this secret or its hash to the database.
3. **In-Memory Storage**: Keep this transient secret in a runtime state struct accessed by:
   - The Admin UI client configuration (acting as its `client_secret` when exchanging codes).
   - The token endpoint credential validator (to verify the inbound `client_secret` for the `admin_ui` client).

### 2.3 Registration Lockdown Panel

Once the first administrator signs up via the OIDC sign-up interface and logs in, they are presented with a **Lockdown Panel** on the dashboard.

- The panel contains a toggle switch controlling public signup.
- Toggling the switch issues an HTMX `PATCH /admin/tenants/{id}/toggle-signup` request.
- The backend updates the tenant config JSONB (`allow_signup = false`).
- Subsequent signup requests are rejected, sealing the admin partition.

---

## 3. Database Schema Extensions

To support the ephemeral client type and signup configurations, the schema is extended as follows:

```sql
-- Client type and secret configuration
-- 1. Ensure `client_secret_hash` is NULLABLE.
-- 2. Add client_type check constraint or enum ('public', 'confidential', 'internal_ephemeral').
ALTER TABLE oauth_clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential'
  CONSTRAINT chk_client_type CHECK (client_type IN ('public', 'confidential', 'internal_ephemeral'));

ALTER TABLE oauth_clients ALTER COLUMN client_secret_hash DROP NOT NULL;

-- Ensure that internal_ephemeral client type has a null secret hash in database
ALTER TABLE oauth_clients ADD CONSTRAINT chk_ephemeral_null_secret
  CHECK (client_type <> 'internal_ephemeral' OR client_secret_hash IS NULL);

-- Extend Tenant Config JSONB structure to contain 'allow_signup' boolean flag
-- Example tenant config JSON representation:
-- {
--   "predefined_scopes": ["openid", "profile", "email"],
--   "predefined_audiences": [],
--   "default_redirect_uri": "https://admin.identity.local/admin",
--   "redirect_whitelist": ["https://admin.identity.local/admin"],
--   "allow_signup": true
-- }
```

---

## 4. OIDC Token Verification & Middleware Update

Standard clients require matching database hashes for their secrets. To support `internal_ephemeral` clients:

1. **Credential Interception**: During client authentication (`/oauth/token`), look up the client registration from storage.
2. **Type Evaluation**: If the client's `client_type` is `'internal_ephemeral'`:
   - Bypass the standard password/hash verification against the database.
   - Assert that the incoming `client_secret` matches the transient in-memory secret exactly.
   - If it matches, client authentication succeeds.

---

## 5. Hexagonal Architecture Compliance & Boundaries

The implementation strictly honors the hexagonal domain boundaries.

```text
internal/
├── domain/
│   ├── model/
│   │   ├── tenant.go                  # Added AllowSignup bool to TenantConfig
│   │   └── client_application.go      # Added ClientType enum ('public', 'confidential', 'internal_ephemeral')
│   ├── port/
│   │   └── admin_state.go             # Contract representing runtime ephemeral admin state
│   └── service/
│       ├── tenant_bootstrap_service.go # Seeding and first-boot logic
│       └── oauth_validator.go         # Token/Client credentials validator updated
└── adapters/
    ├── in/
    │   └── http/
    │       ├── admin_handler.go       # Admin UI views and HTMX action processing (GET/PATCH/POST)
    │       └── handler.go             # Route wiring and credential validator injection
    └── out/
        └── state/
            └── ephemeral_store.go     # Thread-safe in-memory store for the ephemeral secret
```

---

## 6. Reusable UI Component Library (`/views/admin/`)

Using type-safe `templ` components, Tailwind CSS, and Alpine.js, we construct the Admin UI layout and widgets:

- **`AdminLayout(title string)`**: Responsive side-nav layout in `slate-900`/`slate-300`, global profile actions, dynamic modals, and container slots.
- **`InputField(label, name, type, value, error string)`**: Form inputs styled with focus rings (`focus:ring-2 focus:ring-blue-500`) and standard error displays.
- **`StatusBadge(isActive bool)`**: Dynamic visual indicators utilizing `templ.KV` Tailwind mapping to reflect active (green) and inactive (red) configurations.
- **`Modal(title, fetchUrl string)`**: Alpine.js managed modal overlay (`x-data="{ isOpen: false }"`, `@click.outside`) incorporating HTMX lazy-loading (`hx-get`) to fetch administrative sub-forms dynamically into a `#modal-body` container.

---

## 7. Performance & Quality Targets

- **Cognitive Complexity**: No Go function in handlers or services must exceed **15** in cognitive complexity. Large structures should be broken down into clean, testable sub-functions.
- **Unit Testing**: 100% path coverage for the ephemeral authentication bypass, bootstrapping logic, and configuration updates.
- **Error Formatting**: Error messages remain strictly compliant with `.clinerules` (e.g. lowercase strings without punctuation).
