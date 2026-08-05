# Functional Design & Specification: Sprezz Identity Admin Interface

This document establishes the definitive functional and architectural design for the **Sprezz Identity Admin Interface**. This system operates as a secure, built-in administrative dashboard utilizing the **GOTTH stack** (Go, Templ, HTMX, Tailwind, Alpine.js) and adheres strictly to **Hexagonal Architecture (Ports and Adapters)**.

The Admin UI functions as an internal OIDC client executing the Authorization Code Flow with PKCE against the root `admin` tenant of the Sprezz Identity server itself.

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

## 3. OIDC Token Verification & Middleware Update

Standard clients require matching database hashes for their secrets. To support `internal_ephemeral` clients:

1. **Credential Interception**: During client authentication (`/oauth/token`), look up the client registration from storage.
2. **Type Evaluation**: If the client's `client_type` is `'internal_ephemeral'`:
   - Bypass the standard password/hash verification against the database.
   - Assert that the incoming `client_secret` matches the transient in-memory secret exactly.
   - If it matches, client authentication succeeds.

## 4. Hexagonal Architecture Compliance & Boundaries

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
│       ├── tenant_service.go          # Core Tenant CRUD & update operations
│       ├── client_service.go          # Core Client CRUD & update operations
│       ├── user_profile_service.go    # User Profile management & decoupling
│       ├── identity_provider_service.go # Identity Provider CRUD & update operations
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

## 5. Reusable UI Component Library (`/views/admin/`)

Using type-safe `templ` components, Tailwind CSS, and Alpine.js, we construct the Admin UI layout and widgets:

- **`AdminLayout(title string)`**: Responsive side-nav layout in `slate-900`/`slate-300`, global profile actions, dynamic modals, and container slots. Refactored to utilize a declarative struct slice (`[]NavItem`) looping over uniform navigation definitions cleanly, and featuring HTMX targeted routing.
- **`InputField(label, name, type, value, error string)`**: Form inputs styled with focus rings (`focus:ring-2 focus:ring-blue-500`) and standard error displays.
- **`StatusBadge(isActive bool)`**: Dynamic visual indicators utilizing `templ.KV` Tailwind mapping to reflect active (green) and inactive (red) configurations.
- **`Modal(title, fetchUrl string)`**: Alpine.js managed modal overlay (`x-data="{ isOpen: true }"`) incorporating HTMX lazy-loading (`hx-get`) to fetch administrative sub-forms dynamically into a `#modal-body` container. It resolves DOM accumulation and ID collisions by utilizing a CSP-compliant `setTimeout(purgeModal, 200, $root)` handler to cleanly remove the stale modal wrapper from `#modal-container` after transitions finish.

## 5.2 Strict Content Security Policy & Global Nonced Helpers

Because the server runs under a strict Content Security Policy (CSP), we utilize the CSP-friendly build of Alpine (`@alpinejs/csp`). This build uses a customized, lightweight parser that blocks closures (`() => {}`), watches, and arrow functions inside HTML attributes to prevent execution of unvalidated inline scripts.

To support complex UI lifecycles (like modal transition fades followed by node removal) under these constraints, the system implements the **Global Nonced Helper Pattern**:

1. **Secure Execution**: A secure helper script block is rendered in the `<head>` of `@AdminLayout`, locked to a cryptographically secure, per-request `nonce`:

   ```html
   <script nonce={ templ.GetNonce(ctx) }>
       function purgeModal(el) {
           el.dispatchEvent(new CustomEvent('modal-close', { bubbles: true }));
           el.remove();
       }
   </script>
   ```

2. **Standard parameterization**: Inside elements, rather than utilizing arrow functions, standard function pointers are forwarded to the browser's native `setTimeout` utility (e.g., `setTimeout(purgeModal, 200, $root)`). The CSP parser permits this flat method execution, resulting in safe, zero-eval lifecycle management.

### 5.2.1 Scope Inheritance and Flat Callback Pattern

When designing nested forms or complex multi-component configuration pages, the standard Alpine practice of referencing variables from parent data scopes or utilizing complex JavaScript getters (e.g., `get isInvalid() { ... }`) inside element attributes is completely blocked by `@alpinejs/csp`.

To maintain full compliance, prevent parser deadlocks, and eliminate redundant window event overhead:

1. **Scope Inheritance**: Since nested sub-components (such as `ClientIdentitySection` and `ClientGrantTypesSection`) reside directly inside the parent `<form>` layout tag, they inherit the `clientFormManager` parent scope natively.
2. **Flat Callback Redirection**: Instead of using semicolon statement chaining, multi-expression assignments, or inline `$dispatch` magic tokens inside HTML attributes (which the CSP parser blocks), child nodes directly invoke the inherited flat methods:
   - Client Type: `@change="handleClientType($el.value)"`
   - Authorization Code checkbox: `@change="handleAuthCodeChange($el.checked)"`
   - Client Credentials checkbox: `@change="handleClientCredentialsChange($el.checked)"`
3. **Internal Event Dispatching**: Any necessary cross-component notifications are dispatched from within the compiled JavaScript context of the manager method itself using `this.$dispatch` securely (e.g., `this.$dispatch('grant-type-change', { authCode: checked });`). This keeps our HTML markup perfectly flat, simple, and 100% compliant under strict Content Security Policies.

## 5.1 HTMX Partial Render Loop & SPA Architecture

To minimize network payload sizes and prevent high-friction layout repaints on desktop transitions, the administration portal employs a hypermedia partial render design:

1. **Stateful Navigation**: Sidebar navigation links utilize `hx-get` targeting the main `<main>` container, coupled with `hx-swap="innerHTML"` and `hx-push-url="true"` to dynamically alter browser history cleanly.
2. **Tab Highlighting**: Selected tab states are tracked entirely on the client side via Alpine's CSP-friendly `currentTab` reactive string parameter, updating visually in real-time.
3. **Hypermedia Detection**: Route handlers check for the presence of the `HX-Request == "true"` request header:
   - If present, the handler bypasses `@AdminLayout` wrapping and returns only the core page fragment component (`TenantsContent`, `ClientsContent`, `IDPsContent`, or `UsersContent`).
   - If absent (direct hit / browser refresh), the handler wraps the fragment inside the full layout block to ensure independent addressability.

## 6. Terminology Layer Adjustments (Clients to Applications)

To simplify the interface for end administrators while preserving strict conformance with the OpenID Connect (OIDC) specification, a clean mapping is applied between the domain models and the visual HTML/UI layer:

1. **Sidebar Navigation**: The sidebar navigation item is displayed as **"Applications"** (referencing the standard URL path `/admin/clients`).
2. **Page & Card Headers**: Headings are represented as **"OIDC Applications"** and the primary creation button is mapped to **"+ New Application"**.
3. **Core OIDC Fields**: The underlying technical standard terms, specifically **"Client ID"** and **"Client Secret"**, are strictly preserved as-is to remain clear and specification-compliant for developers.

## 7. Performance & Quality Targets

- **Cognitive Complexity**: No Go function in handlers or services must exceed **15** in cognitive complexity. Large structures should be broken down into clean, testable sub-functions.
- **Unit Testing**: 100% path coverage for the ephemeral authentication bypass, bootstrapping logic, and configuration updates.
- **Error Formatting**: Error messages remain strictly compliant with `.clinerules` (e.g. lowercase strings without punctuation).

## 8. Refresh Token Rotation (RTR) Integration in Admin UI

Sprezz Identity Admin UI provides interactive management toggles to control the RTR policy on applications.

### 8.1 Interactive RTR Configuration Toggle

- **The `clientFormManager` State**: The Alpine form manager (`layout.templ`) tracks the client-side `enforceRtr` state natively and updates computed states in real-time.
- **Category Mandate Locking**: If the user selects the **Public** application category, the `enforceRtr` state is automatically set to `true` and locked (the checkbox input is disabled), strictly mandating RTR for native/SPA apps.
- **Conditional Configuration**: For **Confidential** applications, the input checkbox remains unlocked, allowing administrators to optionally enable or disable Refresh Token Rotation as required.
- **Form Preservation**: When saving or validation errors occur, the backend parses `enforce_rtr` from the form payload and correctly repopulates the UI toggle state on subsequent renders.

## 9. Operational Hardening & Horizontal Scaling (UI Integration)

This section maps out how the Inbound HTTP Adapter and the frontend views interface with the core cluster and security guardrails established in **Section 13 of the Sprezz Identity Server Architecture Blueprint**.

### 9.1 Horizontally Scaled Session Resiliency

- **Backend Alignment**: Complies with Section 13.1 by eliminating local memory caching in favor of the shared PostgreSQL single source of truth.
- **UI Behavior**: Because state is centralized in the database, view components automatically reflect real-time updates (such as newly created applications or active tenant status changes) across all replica nodes seamlessly without local cache clearing latency.

### 9.2 Lockdown Interactivity & Session Purge

- **UI Action**: Toggling the "Allow Signup" switch in the lockdown panel shoots a `PATCH /admin/tenants/{id}/toggle-signup` request to the backend.
- **Security Purge**: As specified in Section 13.2, transitioning this state to `false` triggers an atomic backend transaction that blacklists all active tokens for the admin tenant partition.
- **UX Outcome**: The browser executing the toggle, along with any other concurrent administrative sessions, will immediately have their session cookies rejected on the very next HTMX request, forcing an instantaneous redirect back to the OIDC login portal for security re-authentication.

### 9.3 Environment-Aware Cookie Defenses

- **Production Mode**: To enforce Section 13.3, administrative cookies default to the absolute secure envelope: name `__Host-spz_session`, `HttpOnly = true`, `Secure = true`, and `SameSite = Lax`.
- **Local Development Loop**: To maintain local debugging fluidity on `http://localhost` without forcing local SSL configurations, the cookie-setting handler applies the environmental guard clause: if and only if the global setting `APP_ENV` is set to `"local"` AND the request host is `localhost` or `127.0.0.1`, the handler strips the `__Host-` prefix wrapper (falling back to plain `spz_session`) and flips `Secure = false`.

### 9.4 Hypermedia Semantic Validation Error Swapping

- **Semantic Error Delivery**: In compliance with Section 13.4, any form validation failure on the backend (e.g., an invalid URI or scope entry) rejects the transaction with an HTTP Status Code of `422 Unprocessable Entity`.
- **HTMX Listener Binding**: To ensure HTMX does not drop the 4xx error block and safely swaps the validation component highlights into the view layout, the master global layout shell (`@AdminLayout`) embeds the strict, nonced event listener established in Section 13.4.
