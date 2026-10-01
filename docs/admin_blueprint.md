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
│   ├── model/                         # tenant.go, application.go (IsSystem on every tier), federation.go
│   ├── port/
│   │   ├── admin.go                   # AdminApplicationUseCase, section Patch* commands, Create/Update/Delete commands
│   │   ├── errors.go                  # ErrSystemManaged, ErrInUse, ErrAlreadyExists, ValidationError
│   │   └── tenant.go                  # TenantUseCase incl. DeleteTenant
│   └── service/
│       ├── application_service.go     # Applications, profiles and groups; system guards; transactional secrets
│       ├── application_patch.go       # PatchGroup / PatchProfile: overlay one section, then the full validated update
│       ├── group_validation.go        # Redirect URI, scope and default rules
│       ├── profile_validation.go      # Lifetime, algorithm, auth method and grant rules
│       ├── tenant_bootstrap_service.go # Seeds the admin tenant, profile, groups and application (all is_system)
│       ├── tenant_service.go          # Tenant CRUD and guarded DeleteTenant
│       └── identity_provider_service.go
├── adapters/
│   ├── in/http/
│   │   ├── admin_middleware.go        # requireAdminSession guard for every /admin route
│   │   ├── admin_session.go           # Session resolution and cross-site request rejection
│   │   ├── admin_pages.go             # Fragment vs full page, section result mapping, parseBodyForm
│   │   ├── admin_errors.go            # Domain error to status and safe message
│   │   ├── admin_application_*.go     # Application list, detail, create, secret, delete
│   │   ├── admin_group_*.go           # Group list, detail, sections, delete
│   │   └── admin_profile_*.go         # Profile list, detail, sections, delete
│   └── out/ (postgres, memory, federation, crypto)
└── views/
    ├── admin/                         # templ pages and components
    ├── public/                        # login, signup, profile, logout, error
    └── assets/                        # Embedded, versioned static files (see section 5.3)
```

## 5. Reusable UI Component Library (`/views/admin/`)

The admin UI is built from type-safe `templ` components, compiled Tailwind and CSP-safe Alpine.js components.

- **`AdminLayout`**: side navigation from a `[]NavItem` slice, a global spinner and a modal container. Only the Tenants page still uses modals.
- **`ApplicationsSubNav`**: the Applications | Groups | Profiles tab strip. Active state comes from the route, so each tab has its own address and needs no client state.
- **`PageHeader`, `SystemBadge`, `SystemBanner`, `FlashMessage`, `EmptyState`**: page chrome. System objects always show the badge and a banner explaining why the page is read-only.
- **`SectionCard` and `SaveBar`**: one independently saved part of a detail page. Each card is its own form (`hx-put` to `.../{section}`) that swaps only itself, with "Unsaved changes" and "Saved" indicators.
- **`RedirectList`, `URLList`, `ScopePicker`, `TagListManager`, `ToggleRow`, `FieldError`**: field editors. The default redirect URI is a radio on its row and every allowed scope has a default checkbox, so a default can never point outside its list.
- **`ConfirmDelete`**: a danger zone whose button stays disabled until the typed name matches. The server checks the confirmation again. A used object shows why it cannot be deleted instead of a button.
- **`UsedBy`**: links from a group or profile to the applications that use it.
- **`StatusBadge`, `Badge`, `InputField`**: small display helpers.

### 5.1 Routes

```text
/admin/applications                      list (search q, filter type=static|dynamic)
/admin/applications/new                  create
/admin/applications/{clientID}           detail: general, policy, credentials, danger zone
/admin/applications/{clientID}/{section} PUT general | policy
/admin/applications/{clientID}/reset-secret  POST
/admin/applications/groups               list, /new, /{id}, PUT /{id}/{general|redirects|logout|scopes|signin}, DELETE /{id}
/admin/applications/profiles             list, /new, /{id}, PUT /{id}/{general|authentication|lifetimes}, DELETE /{id}
```

Static routes (`new`, `groups`, `profiles`, `generate-secret`) are registered before `/{clientID}`.

## 5.2 Strict Content Security Policy

Every script and stylesheet is served from this origin, so no third-party host is trusted. The policy (built in `buildCSP`):

```text
default-src 'self'; script-src 'self' 'nonce-<per request>'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
```

There is no `unsafe-inline` and no `unsafe-eval`. Two deliberate exceptions exist:

- `/oauth/logout` and `/logout` add `frame-src https: http:`, because the logout page embeds every client's front-channel logout URL in hidden frames.
- `/admin/logout` omits `frame-ancestors`, because the identity provider's logout page frames it. It only clears a cookie.

Responses also carry `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`, and admin responses send `Cache-Control: no-store`.

Because of this policy the UI follows these rules, which are enforced by template tests:

- No inline `<script>`, `style=""` attribute, `<style>` element or inline event handler. Behavior lives in `admin.js` and `logout.js`; hiding uses `x-cloak` and the stylesheet.
- Alpine runs in its CSP build, so attribute expressions stay simple: no arrow functions, template literals, globals or property assignments.
- Values reach components through `data-*` attributes read in `init()`, never through interpolated `x-data` expressions, so a value containing a quote cannot break out.

### 5.2.1 Scope Inheritance and Flat Callback Pattern

When designing nested forms or complex multi-component configuration pages, the standard Alpine practice of referencing variables from parent data scopes or utilizing complex JavaScript getters (e.g., `get isInvalid() { ... }`) inside element attributes is completely blocked by `@alpinejs/csp`.

To maintain full compliance, prevent parser deadlocks, and eliminate redundant window event overhead:

1. **Scope Inheritance**: Since nested sub-components reside directly inside the parent `<form>` layout tag, they inherit the parent manager (e.g., `applicationFormManager`) scope natively.
2. **Internal Event Dispatching**: Any necessary cross-component notifications are dispatched from within the compiled JavaScript context of the manager method itself using `this.$dispatch` securely (e.g., `this.$dispatch('grant-type-change', { authCode: checked });`). This keeps our HTML markup perfectly flat, simple, and 100% compliant under strict Content Security Policies.

### 5.2.2 Declarative Dataset Initialization Pattern

Under strict `@alpinejs/csp`, initializing Alpine data components with parameterized constructors containing Go interpolated dynamic variables (such as `x-data={ fmt.Sprintf("applicationFormManager('%s')", value) }`) will trigger dynamic code execution and be blocked by the browser.

To eliminate these critical CSP violations, the system enforces the **Declarative Dataset Initialization Pattern**:

1. **Zero-Argument Constructor**: Declare all Alpine data component factories with empty argument lists, registering them inside nonced script tags (e.g., `Alpine.data('applicationFormManager', () => ({ ... }))`).
2. **Data-Attributes Hydration**: Pass Go server-side configurations down to elements statelessly using native standard `data-*` fields on the parent container element.
3. **Dataset Evaluation on Initialization**: Inside the Alpine component's `init()` hook, access the configuration using `this.$el.dataset` keys directly to hydrate the local state variables.

```html
<form
    x-data="applicationFormManager"
    data-initial-auth-method={ string(props.Profile.TokenEndpointAuthMethod) }
    data-enforce-rtr={ fmt.Sprintf("%t", props.Profile.EnforceRTR) }
>
```

```javascript
Alpine.data('applicationFormManager', () => ({
    authMethod: 'client_secret_post',
    enforceRtr: false,
    init() {
        this.authMethod = this.$el.dataset.initialAuthMethod || 'client_secret_post';
        this.enforceRtr = this.$el.dataset.enforceRtr === 'true';
        this.$watch('authMethod', (val) => {
            if (val === 'none') {
                this.enforceRtr = true;
            }
        });
    }
}));
```

#### 5.2.3 Sub-Component CSP Hardening Examples

This dataset initialization constraint applies equally to all nested sub-components inside our views, ensuring **no parameterized constructor strings** are injected into HTML attributes.

##### A. Lifetime Calculator Sub-Component

To handle duration conversions for Access, ID, and Refresh Token configurations without raw inline string evaluations:

- **View Layer (`applications.templ`)**:

    ```html
    <div x-data="lifetimeCalculator" data-initial-seconds={ fmt.Sprintf("%d", int(props.Profile.AccessTokenLifetime/time.Second)) }>
        <input type="hidden" name="access_token_lifetime" :value="seconds"/>
        <!-- nested form inputs read/write this.value and this.unit -->
    </div>
    ```

- **Script Layer (`layout.templ`)**:

    ```javascript
    Alpine.data('lifetimeCalculator', () => ({
        seconds: 3600,
        value: 1,
        unit: 'hours',
        init() {
            this.seconds = parseInt(this.$el.dataset.initialSeconds) || 3600;
            const totalSec = parseInt(this.seconds) || 0;
            if (totalSec % 86400 === 0 && totalSec > 0) {
                this.value = totalSec / 86400;
                this.unit = 'days';
            } else if (totalSec % 3600 === 0 && totalSec > 0) {
                this.value = totalSec / 3600;
                this.unit = 'hours';
            } else if (totalSec % 60 === 0 && totalSec > 0) {
                this.value = totalSec / 60;
                this.unit = 'minutes';
            } else {
                this.value = totalSec;
                this.unit = 'seconds';
            }
        }
    }));
    ```

##### B. Client ID & Secret Generator

To generate safe randomized entity identifiers asynchronously:

- **View Layer (`applications.templ`)**:

    ```html
    <div x-data="idSecretGenerator" data-initial-value="">
        <input type="text" name="client_id" x-model="value" required />
    </div>
    ```

- **Script Layer (`layout.templ`)**:

    ```javascript
    Alpine.data('idSecretGenerator', () => ({
        value: '',
        showSecret: false,
        init() {
            this.value = this.$el.dataset.initialValue || '';
        },
        generate() {
            window.fetch('/admin/clients/generate-secret')
                .then(response => response.text())
                .then(text => { this.value = text; });
        }
    }));
    ```

### 5.3 Static Assets

The `assets` package embeds `app.css` (compiled Tailwind v4), `htmx.min.js` (1.9.12), `alpine-csp.min.js`, `admin.js` and `logout.js`, and serves them under `/assets/`. URLs carry a content hash (`?v=`) for one-year immutable caching. The route skips tenant resolution. `make css-gen` rebuilds the stylesheet from the templates, and the compiled file is committed so `go build` works without Tailwind installed.

htmx is configured in the page head with `allowEval`, `allowScriptTags` and `includeIndicatorStyles` off and `selfRequestsOnly` on. Delete confirmations rely on htmx 1.x sending DELETE form data in the body, and a test fails if htmx is upgraded past that assumption.

### 5.4 Hypermedia Render Loop

1. **Navigation**: sidebar, tab and list links use `hx-get` with `hx-target="main"`, `hx-swap="innerHTML"` and `hx-push-url="true"`, and keep a real `href`, so links also work without JavaScript and can be opened in a new tab.
2. **Tab highlighting**: the active Applications | Groups | Profiles tab is rendered by the server from the route (`aria-current="page"`). Only the layout's sidebar uses a small Alpine component (`adminShell`).
3. **Fragment or page**: `renderAdminPage` returns the content fragment for an htmx navigation and the complete layout for any other request, so every URL can be refreshed and bookmarked. History restores from htmx get the full page. Responses carry `Vary: HX-Request`.
4. **Section saves**: a card answers `PUT .../{section}` with that card only (`hx-target="#section-..."`, `hx-swap="outerHTML"`). Validation failures keep what the admin typed.
5. **Redirects after success**: create and delete answer with `HX-Redirect` (a full navigation) and a flash message. There is never an injected script.

## 6. Terminology Layer Adjustments (Clients to Applications)

To simplify the interface for end administrators while preserving strict conformance with the OpenID Connect (OIDC) specification, a clean mapping is applied between the domain models and the visual HTML/UI layer:

1. **Sidebar Navigation**: The sidebar navigation item is displayed as **"Applications"** (referencing the standard URL path `/admin/applications`).
2. **Page & Card Headers**: Headings are represented as **"OIDC Applications"** and the primary creation button is mapped to **"+ New Application"**.
3. **Core OIDC Fields**: The underlying technical standard terms, specifically **"Client ID"** and **"Client Secret"**, are strictly preserved as-is to remain clear and specification-compliant for developers.

## 7. Performance & Quality Targets

- **Cognitive Complexity**: No Go function in handlers or services must exceed **15** in cognitive complexity. Large structures should be broken down into clean, testable sub-functions.
- **Unit Testing**: 100% path coverage for the ephemeral authentication bypass, bootstrapping logic, and configuration updates.
- **Error Formatting**: Error messages remain strictly compliant with `.clinerules` (e.g. lowercase strings without punctuation).

## 8. Refresh Token Rotation (RTR) Integration in Admin UI

Sprezz Identity Admin UI provides interactive management toggles to control the RTR policy on applications.

### 8.1 Interactive RTR Configuration Toggle

- **The `applicationFormManager` State**: The Alpine form manager (`layout.templ`) tracks the client-side `enforceRtr` state natively and updates computed states in real-time.
- **Category Mandate Locking**: If the user selects the **Public** application category (determined by a `TokenEndpointAuthMethod` of `none`), the `enforceRtr` state is automatically set to `true` and locked (the checkbox input is disabled), strictly mandating RTR for native/SPA apps.
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

- **Semantic status codes**: a failed validation answers `422 Unprocessable Entity`, a system-managed object `403`, a missing object `404`, and a blocked delete or duplicate `409`. Unknown failures answer `500` with a generic message; the real error is only logged.
- **Swap listener**: htmx drops non-2xx responses by default. `admin.js` (loaded by `AdminLayout`) listens to `htmx:beforeSwap` and swaps a response when its status is `422` or when the server marked it with `X-Admin-Fragment: true`. The marker is set by `renderFragment` for every card or form fragment that is not a 200.
- **Field errors**: the domain returns a `ValidationError` keyed by form field name, and the handlers merge it into the card or form that failed. The key must equal the input's `name` attribute.

## 10. Multi-Partition User and Provider Isolation

Sprezz Identity supports dividing a single Tenant's space into multiple logical **Partitions**.

### 10.1 Partition-Aware Filtering & Form Controls

- **Admin Dropdown Filters**: Both the **Identity Providers** and **User Profiles** list pages in the Admin UI feature a select dropdown component matching the selected partition. Selecting a partition triggers an HTMX `GET` request reloading the content with the selected `partition_id` query parameter, filtering the data view.
- **Partition Assignment**: When creating or editing an Identity Provider or a User Profile, administrators choose which Partition the resource belongs to.
- **Validation Constraints**: Username-password IDP configurations are restricted to at most **1** per Partition.

## 11. Decoupled Three-Tier Administrative Architecture

To maximize structural flexibility and enforce strict security boundaries, the monolithic "Client Application" entity has been decomposed into a decoupled, standalone Three-Tier CRUD architecture.

### 11.1 Architectural Tier Decomposition

The system segregates application logic across three distinct, independent domain models:

1. **`Application` (Core Instance)**: Represents the high-level application registration, holding core metadata, identifier tokens (`ClientID`), status toggles, and UUID relational pointers to its current `Profile` and `Group`.
2. **`ApplicationProfile` (Security Lifetimes Policy)**: Encapsulates all transport-layer and credential validation rules, including token expiration durations (`AccessTokenLifetime`, `IDTokenLifetime`, `RefreshTokenLifetime`), signature algorithms, and authentication schemes (`TokenEndpointAuthMethod`).
3. **`ApplicationGroup` (Access Bounds Whitelisting)**: Manages routing and security constraints, including allowed OIDC scopes, upstream identity provider routings, front/back-channel single-sign-out targets, and client redirection whitelists (`RedirectURIs`).

### 11.2 Commands, Sections and Transactions

- **Separate commands per tier**: `Create/Update/Delete` commands exist for applications, profiles and groups. Each tier is edited on its own page, so no command spans tiers.
- **Section patches**: `PatchGroupCommand` and `PatchProfileCommand` name one section (`general`, `redirects`, `logout`, `scopes`, `signin` for groups; `general`, `authentication`, `lifetimes` for profiles). The service re-reads the stored object, overlays only that section and runs the same validated update as a full save. Two admins editing different cards therefore do not overwrite each other, although two edits of the same card are still last-write-wins.
- **Secrets**: creating an application and resetting its secret run inside a database transaction. The plaintext secret is written to the response from a delivery callback before the commit, and a failed write rolls the change back.
- **Enabled state**: `UpdateApplicationCommand.IsEnabled`, `UpdateGroupCommand.IsEnabled` and `UpdateProfileCommand.IsEnabled` are pointers. `nil` keeps the stored state, so an edit never re-enables a disabled object.

### 11.5 System-Managed Objects and Deletion

Bootstrap objects carry `is_system` (see the architecture blueprint, section 2.4). The services return `ErrSystemManaged` for edits, toggles, secret resets and deletes, except that the admin group accepts federated sign-in changes. Groups and profiles that applications still use return `ErrInUse`, and the database foreign key repeats that check for a concurrent change. Every delete requires the object's name (the client ID for applications) to be typed back.

### 11.3 Defensive Struct Hydration (Preventing Nil-Pointer Panics)

When returning partial form views or error validation fragments, the Go driving adapters must defensively prepare view properties to satisfy type-safe `templ` parameters:

- **The Invariant**: All empty or unitialized collections inside models (e.g., PostgreSQL arrays or list properties) must never be sent as `nil`.
- **The Guard**: Form controllers must explicitly instantiate slices as empty arrays (`RedirectURIs: []string{}`, `AllowedScopes: []string{}`) and assign default durations to prevent the templates from triggering immediate nil-pointer dereference panics when accessing or looping through properties.

### 11.4 Strict Nomenclature Segregation (Metadata vs Credentials)

To prevent lexical confusion and ensure semantic clarity, a strict separation is enforced between high-level administrative descriptors and lower-level dynamic OIDC credential values:

1. **Application-Level Descriptors (`application_*`)**: Any inputs, fields, or validation handles managing the administrative identity, name, or metadata of the registered entity MUST strictly use the phrase **`application_name`** (mapped directly onto `ApplicationName`). The word *Client* is prohibited for descriptions to ensure end-administrators are not confused by technical developer values.
2. **Credential-Level Identifiers (`client_*`)**: Dynamic tokens, keys, secrets, and protocol identifiers MUST preserve the OIDC vocabulary standard using **`client`** prefixes (e.g. `client_id`, `client_secret`, and structural mappings to `ClientID` and `ClientSecretHash`).
3. **Form-to-Handler Validation Parity**: Every administrative flow must audit form parameter namespaces for perfect symmetry. The HTML input tag's `name` attribute, the Go handler's `r.FormValue(...)` parsing key, and the targeted component `Errors[...]` key must match this nomenclature flawlessly (e.g., changing legacy `client_name` lookups and errors to `application_name` on form invalidations).


## Identity providers

Identity providers follow the same routed, section-card design as groups and profiles.

| Route | Purpose |
| --- | --- |
| `GET /admin/idps` | List with search (`q`), `partition_id`, `type` and `status` filters, plus linked users and allowing groups per provider |
| `GET /admin/idps/new[?type=]` | Type picker, then a short form for the chosen type |
| `POST /admin/idps` | Create, then redirect to the provider page |
| `GET /admin/idps/{id}` | Detail page with one card per section |
| `PUT /admin/idps/{id}/{section}` | Save one section (`general`, `connection`, `credentials`, `behavior`, `assurance`, `local-policy`); answers with that card only |
| `DELETE /admin/idps/{id}` | Delete after the alias is typed |

Rules the pages rely on, all enforced in the domain service:

- A section save re-reads the stored provider, overlays only that section and validates the whole, so configuration no card shows is never lost.
- The alias, type and partition are the storage conflict key and cannot be changed after creation.
- The issuer and the metadata snapshot are taken from the provider's discovery response when the connection is saved; the discovery endpoint must be https (http only for localhost).
- The client secret is write-only. The field is always empty; an empty submission keeps the stored secret.
- System providers (the admin tenant's local accounts and every tenant's `admin-sso`, flag `is_system`) are read-only and cannot be deleted. Only `CreateSystemIdentityProvider`, which is not on the admin use case port, can create one.
- A provider that an application group allows cannot be deleted. Deleting one that users have signed in with removes their link, and the danger zone says how many users that is.


## Users

| Route | Purpose |
| --- | --- |
| `GET /admin/users` | List with search (`q`), `partition_id` and `status` filters, in a stable order |
| `GET /admin/users/new` | Add form |
| `POST /admin/users` | Create, then redirect to the user page |
| `GET /admin/users/{partition}/{id}` | Detail page with one card per section |
| `PUT /admin/users/{partition}/{id}/{section}` | Save one section (`profile`, `status`, `password`); answers with that card only |
| `POST /admin/users/{partition}/{id}/unlock` | Clear a password lockout |
| `DELETE /admin/users/{partition}/{id}/identities/{idp}` | Remove one sign-in method |
| `DELETE /admin/users/{partition}/{id}` | Delete after the username is typed |

Rules, enforced in `AdminUserService` so every caller is covered:

- A user is always loaded by partition **and** ID. (Until this change the Postgres lookup ignored the ID and returned the first user of the partition, so an edit could overwrite the wrong user.)
- An administrator cannot block, deactivate or delete their own account, nor the last administrator who can sign in. A blocked administrator does not count as a remaining one.
- The last sign-in method of a user cannot be removed.
- The password is write-only: the field is never prefilled and the hash is never rendered. Setting a password also clears a lockout, and a failed save is reported to the administrator.
- Username and email are unique per partition and are reported against the field that caused the conflict.
