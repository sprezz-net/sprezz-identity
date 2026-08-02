# Architecture Blueprint: Sprezz Identity Server

This document establishes the definitive functional and technical architectural blueprint for **Sprezz Identity**, a standalone, high-performance Identity Provider (IdP) and Token Server. This system is engineered completely independently of any specific resource application, adheres strictly to **Hexagonal Architecture (Ports and Adapters)** principles, and natively provides multi-tenant execution boundaries.

The server implements **OAuth 2.0 with PKCE**, **OpenID Connect (OIDC)**, and **Dynamic Client Registration (DCR)** using concurrent dual-asymmetric cryptographic signatures (**RS256** and **EdDSA**).

## 1. Global Topology & Boundary Context

Sprezz Identity operates as a decentralized, zero-trust cryptographic boundary layer. It strictly decouples user identity and authentication domains from downstream resource business logic.

```text
[ Public Internet / Native Client Apps ]
                 │
                 │ (Resolves Tenant via Host Header, e.g., ://idp.com)
                 ▼
┌──────────────────┐          ┌──────────────────────────┐
│ SPREZZ-ID ENGINE │          │ EXTERNAL RESOURCE SERVER │
│   (Port 8100)    │          │   (e.g. Sprezz Server)   │
└────────┬─────────┘          └────────────┬─────────────
         │                                 │
         │ (JWKS Public Key Fetch)         │
         └────────────────────────────────►│ [In-Memory Token Verification]
         │                                 │
         ▼                                 ▼
Database: `sprezz_identity`   Database: `sprezz_federation`
  └──────────────┬─────────────────────────┘
                 ▼
[ SHARED POSTGRESQL ENGINE SERVER ]
```

## 2. Microservice Project Structure

The project topology forces strict perimeter isolation. Core business logic cannot contain dependencies on database drivers, HTTP web engines, or external serialization layers.

```text
sprezz-identity/
├── cmd/idp/
│   └── main.go                         # Infrastructure entrypoint & dependency wire-up
├── docs/
│   └── architecture_blueprint.md       # This specification document
├── internal/
│   ├── config/                         # Configuration loaders & Asymmetric Key parsers
│   ├── domain/                         # CORE BUSINESS LOGIC (Pure Go, 0 external imports)
│   │   ├── model/                      # Pure Domain Entities (Tenant, Account, App, Token)
│   │   ├── port/                       # Driving and Driven Structural Interfaces
│   │   └── service/                    # Business Engines (OAuth, ClientRegistration, PKCE)
│   └── adapters/                       # INFRASTRUCTURE WIRE-UP (Ports fulfillment)
│       ├── in/
│       │   └── http/                   # Framework endpoints, route handlers, payload parsers
│       └── out/
│           ├── postgres/               # Relational persistence layer via sqlc
│           │   ├── db/                 # Auto-generated code structures from SQL queries
│           │   ├── migrations/         # DDL transactional schema scripts (.sql)
│           │   └── query/              # Raw database lookup scripts (.sql)
│           └── crypto/                 # Asymmetric signature engines (JWT minting / JWKS building)
├── Dockerfile                          # Multi-stage scratch minimal build environment
├── go.mod
└── sqlc.yaml                           # Custom SQL compiler configuration for identity scope
```

## 3. Pure Domain Model Strategy (`internal/domain/model/`)

All domain entities use native Go primitives. They remain entirely un-annotated by framework database tags, validation micro-framework anchors, or JSON serialization metadata to safeguard domain core purity.

* **`tenant` Component**: Holds internal high-entropy tracking keys, human-readable organization identifiers, and structural canonical tracking domains.
* **`crypto_types` Component**: Maintains definitions for asymmetric algorithms (`RS256` / `EdDSA`) and structure maps for signing key registries.
* **`client_application` Component**: Governs client applications, registration secrets, white-listed redirect URIs, permitted grant/response arrays, and targeted encryption bindings.
* **`auth_session` Component**: Manages temporal storage variables during active validation lifecycles, locking active PKCE challenge state matrices down to explicit users.
* **`oidc_claims` Component**: Handles structural schemas tracking access token lifespans, standard dynamic payload values, and core user-profile field vectors.

## 4. Port Boundaries (`internal/domain/port/`)

Ports define the rigid, un-compromised structural abstract contracts of the system boundary.

### Inbound Ports (Driving / Use Cases)

* **Dynamic Client Registration Contract**: Controls external client engine enrollment processing, mapping unauthenticated registration data to targeted entity spaces safely.
* **OAuth Flow Contract**: Governs authorization state allocations and structural authorization code trade workflows.
* **Tenant Resolution Contract**: Maps routing lookups using inbound layer variables down to verified workspace contexts.

### Outbound Ports (Driven / Infrastructure)

* **Identity Storage Contract**: Abstracts state interactions, decoupling the business engine from physical databases for clients, sessions, and profile tracking.
* **Asymmetric Crypto Engine Contract**: Encapsulates token minting tasks, raw payload cryptographic signing, and public signature set distributions.

## 5. Specification Flow Control Matrix

### A. Dynamic Client Registration (DCR - RFC 7591)

Enables native apps (like mobile clients or single-page applications) to register themselves dynamically over an unauthenticated boundary.

* **Rule 1 (Public Client Stripping)**: If the registration payload specifies a native mobile or browser client application type, the engine **must not** generate or return a `client_secret`. The application profile is saved with a null secret and locked out of standard client-credential grant executions.
* **Rule 2 (Scope Filtering)**: The registration engine matches requested scopes against the global tenant allowance rules before committing the application array.

### B. Authorization Code Flow with PKCE (RFC 7636)

Protects public, native mobile clients from intercept attacks by forcing runtime cryptographic proofs.

```text
[ Mobile Client App ]               [ Browser Engine ]              [ Sprezz Identity Server ]
          │                                 │                                      │
          │ 1. Generate verifier & challenge│                                      │
          │ 2. Direct user to browser ─────>│                                      │
          │                                 │ 3. GET /oauth/authorize              │
          │                                 │    ?response_type=code               │
          │                                 │    &client_id=client_123             │
          │                                 │    &code_challenge=XYZ...            │
          │                                 │    &code_challenge_method=S256       │
          │                                 ├─────────────────────────────────────>│
          │                                 │                                      │ [Renders Login/Consent UI]
          │                                 │ 4. Authenticates user & tenant credentials
          │                                 │<─────────────────────────────────────┤
          │                                 │ 5. Redirects with 302 Found          │
          │                                 │    to client redirect_uri?code=abc...│
          │ <───────────────────────────────┤                                      │
          │ 6. Extracts code parameter      │                                      │
          │                                 │                                      │
          │ 7. POST /oauth/token ───────────┼─────────────────────────────────────>│
          │    (Payload: code, client_id, code_verifier)                           │ [Core Service Engine Validation]
          │                                 │                                      │ - Recomputes SHA256 of verifier
          │                                 │                                      │ - Compares against challenge
          │                                 │                                      │ - Mints Access, ID, & Refresh tokens
          │ <───────────────────────────────┼──────────────────────────────────────┤
          │ 8. Returns 200 OK (JSON Token Set containing access_token, id_token, refresh_token)
```

The mathematical evaluation inside the business layer service strictly asserts:
$$\text{Base64URL}(\text{SHA256}(\text{code\_verifier})) == \text{code\_challenge}$$

### C. Domain-Based Tenant Resolution Workflow

To allow human users and automated clients to interact seamlessly with their specific identity container without passing raw system UUID parameters over wire query variables:

1. The Inbound HTTP Adapter intercepts the browser connection flow at `/oauth/authorize`.
2. The middleware inspects the incoming request's `r.Host` parameter (e.g., `localhost:8100`).
3. The server calls the `TenantResolutionUseCase`, driving an immediate O(1) indexed lookup against the persistence layer.
4. If valid, the engine assigns the specific `TenantID` directly to the running context thread (`context.Context`), locking all downstream logins, clients, and cryptographic signatures to that partition.

## 6. Multi-Tenant Relational Identity Schema Strategy

The persistence architecture isolates records by forcing a primary composite multi-tenant index lock across all lookup rows.

* **`tenants` Engine Domain**: Isolates the global identity landscapes. Employs a partial index on domains to provide zero-latency workspace routing for active accounts.
* **`applications` Engine Domain**: Stores tenant client details. Includes an algorithm identifier (`RS256` or `EdDSA`) and tracks application details via primary composite multi-tenant matrix structures.
* **`auth_sessions` Engine Domain**: Tracks high-entropy short-lived validation codes, state parameters, scopes, and expirations.

Internally a tenant is represented by an integer, externally (inside tokens for example) by a UUIDv4.

## 7. Cryptographic Strategy & Universal JWKS Layout

Sprezz Identity implements concurrent asymmetric dual-signing. It uses an internal Key Registry pattern mapping keys by Key ID (`kid`) and signature algorithm type (`alg`).

* **Egress Token Evaluation**: When minting tokens, the service queries the application profile. If `idp_signing_algorithm` matches `EdDSA`, it utilizes the **Ed25519** signing key to yield sub-millisecond encryption footprints. If it matches `RS256`, it applies the **RSA-2048** key for backwards-compatibility.
* **The Single-GET JWKS Route**: The infrastructure exposes `/.well-known/jwks.json`, grouping both signatures into an immutable pre-computed memory byte array.
* **Dynamic OIDC Issuer Claim Matching**: When minting an identity payload certificate (the ID Token), the crypto engine no longer pushes a static server-wide root domain string. It reads the specific resolved tenant parameters to generate distinct, isolated identity issuers dynamically matching the client's origin (e.g., `"iss": "https://idp.com"`).

## 8. Protocol Compliance Interface Map

To maintain complete compatibility with off-the-shelf native app clients, the HTTP Inbound Adapter layer translates protocol transport wire conventions down to domain primitives.

1. **Scope Tokenization Check**: On the HTTP wire, scopes pass as space-delimited string vectors (`"openid profile email"`). The inbound controller must intercept this parameter and tokenize it immediately, routing only a pure Go slice array to the ports layer.
2. **Extended Boundary Constraints**: The IDP serves strictly as an access gatekeeper mapping identities down to an un-alterable `sub` URI or resource pointer. It **does not** function as an expansive CRM, contact manager, or corporate directory table. Any future requirement for semantic contact mapping via RDF or triple stores must reside in an entirely detached, isolated application container.

### Token Endpoint Route Requirements

| Route Endpoint | HTTP Method | RFC/Specification Context | Functional Responsibility |
| :--- | :--- | :--- | :--- |
| `/.well-known/openid-configuration` | `GET` | OpenID Discovery 1.0 | Aggregates all protocol server metadata paths and crypto capabilities. |
| `/.well-known/jwks.json` | `GET` | RFC 7517 (JWK) | Distributes concurrent public signing parameters to external servers. |
| `/oauth/register` | `POST` | RFC 7591 (DCR) | Executes dynamic onboard profiles for untrusted mobile native clients. |
| `/oauth/authorize` | `GET`/`POST` | RFC 6749 / RFC 7636 | Orchestrates credentials authentication, tenant isolation, and consent UI. |
| `/oauth/token` | `POST` | RFC 6749 / PKCE Swap | Validates verifiers, confirms code constraints, and issues the token payload. |
| `/oauth/userinfo` | `GET` | OIDC Core 1.0 | Authenticated user profile retrieval interface (`Authorization: Bearer`). |
| **Dynamic Routing Middleware** | `Intercept` | HTTP Host Header Context | Resolves incoming raw server domains (`Host`) to a valid internal `tenant_id` state. |

## 9. Identity Providers

Each user has a profile is identified with a unique UUIDv4, has a display name and email address (with verification status). Each user profile is coupled to one or more identities from an identity provider. Each tenant has a list of available identity providers. At the moment the only identity provider implemented is the username-password identity provider. Whenever an identity provider does a succesful authentication, it will create an identity that is linked to the user profile. Identities can be decoupled. Each identity has a unique UUIDv4.

### Username-Password

The password is stored as Argon2id Hash in the database.
