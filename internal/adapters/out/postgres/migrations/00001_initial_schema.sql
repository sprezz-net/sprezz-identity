CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    tenant_uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain_name VARCHAR(253) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_domain_resolution ON tenants(domain_name) WHERE is_active = TRUE;

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    front_channel_logout_uri VARCHAR(512) DEFAULT '',
    back_channel_logout_uri VARCHAR(512) DEFAULT '',
    grant_types TEXT[] NOT NULL,
    response_types TEXT[] NOT NULL,
    idp_signing_algorithm VARCHAR(50) NOT NULL DEFAULT 'RS256',
    access_token_lifetime INTERVAL NOT NULL DEFAULT '1 hour',
    refresh_token_lifetime INTERVAL NOT NULL DEFAULT '30 days',
    id_token_lifetime INTERVAL NOT NULL DEFAULT '10 minutes',
    allowed_scopes TEXT[] NOT NULL,
    default_scopes TEXT[] NOT NULL DEFAULT '{openid}',
    UNIQUE(tenant_id, client_id),
    CONSTRAINT chk_default_scopes_subset CHECK (default_scopes <@ allowed_scopes)
);

CREATE TABLE auth_sessions (
    code VARCHAR(255) PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    challenge_method VARCHAR(50) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Append-Only Security Event Store (Strictly no DELETES or UPDATES permitted)
CREATE TABLE audit_event_log (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- e.g., 'TOKEN_MINTED', 'SESSION_REVOKED_LOGOUT', 'DCR_CLIENT_CREATED'
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,    -- The actor performing the action

    -- Dynamic contextual payload store (captures non-sensitive metadata like tracking JTIs, IP, or User-Agent)
    payload JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Highly optimized composite index for rapid multi-tenant security auditing pipelines
CREATE INDEX idx_audit_event_stream ON audit_event_log(tenant_id, subject, event_type);
