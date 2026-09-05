-- name: PruneExpiredRevokedTokens :exec
-- PruneExpiredRevokedTokens purges records from the blacklisted token cache
-- that have outlived their validation window threshold.
DELETE FROM revoked_tokens WHERE expires_at <= NOW();

-- name: PruneExpiredAuthSessions :exec
-- PruneExpiredAuthSessions evicts old backplane authorization code session keys
-- that have naturally expired without being consumed.
DELETE FROM auth_sessions WHERE expires_at <= NOW();

-- name: PruneExpiredInteractionSessions :exec
-- PruneExpiredInteractionSessions clears out stale login and authorization panel
-- interaction wizard states after their tracking deadline passes.
DELETE FROM interaction_sessions WHERE expires_at <= NOW();

-- name: PruneExpiredPushedAuthRequests :exec
-- PruneExpiredPushedAuthRequests wipes out stale PAR endpoints from memory
-- that were initiated but never exchanged for an authorization path.
DELETE FROM pushed_authorization_requests WHERE expires_at <= NOW();

-- name: PruneExpiredDPoPProofs :exec
-- PruneExpiredDPoPProofs drops old device-binding proof thumbprints
-- whose replay protection time windows have closed.
DELETE FROM dpop_proofs WHERE expires_at <= NOW();
