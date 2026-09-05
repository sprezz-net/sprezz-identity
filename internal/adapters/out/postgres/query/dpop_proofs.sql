-- name: SaveDPoPProof :exec
-- SaveDPoPProof persists a unique thumbprint identifier (jti) along with its
-- temporal lifecycle expiration frame to stop token replay and cloning exploits.
INSERT INTO dpop_proofs (
    jti,
    expires_at
)
VALUES (
    @jti,
    @expires_at::timestamptz -- Explicit type casting hint for driver consistency
)
ON CONFLICT (jti) DO NOTHING;

-- name: IsDPoPProofUsed :one
-- IsDPoPProofUsed checks the system catalog table to determine whether an incoming
-- cryptographic proof thumbprint has already been processed within its active lifetime window.
SELECT EXISTS (
    SELECT 1
    FROM dpop_proofs
    WHERE jti = @jti
      AND expires_at > NOW()
) AS is_used;
