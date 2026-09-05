-- name: GetPartitions :many
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid)
ORDER BY id ASC;

-- name: GetPartitionByID :one
-- GetPartitionByID resolves a partition's metadata and URL string slug using its internal numeric primary key.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    name, -- Corrected from partition_name to match the standard table layout
    alias_name
FROM partitions
WHERE id = @partition_id::bigint
  AND tenant_id = (SELECT id FROM tenant)
LIMIT 1;

-- name: GetPartitionByAlias :one
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid)
  AND alias_name = @alias_name
LIMIT 1;

-- name: CreatePartition :one
INSERT INTO partitions (tenant_id, name, alias_name)
VALUES ((SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid), @name, @alias_name)
RETURNING id, tenant_id, name, alias_name;

-- name: GetPartitionsByInternalTenantID :many
-- GetPartitionsByInternalTenantID scans the partitions grid to verify
-- whether this specific tenant row already holds any operational isolation boundaries.
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE tenant_id = @tenant_id::integer;

-- name: InsertPartition :one
-- InsertPartition provisions a brand new partition record linked to the tenant's internal sequence.
INSERT INTO partitions (
    tenant_id,
    name,
    alias_name
) VALUES (
    @tenant_id::integer,
    @name,
    @alias_name
)
RETURNING id, tenant_id, name, alias_name;
