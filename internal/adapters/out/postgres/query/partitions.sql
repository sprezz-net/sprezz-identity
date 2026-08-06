-- name: GetPartitions :many
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
ORDER BY id ASC;

-- name: GetPartitionByAlias :one
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
  AND alias_name = $2
LIMIT 1;

-- name: CreatePartition :one
INSERT INTO partitions (tenant_id, name, alias_name)
VALUES ((SELECT id FROM tenants WHERE tenant_uuid = $1::uuid), $2, $3)
RETURNING id, tenant_id, name, alias_name;

-- name: GetPartitionByID :one
SELECT id, tenant_id, name, alias_name
FROM partitions
WHERE id = $1
LIMIT 1;
