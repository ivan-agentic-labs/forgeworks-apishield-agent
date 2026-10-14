-- ForgeWorks staging G3: read-only server-owned app_metadata grant planner.
-- Run only against Supabase project fljekuwplgkrpdoajyhn.
-- This grants NOTHING by itself; an authorized Auth Admin must update two NEW
-- test users, and membership rows must be provisioned separately.
-- No existing REVOKED principal may be reused.
WITH slots AS (
  SELECT 'apishield-agent'::text AS product, slug, id AS tenant_id,
         'analysis:read'::text AS scope FROM fw_apishield_agent.tenants
    WHERE slug IN ('g3-owner-20261014-tenant-a', 'g3-owner-20261014-tenant-b') AND status = 'ACTIVE'
  UNION ALL SELECT 'accessfix-ai', slug, id, 'scan:read' FROM fw_accessfix_ai.tenants
    WHERE slug IN ('g3-owner-20261014-tenant-a', 'g3-owner-20261014-tenant-b') AND status = 'ACTIVE'
  UNION ALL SELECT 'specforge-ai', slug, id, 'spec:read' FROM fw_specforge_ai.tenants
    WHERE slug IN ('g3-owner-20261014-tenant-a', 'g3-owner-20261014-tenant-b') AND status = 'ACTIVE'
  UNION ALL SELECT 'agenttest-lab', slug, id, 'evaluation:read' FROM fw_agenttest_lab.tenants
    WHERE slug IN ('g3-owner-20261014-tenant-a', 'g3-owner-20261014-tenant-b') AND status = 'ACTIVE'
  UNION ALL SELECT 'datareconcile-ai', slug, id, 'report:read' FROM fw_datareconcile_ai.tenants
    WHERE slug IN ('g3-owner-20261014-tenant-a', 'g3-owner-20261014-tenant-b') AND status = 'ACTIVE'
),
grants AS (
  SELECT right(slug, 1) AS slot, count(*) AS product_count,
         jsonb_build_object('forgeworks',
           jsonb_object_agg(product, jsonb_build_object(
             'tenant_id', tenant_id, 'scopes', jsonb_build_array(scope)))
         ) AS app_metadata
  FROM slots GROUP BY right(slug, 1)
)
SELECT slot, product_count, app_metadata FROM grants
WHERE product_count = 5 AND slot IN ('a', 'b') ORDER BY slot;
