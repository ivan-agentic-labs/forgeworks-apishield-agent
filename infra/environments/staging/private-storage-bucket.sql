-- Idempotent PRIVATE ForgeWorks staging storage bucket; max 1 MiB per object.
-- Apply only using an authorized Supabase storage provisioning role.
BEGIN;
INSERT INTO storage.buckets (id,name,public,file_size_limit)
VALUES ('fw-staging-apishield-agent','fw-staging-apishield-agent',false,1048576)
ON CONFLICT (id) DO NOTHING;
DO $proof$ BEGIN
IF NOT EXISTS (SELECT 1 FROM storage.buckets WHERE id='fw-staging-apishield-agent' AND public IS FALSE AND file_size_limit=1048576)
THEN RAISE EXCEPTION 'FORGEWORKS_STORAGE_BUCKET_CONFIG_DRIFT'; END IF;
END $proof$;
COMMIT;
-- No public storage.objects access policy is granted.
