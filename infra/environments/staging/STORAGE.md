# Private artifact storage

The staging service uses a private Railway S3 bucket through S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_URL_STYLE. Credentials are Railway variable references and are never committed or exposed to clients.

Objects use product/tenant UUID/artifact UUID/SHA-256 keys. The service validates byte limits, declared size and digest before upload, then fetches the stored bytes and verifies them again. Artifact generations equal their content digest. Transfer capabilities remain short lived, and the API checks tenant membership before issuing them.

The pre-deploy storage probe writes, reads and deletes only its own disposable object; deployment is blocked when storage cannot be verified.

The current Railway plan allows three buckets in this project. SpecForge and DataReconcile share a bucket with separate product prefixes. This is application-level separation; these services share the bucket credential boundary. APIShield and AgentTest each have their own bucket.

DataReconcile's existing content_base64 column holds an immutable s3:SHA-256 locator for external objects; legacy development records still contain base64 bytes. The external read path validates the locator and object generation before fetching.
