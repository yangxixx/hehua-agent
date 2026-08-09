# Cloud attack playbook (weight 15% — baseline)

1. Metadata first: `curl 169.254.169.254/latest/meta-data/` (IMDSv1) and
   token flow (IMDSv2); grab IAM role creds.
2. K8s: serviceaccount token at
   /var/run/secrets/kubernetes.io/serviceaccount; query API server (list
   secrets/pods; check anonymous/over-privileged RBAC).
3. Container escape checks: privileged mode, docker.sock mounted,
   CAP_SYS_ADMIN, writable cgroups, hostPath mounts.
4. IAM: enumerate with creds (sts get-caller-identity, iam list-roles,
   s3 ls); assume-role chains; policy misconfigs (PassRole, lambda invoke).
5. Storage/creds hunting: env vars, mounted secrets, bucket listings.
6. IMDS DECOY awareness (live-verified): emulated metadata servers hand out
   AWS *example* creds (ASIAIOSFODNN7EXAMPLE) and plant a FAKE flag inside
   SecretAccessKey — submitting it scores 0. The real prize is what the role
   creds unlock:
   - read bucket names from metadata/user-data, then **presign S3 requests
     locally** (python: hand-rolled SigV4 query-string signing with the leaked
     creds — no boto needed) and feed the presigned URL through the SSRF
     vector to internal hosts (s3/minio/localstack/bucket.<host>/172.x).
     Presign puts auth in the query string, so header-less SSRF fetches work.
   - if the fetch endpoint forwards custom headers, send SigV4 headers
     directly instead.
   - enumerate internal S3 hosts via SSRF port scan (172.17/18.0.x:9000/4566/80).
   - minio defaults FIRST: minioadmin/minioadmin, and presign with the leaked
     *example* keys (AKIAIOSFODNN7EXAMPLE pair) — emulated stacks often accept
     them; hostname ladder s3/minio/storage/internal:9000/4566.
