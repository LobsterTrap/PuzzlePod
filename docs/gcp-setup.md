# GCP Setup for Agent Dispatch

This guide configures GCP Workload Identity Federation so the `agent-dispatch.yml`
workflow can call Vertex AI (Claude on Vertex) without stored API keys.

## Prerequisites

- A GCP project with billing enabled
- `gcloud` CLI installed and authenticated
- Owner or IAM Admin role on the GCP project

## Step 1: Enable Required APIs

```bash
gcloud services enable aiplatform.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  sts.googleapis.com \
  iamcredentials.googleapis.com
```

## Step 2: Create Workload Identity Pool

```bash
gcloud iam workload-identity-pools create github-actions-pool \
  --location="global" \
  --display-name="GitHub Actions Pool"
```

## Step 3: Create OIDC Provider

Replace `<GITHUB_ORG>` with your GitHub organization or username.

```bash
gcloud iam workload-identity-pools providers create-oidc github-actions-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --display-name="GitHub Actions Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
  --attribute-condition="assertion.repository_owner == '<GITHUB_ORG>'"
```

## Step 4: Create Service Account

```bash
gcloud iam service-accounts create puzzlepod-ci \
  --display-name="PuzzlePod CI Service Account"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

## Step 5: Bind Workload Identity

Replace `<PROJECT_NUMBER>` and `<GITHUB_ORG>/<REPO>` with your values.

```bash
gcloud iam service-accounts add-iam-policy-binding \
  puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions-pool/attribute.repository/<GITHUB_ORG>/<REPO>"
```

## Step 6: Get Provider Resource Name

```bash
gcloud iam workload-identity-pools providers describe github-actions-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --format="value(name)"
```

## Step 7: Configure GitHub Repository

### Secrets (Settings > Secrets and variables > Actions > Secrets)

| Secret | Value |
|--------|-------|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Full provider resource name from Step 6 |
| `GCP_SERVICE_ACCOUNT` | `puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com` |

### Variables (Settings > Secrets and variables > Actions > Variables)

| Variable | Value | Default |
|----------|-------|---------|
| `GCP_PROJECT_ID` | Your GCP project ID | (required) |
| `GCP_REGION` | Vertex AI region | `us-east5` |
| `GOOSE_MODEL` | Model for Goose agent | `claude-opus-4-20250514` |

### Labels (Settings > Labels)

Create these labels for the agent dispatch workflow:

| Label | Color | Purpose |
|-------|-------|---------|
| `agent:implement` | `#0075ca` | Trigger: implement a feature |
| `agent:fix` | `#d73a4a` | Trigger: fix a bug |
| `agent:test` | `#a2eeef` | Trigger: write tests |
| `agent:in-progress` | `#fbca04` | State: agent is working |
| `agent:pr-created` | `#0e8a16` | State: draft PR exists |
| `agent:failed` | `#b60205` | State: agent failed |

## Security Notes

- **No long-lived credentials**: All authentication uses short-lived OIDC tokens
- **Scoped access**: Attribute condition restricts to your specific repository
- **Minimal permissions**: Service account only has `roles/aiplatform.user`
- **Audit trail**: All Vertex AI calls are logged in GCP Cloud Audit Logs
