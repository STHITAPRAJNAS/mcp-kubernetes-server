# MCP Kubernetes Server

Enterprise-grade [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for Kubernetes operations built with [FastMCP](https://gofastmcp.com).

Designed for two primary deployment scenarios:
- **Local development**: Application engineers using their own kubeconfig (with team RBAC roles)
- **AWS EKS production**: Deployed as a pod with IRSA (IAM Roles for Service Accounts)

## Features

### Read Operations (always safe)
- List/inspect pods, deployments, services, namespaces, nodes, ingresses
- Stream pod logs with filtering (tail lines, since, previous instance)
- View ConfigMap keys (values optional), Secret metadata (values **never** exposed)
- List jobs, cronjobs, events (with warning filters)
- Cluster health summary and version info

### Write Operations (with dry-run support)
- Scale deployments up/down (with 0-replica warning)
- Rolling restart of deployments
- Create namespaces and configmaps
- Apply YAML/JSON manifests (server-side apply)
- Validate manifests (dry-run only)
- Rollback deployments to previous revisions

### Destructive Operations (multi-layer guards)
- Delete pods, deployments, services, configmaps, namespaces
- Rollback deployments
- Every destructive operation requires:
  1. `MCP_K8S_ALLOW_DESTRUCTIVE=true` (global kill switch)
  2. Protected namespaces (kube-system etc.) are always blocked
  3. Confirmation token: `confirm_name` must match resource name exactly
  4. Full audit trail

### Resources (LLM context)
- `k8s://cluster/info` — cluster version, identity, node/namespace counts
- `k8s://cluster/namespaces` — all namespace names
- `k8s://cluster/nodes` — all nodes with status
- `k8s://cluster/health` — health summary (not-ready pods, warning events)

### Guided Prompts
- `diagnose_pod` — systematic pod troubleshooting workflow
- `diagnose_deployment` — deployment health investigation
- `pre_deployment_checklist` — pre-flight checks before deploying
- `cluster_health_report` — comprehensive cluster health report
- `safe_delete_workflow` — guided safe deletion with impact assessment

---

## Architecture

```
mcp-kubernetes-server/
├── src/mcp_kubernetes/
│   ├── server.py              # FastMCP server + tool registration
│   ├── config.py              # Pydantic settings (env vars)
│   ├── k8s_client.py          # Kubernetes client manager
│   ├── audit.py               # Structured audit logging
│   ├── utils.py               # Shared utilities
│   ├── auth/
│   │   ├── base.py            # AuthProvider interface
│   │   ├── local.py           # Kubeconfig auth (local engineers)
│   │   ├── aws.py             # AWS EKS IAM auth (pre-signed STS token)
│   │   └── factory.py         # Auto-detect env and create provider
│   ├── tools/
│   │   ├── pods.py            # Pod list/get/logs/exec
│   │   ├── deployments.py     # Deployment list/get/scale/restart/history
│   │   ├── namespaces.py      # Namespace list/create
│   │   ├── services.py        # Service/Ingress list/get
│   │   ├── nodes.py           # Node list/get/pod-list
│   │   ├── configmaps_secrets.py  # ConfigMap/Secret operations
│   │   ├── events.py          # Events/Jobs/CronJobs
│   │   ├── apply.py           # Manifest apply/validate
│   │   └── destructive.py     # Delete operations with guards
│   ├── resources/
│   │   └── cluster.py         # k8s:// URI resources
│   ├── prompts/
│   │   └── diagnose.py        # Guided workflow prompts
│   └── models/
│       └── responses.py       # Pydantic response models
├── tests/                     # Pytest test suite
├── deploy/k8s/                # Kubernetes manifests + IAM policies
├── Dockerfile                 # Multi-stage production image
└── docker-compose.yaml        # Local development
```

---

## Authentication

### Local Mode (Application Engineers)

Uses the standard kubeconfig file. Supports all authentication mechanisms:
- Client certificates
- Bearer tokens
- OIDC / SSO via exec plugins
- AWS EKS via `aws eks get-token` exec plugin in kubeconfig

```bash
# Uses ~/.kube/config with current-context
MCP_K8S_ENV=local

# Or specify a context
MCP_K8S_ENV=local
MCP_K8S_DEFAULT_CONTEXT=my-team-staging

# Custom kubeconfig path
KUBECONFIG=/path/to/my-kubeconfig
```

### AWS Mode (Deployed in AWS)

Generates EKS authentication tokens via pre-signed AWS STS requests.

**When deployed as an EKS pod** (IRSA):
```bash
MCP_K8S_ENV=aws
MCP_K8S_EKS_CLUSTER_NAME=my-production-cluster
AWS_DEFAULT_REGION=us-east-1
# AWS credentials come automatically from IRSA (no explicit config needed)
```

**When running locally against AWS EKS** (assume engineer role):
```bash
MCP_K8S_ENV=aws
MCP_K8S_EKS_CLUSTER_NAME=my-production-cluster
AWS_DEFAULT_REGION=us-east-1
# Assume a specific IAM role before generating the token:
MCP_K8S_AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ApplicationEngineer
MCP_K8S_AWS_ROLE_SESSION_DURATION=3600
```

**Multi-cluster** (AWS):
```bash
MCP_K8S_CLUSTER_MAP={"prod":"eks-prod-01","staging":"eks-staging-01","dev":"eks-dev-01"}
MCP_K8S_DEFAULT_CLUSTER=staging
```

---

## Installation

### Requirements
- Python 3.11+
- `uv` (recommended) or `pip`

### Local Development

```bash
# Clone and set up
git clone https://github.com/sthitaprajnas/mcp-kubernetes-server.git
cd mcp-kubernetes-server

# Install with uv
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"

# Configure (copy and edit .env)
cp .env.example .env
```

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "mcp-kubernetes",
      "env": {
        "MCP_K8S_ENV": "local",
        "MCP_K8S_ALLOW_DESTRUCTIVE": "true",
        "MCP_K8S_REQUIRE_DESTRUCTIVE_CONFIRMATION": "true"
      }
    }
  }
}
```

For AWS EKS:
```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "mcp-kubernetes",
      "env": {
        "MCP_K8S_ENV": "aws",
        "MCP_K8S_EKS_CLUSTER_NAME": "my-cluster",
        "AWS_DEFAULT_REGION": "us-east-1",
        "MCP_K8S_AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/ApplicationEngineer",
        "MCP_K8S_ALLOW_DESTRUCTIVE": "true"
      }
    }
  }
}
```

### Claude Code (VS Code Extension)

Add to `.claude/mcp.json` in your project:
```json
{
  "servers": {
    "kubernetes": {
      "type": "stdio",
      "command": "mcp-kubernetes",
      "env": {
        "MCP_K8S_ENV": "local"
      }
    }
  }
}
```

### SSE Transport (for web-based MCP clients)

```bash
MCP_K8S_TRANSPORT=sse MCP_K8S_PORT=8080 mcp-kubernetes
```

---

## Docker Usage

### Local development with Docker Compose

```bash
# Copy and configure
cp .env.example .env
# Edit .env with your settings

# Run with your local kubeconfig
docker-compose up

# MCP server available at http://localhost:8080
```

### Building the image

```bash
docker build -t mcp-kubernetes-server:latest .
```

### Running in read-only mode

```bash
docker run -p 8080:8080 \
  -v ~/.kube/config:/home/mcpuser/.kube/config:ro \
  -e MCP_K8S_ALLOW_DESTRUCTIVE=false \
  -e MCP_K8S_TRANSPORT=sse \
  mcp-kubernetes-server:latest
```

---

## Deploying to AWS EKS

### 1. Create namespace and RBAC

```bash
kubectl apply -f deploy/k8s/rbac.yaml
```

### 2. Create IAM role for IRSA

```bash
# Get your OIDC provider URL
OIDC=$(aws eks describe-cluster --name my-cluster \
  --query 'cluster.identity.oidc.issuer' --output text | sed 's|https://||')

# Edit the trust policy
sed -i "s/ACCOUNT_ID/$(aws sts get-caller-identity --query Account --output text)/" \
  deploy/k8s/iam-role-trust-policy.json
sed -i "s/REGION/$(aws configure get region)/" \
  deploy/k8s/iam-role-trust-policy.json
sed -i "s|OIDC_PROVIDER_ID|${OIDC}|g" \
  deploy/k8s/iam-role-trust-policy.json

# Create the role
aws iam create-role \
  --role-name mcp-kubernetes-server-role \
  --assume-role-policy-document file://deploy/k8s/iam-role-trust-policy.json

aws iam put-role-policy \
  --role-name mcp-kubernetes-server-role \
  --policy-name eks-access \
  --policy-document file://deploy/k8s/iam-role-inline-policy.json
```

### 3. Create ServiceAccount with IRSA annotation

```bash
# Update ACCOUNT_ID in serviceaccount.yaml
sed -i "s/ACCOUNT_ID/$(aws sts get-caller-identity --query Account --output text)/" \
  deploy/k8s/serviceaccount.yaml

kubectl apply -f deploy/k8s/serviceaccount.yaml
```

### 4. Grant the IAM role access in aws-auth (or EKS access entries)

```bash
# For aws-auth ConfigMap approach:
kubectl edit configmap aws-auth -n kube-system
# Add:
# - rolearn: arn:aws:iam::ACCOUNT_ID:role/mcp-kubernetes-server-role
#   username: mcp-kubernetes-server
#   groups:
#     - mcp-server  # Create a dedicated group with appropriate RBAC
```

### 5. Deploy the server

```bash
# Update the image registry in deployment.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_K8S_ENV` | `auto` | Environment mode: `local`, `aws`, `auto` |
| `MCP_K8S_TRANSPORT` | `stdio` | Transport: `stdio` or `sse` |
| `MCP_K8S_HOST` | `0.0.0.0` | SSE server bind address |
| `MCP_K8S_PORT` | `8080` | SSE server port |
| `MCP_K8S_LOG_LEVEL` | `INFO` | Log level |
| `MCP_K8S_JSON_LOGS` | `false` | Structured JSON logging |
| `MCP_K8S_AUDIT_LOG_FILE` | `` | Path to audit log file |
| `KUBECONFIG` | `~/.kube/config` | Kubeconfig path (local mode) |
| `MCP_K8S_DEFAULT_CONTEXT` | `` | Default kubeconfig context |
| `AWS_DEFAULT_REGION` | `us-east-1` | AWS region |
| `AWS_PROFILE` | `` | AWS credential profile |
| `MCP_K8S_EKS_CLUSTER_NAME` | `` | EKS cluster name (AWS mode) |
| `MCP_K8S_AWS_ROLE_ARN` | `` | IAM role ARN to assume |
| `MCP_K8S_AWS_ROLE_SESSION_DURATION` | `3600` | Assumed role duration (seconds) |
| `MCP_K8S_ALLOW_DESTRUCTIVE` | `true` | Enable delete operations |
| `MCP_K8S_PROTECTED_NAMESPACES` | `kube-system,kube-public,kube-node-lease` | Protected namespaces |
| `MCP_K8S_REQUIRE_DESTRUCTIVE_CONFIRMATION` | `true` | Require name confirmation |
| `MCP_K8S_MAX_BATCH_DELETE` | `5` | Max resources deleteable at once |
| `MCP_K8S_DRY_RUN` | `false` | Global dry-run mode |
| `MCP_K8S_MASK_SECRETS` | `true` | Mask secret values in responses |
| `MCP_K8S_RATE_LIMIT_PER_MINUTE` | `120` | API rate limit |
| `MCP_K8S_REQUEST_TIMEOUT` | `30` | K8s API timeout (seconds) |
| `MCP_K8S_CLUSTER_MAP` | `{}` | JSON map of alias→cluster name |
| `MCP_K8S_DEFAULT_CLUSTER` | `` | Default cluster alias |

---

## Security Considerations

### Secret Handling
Secret **values are never returned** by any tool. `list_secrets` and `get_secret_metadata` return only key names and metadata. This is hardcoded and cannot be configured away.

### Destructive Operations
Three independent gates must all pass:
1. **Global flag**: `MCP_K8S_ALLOW_DESTRUCTIVE=true`
2. **Namespace protection**: namespace not in `MCP_K8S_PROTECTED_NAMESPACES`
3. **Confirmation token**: `confirm_name` must equal the resource name exactly

For namespace deletion, the system namespaces (`default`, `kube-system`, `kube-public`, `kube-node-lease`) are **always blocked** regardless of configuration.

### Read-Only Mode
Set `MCP_K8S_ALLOW_DESTRUCTIVE=false` for a completely read-only server suitable for monitoring/observability use cases.

### Audit Logging
Every operation (read and write) is audit-logged with:
- ISO 8601 UTC timestamp
- Operation type (READ/WRITE/DELETE/EXEC/SCALE/AUTH)
- Tool name, resource kind/name/namespace
- Identity (IAM ARN or kubeconfig user)
- Cluster name
- Success/failure
- Dry-run flag

Configure `MCP_K8S_AUDIT_LOG_FILE=/var/log/mcp-k8s-audit.json` for persistent audit logs.

### Network Security
When using SSE transport in production:
- Deploy behind an API gateway or reverse proxy with mTLS
- Use Kubernetes NetworkPolicy to restrict pod-to-pod access
- Consider deploying as a sidecar to the Claude client

---

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=mcp_kubernetes --cov-report=html

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## Comparison to mcp-server-kubernetes

Inspired by [Flux159/mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes).

| Feature | This Server | Flux159 |
|---------|-------------|---------|
| Language | Python (FastMCP) | TypeScript (Bun) |
| AWS EKS auth | Native IRSA + role assumption | Via kubeconfig exec plugin |
| Auto env detection | Yes (IMDS, IRSA, env vars) | No |
| Destructive guards | 3-layer (flag + namespace + confirm) | Non-destructive mode flag |
| Audit logging | Structured JSON, file+stdout | No |
| Secret masking | Values never returned | Partial |
| Multi-cluster | Via cluster_map + switch_cluster | No |
| Helm support | Planned | Yes |
| Port forwarding | Planned | Yes |

---

## License

MIT
