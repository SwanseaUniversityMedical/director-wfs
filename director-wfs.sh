#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Logging helpers
# -----------------------------
log()  { printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
warn() { log "WARN: $*"; }

# -----------------------------
# Usage
# -----------------------------
usage() {
  cat >&2 <<'EOF'
Usage:
  ./director-wfs.sh <dns_name> [dev_password] [s3_endpoint] [s3_access_key] [s3_secret_key] [s3_use_tls] [signing_cert_fullchain_or_path] [signing_key_or_path] [extra_egress_endpoints]

Args:
  1. dns_name                         (required)
  2. dev password                     (optional)
  3. s3_endpoint                      (optional; include protocol+port ideally)
  4. s3_access_key                    (optional)
  5. s3_secret_key                    (optional)
  6. s3_use_tls                       (optional; true/false/1/0/yes/no)
  7. signing cert full chain OR path  (optional; .crt/.pem, chain: intermediate then root)
  8. signing cert key OR path         (optional; .key)
  9. extra egress IPs / hostnames     (optional; comma-separated list)

Env fallbacks (if args missing):
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_ENDPOINT

AWS credentials fallback file:
  ~/.aws/credentials  (expects keys: aws_access_key_id, aws_secret_access_key; and optionally endpoint)
EOF
}

# -----------------------------
# Input args
# -----------------------------
DNS_NAME="${1:-}"
DEV_PASSWORD_IN="${2:-}"
S3_ENDPOINT_RAW="${3:-}"
S3_ACCESS_KEY="${4:-}"
S3_SECRET_KEY="${5:-}"
S3_USE_TLS_RAW="${6:-}"
SIGNING_CHAIN_IN="${7:-}"
SIGNING_KEY_IN="${8:-}"
EXTRA_EGRESS_RAW="${9:-}"

[[ -n "$DNS_NAME" ]] || { usage; die "dns_name (arg1) is required"; }

# -----------------------------
# OS detection 
# -----------------------------
detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Darwin) echo "macos" ;;
    Linux)
      if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
          ubuntu) echo "ubuntu" ;;
          debian) echo "debian" ;;
          *) echo "linux" ;;
        esac
      else
        echo "linux"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

OS_FAMILY="$(detect_os)"
log "Detected OS family: ${OS_FAMILY}"

# -----------------------------
# Helpers: truthy parsing
# -----------------------------
to_bool() {
  # echoes "true" or "false" or empty if unknown
  local v="${1:-}"
  v="$(echo "$v" | tr '[:upper:]' '[:lower:]' | xargs || true)"
  case "$v" in
    1|true|yes|y|on)  echo "true" ;;
    0|false|no|n|off) echo "false" ;;
    "") echo "" ;;
    *) echo "" ;;
  esac
}

# -----------------------------
# AWS creds parsing from ~/.aws/credentials
# - simple INI parsing for [default]
# - also tries to find "endpoint" if present
# -----------------------------
parse_aws_credentials_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1

  # Extract from [default] section (or first occurrence if no section)
  # This is intentionally simple; good enough for typical credentials files.
  local in_default=0
  local ak="" sk="" ep=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    # strip comments
    line="${line%%#*}"
    line="${line%%;*}"
    line="$(echo "$line" | xargs || true)"
    [[ -n "$line" ]] || continue

    if [[ "$line" =~ ^\[.*\]$ ]]; then
      if [[ "$line" == "[default]" ]]; then
        in_default=1
      else
        in_default=0
      fi
      continue
    fi

    # If file has sections, only parse default. If no sections, in_default stays 0 and we still parse.
    if grep -q '^\[' "$file"; then
      [[ "$in_default" -eq 1 ]] || continue
    fi

    case "$line" in
      aws_access_key_id=*|aws_access_key_id\ =*)
        ak="${line#*=}"; ak="$(echo "$ak" | xargs || true)"
        ;;
      aws_secret_access_key=*|aws_secret_access_key\ =*)
        sk="${line#*=}"; sk="$(echo "$sk" | xargs || true)"
        ;;
      endpoint=*|endpoint\ =*)
        ep="${line#*=}"; ep="$(echo "$ep" | xargs || true)"
        ;;
    esac
  done < "$file"

  [[ -n "$ak" ]] && echo "AWS_ACCESS_KEY_ID=$ak"
  [[ -n "$sk" ]] && echo "AWS_SECRET_ACCESS_KEY=$sk"
  [[ -n "$ep" ]] && echo "AWS_ENDPOINT=$ep"
  return 0
}

# -----------------------------
# Endpoint normalization
# - ensure scheme; if missing, try probe (curl) else heuristics based on port
# - return normalized endpoint and inferred tls bool if not explicitly provided
# -----------------------------
has_scheme() {
  [[ "${1:-}" =~ ^https?:// ]]
}

extract_port() {
  # best-effort: grabs last ":<digits>" in host:port (ignores scheme)
  local s="${1:-}"
  s="${s#http://}"
  s="${s#https://}"
  if [[ "$s" =~ :([0-9]{2,5})($|/) ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo ""
  fi
}

probe_scheme_with_curl() {
  local hostport="$1" # no scheme
  command -v curl >/dev/null 2>&1 || return 1

  # Try https first quickly; if it responds at all, assume https.
  if curl -k -sS --max-time 2 -I "https://${hostport}" >/dev/null 2>&1; then
    echo "https"
    return 0
  fi
  if curl -sS --max-time 2 -I "http://${hostport}" >/dev/null 2>&1; then
    echo "http"
    return 0
  fi
  return 1
}

infer_scheme_heuristic() {
  local hostport="$1"
  local port
  port="$(extract_port "$hostport")"
  case "$port" in
    443|8443|9443) echo "https" ;;
    80|8080|9000|9001) echo "http" ;;
    "") echo "https" ;; # conservative default if unknown
    *)  echo "https" ;; # conservative default
  esac
}

normalize_endpoint_and_tls() {
  local endpoint_raw="$1"
  local tls_raw="$2" # may be empty
  local tls_val=""
  tls_val="$(to_bool "$tls_raw" || true)"

  if [[ -z "$endpoint_raw" ]]; then
    echo "ENDPOINT="
    echo "TLS="
    return 0
  fi

  local endpoint="$endpoint_raw"
  if has_scheme "$endpoint"; then
    # Infer TLS from scheme if tls not provided
    if [[ -z "$tls_val" ]]; then
      if [[ "$endpoint" =~ ^https:// ]]; then tls_val="true"; else tls_val="false"; fi
    fi
    echo "ENDPOINT=$endpoint"
    echo "TLS=$tls_val"
    return 0
  fi

  # No scheme: infer it
  local scheme=""
  if scheme="$(probe_scheme_with_curl "$endpoint" 2>/dev/null)"; then
    :
  else
    scheme="$(infer_scheme_heuristic "$endpoint")"
  fi

  endpoint="${scheme}://${endpoint}"

  if [[ -z "$tls_val" ]]; then
    [[ "$scheme" == "https" ]] && tls_val="true" || tls_val="false"
  fi

  echo "ENDPOINT=$endpoint"
  echo "TLS=$tls_val"
}

# -----------------------------
# Random secrets helper
# -----------------------------
rand_secret() {
  # 32-ish chars; prefer openssl, fallback to /dev/urandom
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -d '\n'
  else
    # urandom fallback
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32
  fi
}

# -----------------------------
# Cert generation (root + intermediate + chain)
# - intermediate is constrained to DNS_NAME and subdomains via nameConstraints
# -----------------------------
ensure_openssl() {
  command -v openssl >/dev/null 2>&1 || die "openssl is required for cert generation"
}

make_cert_dir() {
  local d
  d="$(mktemp -d -t kind-bootstrap-certs.XXXXXX)"
  echo "$d"
}

generate_root_and_intermediate_chain() {
  ensure_openssl
  local dns="$1"
  local outdir="$2"

  local root_key="${outdir}/root-ca.key"
  local root_crt="${outdir}/root-ca.crt"
  local int_key="${outdir}/intermediate-ca.key"
  local int_csr="${outdir}/intermediate-ca.csr"
  local int_crt="${outdir}/intermediate-ca.crt"
  local chain_crt="${outdir}/signing-fullchain.pem"

  log "Generating self-signed ROOT CA..."
  openssl genrsa -out "$root_key" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "$root_key" -sha256 -days 3650 \
    -subj "/CN=kind-bootstrap-root-ca" \
    -out "$root_crt" >/dev/null 2>&1

  log "Generating INTERMEDIATE CA (restricted to *.${dns})..."
  openssl genrsa -out "$int_key" 4096 >/dev/null 2>&1
  openssl req -new -key "$int_key" -subj "/CN=kind-bootstrap-intermediate-ca" -out "$int_csr" >/dev/null 2>&1

  # Create v3 extensions for intermediate CA with name constraints
  local v3ext="${outdir}/intermediate-v3.ext"
  cat >"$v3ext" <<EOF
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
nameConstraints = critical, permitted;DNS:.${dns}
EOF

  openssl x509 -req -in "$int_csr" -CA "$root_crt" -CAkey "$root_key" -CAcreateserial \
    -out "$int_crt" -days 1825 -sha256 -extfile "$v3ext" >/dev/null 2>&1

  log "Writing full chain (intermediate then blank line then root)..."
  {
    cat "$int_crt"
    echo
    echo
    cat "$root_crt"
  } > "$chain_crt"

  echo "SIGNING_CHAIN=$chain_crt"
  echo "SIGNING_KEY=$int_key"
  echo "ROOT_CA=$root_crt"
  echo "INTERMEDIATE_CA=$int_crt"
}

# -----------------------------
# Resolve inputs
# -----------------------------
AWS_CREDS_FILE="${HOME}/.aws/credentials"

# 1) Pull missing S3 config from ~/.aws/credentials if needed
if [[ -z "${S3_ACCESS_KEY}" || -z "${S3_SECRET_KEY}" || -z "${S3_ENDPOINT_RAW}" ]]; then
  if [[ -f "$AWS_CREDS_FILE" ]]; then
    log "Attempting to read missing S3 config from ${AWS_CREDS_FILE}"
    while IFS= read -r kv; do
      case "$kv" in
        AWS_ACCESS_KEY_ID=*)
          [[ -n "$S3_ACCESS_KEY" ]] || S3_ACCESS_KEY="${kv#*=}"
          ;;
        AWS_SECRET_ACCESS_KEY=*)
          [[ -n "$S3_SECRET_KEY" ]] || S3_SECRET_KEY="${kv#*=}"
          ;;
        AWS_ENDPOINT=*)
          [[ -n "$S3_ENDPOINT_RAW" ]] || S3_ENDPOINT_RAW="${kv#*=}"
          ;;
      esac
    done < <(parse_aws_credentials_file "$AWS_CREDS_FILE" || true)
  fi
fi

# 2) Pull missing S3 config from env vars if needed
if [[ -z "${S3_ACCESS_KEY}" && -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
  S3_ACCESS_KEY="$AWS_ACCESS_KEY_ID"
fi
if [[ -z "${S3_SECRET_KEY}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  S3_SECRET_KEY="$AWS_SECRET_ACCESS_KEY"
fi
if [[ -z "${S3_ENDPOINT_RAW}" && -n "${AWS_ENDPOINT:-}" ]]; then
  S3_ENDPOINT_RAW="$AWS_ENDPOINT"
fi

# 3) Normalize endpoint + TLS
normalized="$(normalize_endpoint_and_tls "$S3_ENDPOINT_RAW" "$S3_USE_TLS_RAW")"
# shellcheck disable=SC2206
eval "$normalized"  # sets ENDPOINT and TLS
S3_ENDPOINT="$ENDPOINT"
S3_USE_TLS="$TLS"

# Validate S3 required fields (if any still empty the script fails fail)
[[ -n "$S3_ENDPOINT" ]]   || die "S3 endpoint is required (arg2 or ~/.aws/credentials or AWS_ENDPOINT)"
[[ -n "$S3_ACCESS_KEY" ]] || die "S3 access key is required (arg3 or ~/.aws/credentials or AWS_ACCESS_KEY_ID)"
[[ -n "$S3_SECRET_KEY" ]] || die "S3 secret key is required (arg4 or ~/.aws/credentials or AWS_SECRET_ACCESS_KEY)"
[[ -n "$S3_USE_TLS" ]]    || die "S3 use tls could not be determined (arg5 or from endpoint scheme)"

# -----------------------------
# Signing cert chain/key resolution
# -----------------------------
CERT_DIR=""
SIGNING_CHAIN=""
SIGNING_KEY=""
ROOT_CA=""
INTERMEDIATE_CA=""

resolve_path_or_inline_pem() {
  # If arg is a readable file path, echo that path.
  # Else treat as inline PEM content and write to a temp file, echo the temp file path.
  local val="$1"
  local outpath="$2"

  if [[ -n "$val" && -f "$val" && -r "$val" ]]; then
    echo "$val"
    return 0
  fi

  # Inline content: must include PEM header
  if [[ "$val" == *"-----BEGIN"* ]]; then
    printf "%s\n" "$val" >"$outpath"
    echo "$outpath"
    return 0
  fi

  # empty or invalid
  echo ""
}

if [[ -n "$SIGNING_CHAIN_IN" && -n "$SIGNING_KEY_IN" ]]; then
  CERT_DIR="$(make_cert_dir)"
  chain_file="$(resolve_path_or_inline_pem "$SIGNING_CHAIN_IN" "${CERT_DIR}/provided-fullchain.pem")"
  key_file="$(resolve_path_or_inline_pem "$SIGNING_KEY_IN" "${CERT_DIR}/provided-key.pem")"

  [[ -n "$chain_file" ]] || die "arg6 provided but not a readable file and not inline PEM"
  [[ -n "$key_file"   ]] || die "arg7 provided but not a readable file and not inline PEM"

  SIGNING_CHAIN="$chain_file"
  SIGNING_KEY="$key_file"
  log "Using provided signing chain/key."
else
  log "No signing chain/key provided -> generating root + intermediate + chain."
  CERT_DIR="$(make_cert_dir)"
  gen_out="$(generate_root_and_intermediate_chain "$DNS_NAME" "$CERT_DIR")"
  # shellcheck disable=SC2206
  eval "$gen_out"
fi

# -----------------------------
# Dev password / per-app passwords
# -----------------------------
DEV_PASSWORD="$DEV_PASSWORD_IN"
ARGO_PASSWORD=""
GRAFANA_PASSWORD=""

if [[ -n "$DEV_PASSWORD" ]]; then
  ARGO_PASSWORD="$DEV_PASSWORD"
  GRAFANA_PASSWORD="$DEV_PASSWORD"
else
  log "No dev password provided -> generating random passwords for Argo and Grafana."
  ARGO_PASSWORD="$(rand_secret)"
  GRAFANA_PASSWORD="$(rand_secret)"
fi

# -----------------------------
# Summary (safe-ish; do not echo secret key)
# -----------------------------
log "Resolved configuration:"
log "  DNS_NAME:         $DNS_NAME"
log "  S3_ENDPOINT:      $S3_ENDPOINT"
log "  S3_USE_TLS:       $S3_USE_TLS"
log "  S3_ACCESS_KEY:    ${S3_ACCESS_KEY:0:4}****"
log "  S3_SECRET_KEY:    (hidden)"
log "  SIGNING_CHAIN:    $SIGNING_CHAIN"
log "  SIGNING_KEY:      $SIGNING_KEY"
log "  CERT_DIR:         ${CERT_DIR:-"(none)"}"
log "  ARGO_PASSWORD:    ${ARGO_PASSWORD:0:4}****"
log "  GRAFANA_PASSWORD: ${GRAFANA_PASSWORD:0:4}****"


# kind doesn't work on apple silicon if this is set
export DOCKER_DEFAULT_PLATFORM=
set DOCKER_DEFAULT_PLATFORM=

# if we don't set this we get open file exhaustion
sudo sysctl -w fs.inotify.max_user_watches=10485760


# -----------------------------
# Prereq versions (override via env if needed)
# -----------------------------
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.35.0}"   
KIND_VERSION="${KIND_VERSION:-v0.31.0}"
HELM_VERSION="${HELM_VERSION:-v4.1.1}"
YQ_VERSION="${YQ_VERSION:-v4.52.2}"
K9S_VERSION="${K9S_VERSION:-v0.50.18}"
FREELENS_VERSION="${FREELENS_VERSION:-1.8.0}"   # version number WITHOUT leading v
FREELENS_TAG="v${FREELENS_VERSION}"

# -----------------------------
# Small helpers
# -----------------------------
have() { command -v "$1" >/dev/null 2>&1; }

need_internet_hint() {
  warn "This step downloads binaries from the internet (kubectl/kind/helm)."
}

ensure_curl_linux() {
  if ! have curl; then
    log "Installing curl..."
    sudo apt-get update -y
    sudo apt-get install -y curl ca-certificates
  fi
}

ensure_brew_macos() {
  if ! have brew; then
    die "Homebrew is required on macOS for automated installs. Install it, then re-run."
  fi
}

# -----------------------------
# Docker
# -----------------------------
install_docker_linux() {
  if have docker; then
    log "docker already installed: $(docker --version || true)"
    return 0
  fi

  log "Installing docker (apt package docker.io)..."
  sudo apt-get update -y
  sudo apt-get install -y docker.io

  # Enable and start daemon (systemd systems)
  if have systemctl; then
    sudo systemctl enable --now docker || true
  fi

  # Allow current user to run docker without sudo (takes effect after re-login)
  if ! groups "$USER" | grep -q '\bdocker\b'; then
    log "Adding user '$USER' to docker group (may require re-login)..."
    sudo usermod -aG docker "$USER" || true
    warn "You may need to log out/in for docker group changes to apply."
  fi

  # Quick sanity check (may fail until re-login if group change needed)
  docker version >/dev/null 2>&1 || warn "docker installed but not usable without sudo yet. If needed, use: sudo docker ..."
}

install_docker_macos() {
  if have docker; then
    log "docker already installed: $(docker --version || true)"
    return 0
  fi

  ensure_brew_macos

  log "Attempting to install Docker Desktop via Homebrew Cask..."
  brew install --cask docker || true

  warn "Docker Desktop may require manual launch + permission prompts."
  warn "Open Docker.app, finish setup, then re-run the script."
  have docker || die "docker is still not available on PATH after install attempt."
}

ensure_docker() {
  case "$OS_FAMILY" in
    ubuntu|debian|linux) install_docker_linux ;;
    macos) install_docker_macos ;;
    *) die "Unsupported OS for docker install: $OS_FAMILY" ;;
  esac
}

# -----------------------------
# kubectl (download official binary)
# -----------------------------
install_kubectl() {
  if have kubectl; then
    log "kubectl already installed: $(kubectl version --client --output=yaml 2>/dev/null | head -n 3 | tr '\n' ' ' || kubectl version --client || true)"
    return 0
  fi

  need_internet_hint

  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      ensure_curl_linux
      ;;
    macos)
      ensure_brew_macos
      ;;
  esac

  local os arch url tmp
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for kubectl: $(uname -m)" ;;
  esac

  url="https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/${os}/${arch}/kubectl"
  tmp="$(mktemp -t kubectl.XXXXXX)"

  log "Downloading kubectl ${KUBECTL_VERSION}..."
  curl -fsSL "$url" -o "$tmp"
  chmod +x "$tmp"

  log "Installing kubectl to /usr/local/bin (sudo)..."
  sudo install -m 0755 "$tmp" /usr/local/bin/kubectl
  rm -f "$tmp"

  kubectl version --client >/dev/null 2>&1 || die "kubectl install failed"
}

# -----------------------------
# kind (download official binary)
# -----------------------------
install_kind() {
  if have kind; then
    log "kind already installed: $(kind version || true)"
    return 0
  fi

  need_internet_hint

  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      ensure_curl_linux
      ;;
    macos)
      ensure_brew_macos
      ;;
  esac

  local os arch url tmp
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for kind: $(uname -m)" ;;
  esac

  # kind release assets use: kind-<os>-<arch>
  # os is "linux" or "darwin"
  case "$os" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) die "Unsupported OS for kind: $(uname -s)" ;;
  esac

  url="https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-${os}-${arch}"
  tmp="$(mktemp -t kind.XXXXXX)"

  log "Downloading kind ${KIND_VERSION}..."
  curl -fsSL "$url" -o "$tmp"
  chmod +x "$tmp"

  log "Installing kind to /usr/local/bin (sudo)..."
  sudo install -m 0755 "$tmp" /usr/local/bin/kind
  rm -f "$tmp"

  kind version >/dev/null 2>&1 || die "kind install failed"
}

# -----------------------------
# helm
# -----------------------------
install_helm() {
  if have helm; then
    log "helm already installed: $(helm version --short 2>/dev/null || helm version || true)"
    return 0
  fi

  need_internet_hint

  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      ensure_curl_linux
      ;;
    macos)
      ensure_brew_macos
      ;;
  esac

  local os arch url tmp tarball
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"  # linux/darwin
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for helm: $(uname -m)" ;;
  esac

  url="https://get.helm.sh/helm-${HELM_VERSION}-${os}-${arch}.tar.gz"
  tmp="$(mktemp -d -t helm.XXXXXX)"
  tarball="${tmp}/helm.tgz"

  log "Downloading helm ${HELM_VERSION}..."
  curl -fsSL "$url" -o "$tarball"
  tar -xzf "$tarball" -C "$tmp"

  log "Installing helm to /usr/local/bin (sudo)..."
  sudo install -m 0755 "${tmp}/${os}-${arch}/helm" /usr/local/bin/helm
  rm -rf "$tmp"

  helm version >/dev/null 2>&1 || die "helm install failed"
}

install_yq() {
  if have yq; then
    log "yq already installed: $(yq --version || true)"
    return 0
  fi

  need_internet_hint

  local os arch url tmp
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for yq: $(uname -m)" ;;
  esac
  case "$os" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *) die "Unsupported OS for yq: $(uname -s)" ;;
  esac

  url="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_${os}_${arch}"
  tmp="$(mktemp -t yq.XXXXXX)"
  log "Downloading yq ${YQ_VERSION}..."
  curl -fsSL "$url" -o "$tmp"
  chmod +x "$tmp"
  sudo install -m 0755 "$tmp" /usr/local/bin/yq
  rm -f "$tmp"

  yq --version >/dev/null 2>&1 || die "yq install failed"
}

# -----------------------------
# K9s
# -----------------------------
install_k9s() {
  if have k9s; then
    log "k9s already installed: $(k9s version --short 2>/dev/null || true)"
    return 0
  fi

  need_internet_hint

  local os arch url tmpdir
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for k9s: $(uname -m)" ;;
  esac

  url="https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_${os}_${arch}.tar.gz"
  tmpdir="$(mktemp -d -t k9s.XXXXXX)"

  log "Downloading k9s ${K9S_VERSION}..."
  curl -fsSL "$url" -o "$tmpdir/k9s.tgz"
  tar -xzf "$tmpdir/k9s.tgz" -C "$tmpdir"

  sudo install -m 0755 "$tmpdir/k9s" /usr/local/bin/k9s
  rm -rf "$tmpdir"

  have k9s || die "k9s install failed"
}


# -----------------------------
# Freelens
# -----------------------------
install_freelens_linux() {
  # Prefer .deb on Debian/Ubuntu (clean uninstall/updates), fallback to AppImage if dpkg not available
  if have freelens; then
    log "freelens already installed"
    return 0
  fi

  need_internet_hint

  local arch url tmp
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "Unsupported arch for Freelens: $(uname -m)" ;;
  esac

  # If dpkg exists, install the .deb
  if have dpkg; then
    url="https://github.com/freelensapp/freelens/releases/download/${FREELENS_TAG}/Freelens-${FREELENS_VERSION}-linux-${arch}.deb"
    tmp="$(mktemp -t freelens.XXXXXX.deb)"
    log "Downloading Freelens .deb (${FREELENS_TAG})..."
    curl -fsSL "$url" -o "$tmp"
    log "Installing Freelens via dpkg..."
    sudo dpkg -i "$tmp" || sudo apt-get -f install -y
    rm -f "$tmp"
    return 0
  fi

  # Fallback: AppImage
  url="https://github.com/freelensapp/freelens/releases/download/${FREELENS_TAG}/Freelens-${FREELENS_VERSION}-linux-${arch}.AppImage"
  tmp="$(mktemp -t freelens.XXXXXX.AppImage)"

  log "Downloading Freelens AppImage (${FREELENS_TAG})..."
  curl -fsSL "$url" -o "$tmp"
  chmod +x "$tmp"

  log "Installing Freelens AppImage to /usr/local/bin/freelens..."
  sudo install -m 0755 "$tmp" /usr/local/bin/freelens
  rm -f "$tmp"
}

install_freelens() {
  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      install_freelens_linux
      ;;
    macos)
      install_freelens_macos
      ;;
    *)
      warn "Skipping Freelens install on unsupported OS: $OS_FAMILY"
      ;;
  esac
}

# -----------------------------
# Composite
# -----------------------------
ensure_prereqs() {
  log "Ensuring prerequisites: docker, kubectl, kind, helm"
  ensure_docker
  install_kubectl
  install_kind
  install_helm
  install_yq
  install_k9s
  install_freelens
  log "Prereqs OK."
}

# - install deps (kind/kubectl/docker/helm/etc) depending on OS
ensure_prereqs

# clone repo + create KIND cluster
# installs/checks git
# clones repo to a predictable location (default ./director-wfs unless you want elsewhere)
# if repo already exists: does a git fetch + hard reset to origin/<default-branch> (safe for CI)
# creates the KIND cluster using the repo’s kind-config.yaml
# if a cluster already exists, it either skips or recreates based on FORCE_RECREATE=1
# -----------------------------
# Repo config (hardcoded)
# -----------------------------
REPO_URL="https://github.com/SwanseaUniversityMedical/director-wfs.git"   
REPO_DIR_NAME="${REPO_DIR_NAME:-director-wfs}"   
REPO_PARENT_DIR="${REPO_PARENT_DIR:-$PWD}"               
REPO_DIR="${REPO_PARENT_DIR}/${REPO_DIR_NAME}"
REPO_BRANCH="${REPO_BRANCH:-main}"    

# KIND cluster name (use a stable name so we can detect it)
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-director-wfs}"

# If set to 1, delete/recreate cluster if it already exists
FORCE_RECREATE="${FORCE_RECREATE:-0}"

# -----------------------------
# Git install/check
# -----------------------------
ensure_git() {
  if have git; then
    log "git already installed: $(git --version || true)"
    return 0
  fi

  log "Installing git..."
  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      sudo apt-get update -y
      sudo apt-get install -y git
      ;;
    macos)
      ensure_brew_macos
      brew install git
      ;;
    *)
      die "Unsupported OS for git install: $OS_FAMILY"
      ;;
  esac

  have git || die "git install failed"
}

# -----------------------------
# Clone/update repo
# -----------------------------
clone_or_update_repo() {
  ensure_git

  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Repo already exists at: $REPO_DIR"
    log "Updating repo (fetch + hard reset to remote default branch)..."

    pushd "$REPO_DIR" >/dev/null

    # Determine default branch from origin/HEAD if possible
    git fetch --prune origin

    log "Resetting to origin/${REPO_BRANCH}"
    git reset --hard "origin/${REPO_BRANCH}"
    git clean -fdx

    popd >/dev/null
  else
    log "Cloning repo: $REPO_URL -> $REPO_DIR"
    git clone "$REPO_URL" "$REPO_DIR"
    pushd "$REPO_DIR" >/dev/null
    git checkout ${REPO_BRANCH}
  fi

  [[ -d "$REPO_DIR/files" ]] || die "Expected repo structure not found: $REPO_DIR/files"
  [[ -f "$REPO_DIR/files/kind-config.yaml" ]] || die "Expected kind-config.yaml not found in repo root"
  [[ -f "$REPO_DIR/scripts/clean-up.sh" ]] || warn "clean-up.sh not found "
}

# -----------------------------
# KIND cluster creation (idempotent)
# -----------------------------
kind_cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"
}

delete_kind_cluster() {
  if kind_cluster_exists; then
    log "Deleting existing kind cluster: $KIND_CLUSTER_NAME"
    kind delete cluster --name "$KIND_CLUSTER_NAME" || true
  fi
}

create_kind_cluster_from_repo() {
  pushd "$REPO_DIR" >/dev/null

  if kind_cluster_exists; then
    if [[ "$FORCE_RECREATE" == "1" ]]; then
      delete_kind_cluster
    else
      log "kind cluster already exists: $KIND_CLUSTER_NAME (skipping create)"
      popd >/dev/null
      return 0
    fi
  fi

  log "Creating kind cluster '$KIND_CLUSTER_NAME' using config: files/kind-config.yaml"
  kind create cluster --name "$KIND_CLUSTER_NAME" --config=files/kind-config.yaml

  # quick sanity check
  export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
  kubectl cluster-info >/dev/null 2>&1 || die "Cluster created but kubectl cluster-info failed"

  log "kind cluster ready: $KIND_CLUSTER_NAME"
  popd >/dev/null
}

# -----------------------------
# Composite step
# -----------------------------
setup_repo_and_kind_cluster() {
  clone_or_update_repo
  create_kind_cluster_from_repo
}

setup_repo_and_kind_cluster


# install charts/deps on the cluster
# -----------------------------
# Namespaces / releases
# -----------------------------
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
INGRESS_RELEASE="${INGRESS_RELEASE:-ingress-nginx}"

CILIUM_NS="${CILIUM_NS:-kube-system}"     # common default
CILIUM_RELEASE="${CILIUM_RELEASE:-cilium}"

# Cilium chart version optional pin
CILIUM_CHART_VERSION="${CILIUM_CHART_VERSION:-1.19.0}"   # e.g. "1.15.6"
INGRESS_CHART_VERSION="${INGRESS_CHART_VERSION:-}" # e.g. "4.11.3"

# Repo YAML locations (from cloned repo root)
DEPS_DIR="${DEPS_DIR:-${REPO_DIR}/files/deps}"
COREDNS_PATCH_YAML="${COREDNS_PATCH_YAML:-${DEPS_DIR}/coredns.yaml}"
INGRESS_VALUES_YAML="${INGRESS_VALUES_YAML:-${DEPS_DIR}/ingress-nginx.yaml}"
CILIUM_VALUES_YAML="${CILIUM_VALUES_YAML:-${DEPS_DIR}/cilium.yaml}"

# -----------------------------
# Helm repo setup (idempotent)
# -----------------------------
ensure_helm_repos() {
  log "Ensuring helm repos..."
  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
  helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
  helm repo update >/dev/null
}

# -----------------------------
# Utilities
# -----------------------------
ensure_namespace() {
  local ns="$1"
  kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create ns "$ns" >/dev/null
}

helm_release_exists() {
  local ns="$1" rel="$2"
  helm -n "$ns" status "$rel" >/dev/null 2>&1
}

# -----------------------------
# Ingress-NGINX install/upgrade
# - If ${INGRESS_VALUES_YAML} exists, use it as values file
# -----------------------------
install_or_upgrade_ingress_nginx() {
  ensure_namespace "$INGRESS_NS"

  local -a extra_args=()
  if [[ -n "$INGRESS_CHART_VERSION" ]]; then
    extra_args+=(--version "$INGRESS_CHART_VERSION")
  fi

  if [[ -f "$INGRESS_VALUES_YAML" ]]; then
    log "Installing/upgrading ingress-nginx with values: $INGRESS_VALUES_YAML"
    helm upgrade --install "$INGRESS_RELEASE" ingress-nginx/ingress-nginx \
      -n "$INGRESS_NS" \
      -f "$INGRESS_VALUES_YAML" \
      --kube-context kind-${KIND_CLUSTER_NAME} \
      --wait --timeout 10m 
  else
    log "Installing/upgrading ingress-nginx with default values (no values file found at $INGRESS_VALUES_YAML)"
    helm upgrade --install "$INGRESS_RELEASE" ingress-nginx/ingress-nginx \
      -n "$INGRESS_NS" \
      --kube-context kind-${KIND_CLUSTER_NAME} \
      --wait --timeout 10m 
  fi

  # Sanity: wait for controller deployment ready
  kubectl -n "$INGRESS_NS" rollout status deployment/"${INGRESS_RELEASE}"-controller --timeout=5m || \
    warn "Ingress controller rollout check didn't match expected deployment name; continuing."
}

# -----------------------------
# Cilium install/upgrade
# Notes:
# - For kind, Cilium often needs specific settings depending on kube-proxy replacement, etc.
# - We'll allow a values file if you have one.
# -----------------------------
install_or_upgrade_cilium() {
  ensure_namespace "$CILIUM_NS"

  if [[ -f "$CILIUM_VALUES_YAML" ]]; then
    log "Installing/upgrading cilium with values: $CILIUM_VALUES_YAML"
    helm upgrade --install "$CILIUM_RELEASE" oci://quay.io/cilium/charts/cilium --version ${CILIUM_CHART_VERSION} \
      -n "$CILIUM_NS" \
      -f "$CILIUM_VALUES_YAML" \
      --wait --timeout 10m 
  else
    log "Installing/upgrading cilium with baseline kind-friendly defaults (no values file found at $CILIUM_VALUES_YAML)"
    # Baseline defaults that usually work on kind.
    # If your kind-config disables kube-proxy, you may need kubeProxyReplacement=strict.
    helm upgrade --install "$CILIUM_RELEASE" oci://quay.io/cilium/charts/cilium --version ${CILIUM_CHART_VERSION} \
      -n "$CILIUM_NS" \
      --kube-context kind-${KIND_CLUSTER_NAME} \
      --set operator.replicas=1 \
      --set ipam.mode=kubernetes \
      --wait --timeout 10m 
  fi

  # Wait for cilium daemonset; name usually "cilium"
  kubectl -n "$CILIUM_NS" rollout status ds/cilium --timeout=10m || \
    warn "Cilium daemonset rollout check failed or DS name differs; continuing."
}

# -----------------------------
# Patch / apply CoreDNS config
# -----------------------------
apply_coredns_patch() {
  [[ -f "$COREDNS_PATCH_YAML" ]] || die "CoreDNS patch file not found: $COREDNS_PATCH_YAML"

  log "Applying CoreDNS patch: $COREDNS_PATCH_YAML"
  kubectl apply -f "$COREDNS_PATCH_YAML"

  # Restart CoreDNS to pick up changes (safe + common)
  log "Restarting CoreDNS deployment..."
  kubectl -n kube-system rollout restart deployment/coredns >/dev/null 2>&1 || \
    warn "Could not restart coredns deployment (name may differ); continuing."
  kubectl -n kube-system rollout status deployment/coredns --timeout=5m >/dev/null 2>&1 || \
    warn "CoreDNS rollout status check failed; continuing."
}

# -----------------------------
# Composite step
# -----------------------------
install_networking_and_patch_dns() {
  ensure_helm_repos
  install_or_upgrade_cilium
  install_or_upgrade_ingress_nginx
  apply_coredns_patch
  log "Networking components installed and CoreDNS patched."
}

install_networking_and_patch_dns

# ----------------
# TEMPLATE ARGO
# ----------------
ARGO_VALUES_SRC="${ARGO_VALUES_SRC:-${REPO_DIR}/files/deps/argo.yaml}"
ARGO_VALUES_RENDERED="${ARGO_VALUES_RENDERED:-${REPO_DIR}/files/deps/argo.rendered.yaml}"

ensure_htpasswd() {
  if have htpasswd; then
    return 0
  fi

  log "Installing htpasswd..."
  case "$OS_FAMILY" in
    ubuntu|debian|linux)
      sudo apt-get update -y -qq >/dev/null
      sudo apt-get install -y -qq apache2-utils >/dev/null
      ;;
    macos)
      ensure_brew_macos
      brew install httpd >/dev/null
      ;;
    *)
      die "Unsupported OS for htpasswd install: $OS_FAMILY"
      ;;
  esac

  have htpasswd || die "htpasswd install failed"
}

argocd_admin_bcrypt() {
  # Outputs bcrypt hash compatible with Argo CD
  # Uses: htpasswd -nbBC 10 "" password | tr -d ':\n' | sed 's/$2y/$2a/'
  local password="$1"
  ensure_htpasswd >/dev/null 2>&1

  htpasswd -nbBC 10 "" "$password" \
    | tr -d ':\n' \
    | sed 's/\$2y/\$2a/'
}

template_argo_values() {
  [[ -f "$ARGO_VALUES_SRC" ]] || die "Argo values file not found: $ARGO_VALUES_SRC"
  have yq || die "yq is required for templating (install_yq in prereqs)"

  local argocd_domain="argocd.${DNS_NAME}"
  local argocd_url="http://${argocd_domain}"
  local argocd_hash
  argocd_hash="$(argocd_admin_bcrypt "$ARGO_PASSWORD")"

  log "Templating Argo values:"
  log "  domain: $argocd_domain"
  log "  url:    $argocd_url"
  log "  admin password: ${ARGO_PASSWORD:0:4}****"

  # Start from source -> rendered
  cp -f "$ARGO_VALUES_SRC" "$ARGO_VALUES_RENDERED"

  # Structural edits
  yq -i "
    .global.domain = \"${argocd_domain}\" |
    .configs.cm.url = \"${argocd_url}\" |
    .server.ingress.hostname = \"${argocd_domain}\" |
    .configs.secret.argocdServerAdminPassword = \"${argocd_hash}\"
  " "$ARGO_VALUES_RENDERED"

  # Quick sanity checks so we fail early if paths don't match expected structure
  [[ "$(yq -r '.global.domain' "$ARGO_VALUES_RENDERED")" == "$argocd_domain" ]] \
    || die "Failed to set global.domain in rendered Argo values"

  [[ "$(yq -r '.configs.cm.url' "$ARGO_VALUES_RENDERED")" == "$argocd_url" ]] \
    || die "Failed to set configs.cm.url in rendered Argo values"

  [[ "$(yq -r '.server.ingress.hostname' "$ARGO_VALUES_RENDERED")" == "$argocd_domain" ]] \
    || die "Failed to set server.ingress.hostname in rendered Argo values"

  log "Rendered Argo values written to: $ARGO_VALUES_RENDERED"
}

template_argo_values


# -----------------------------
# Argo CD helm config
# -----------------------------
ARGOCD_NS="${ARGOCD_NS:-argocd}"
ARGOCD_RELEASE="${ARGOCD_RELEASE:-argocd}"

# Pin chart version optionally
ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-}"   # e.g. "7.6.12"

# Rendered values file from previous step
ARGOCD_VALUES_FILE="${ARGOCD_VALUES_FILE:-$ARGO_VALUES_RENDERED}"

ensure_argo_helm_repo() {
  log "Ensuring Argo Helm repo..."
  helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
  helm repo update >/dev/null
}

install_or_upgrade_argocd() {
  [[ -n "${KIND_CLUSTER_NAME:-}" ]] || warn "KIND_CLUSTER_NAME not set; relying on current kubectl context"
  [[ -f "$ARGOCD_VALUES_FILE" ]] || die "Argo CD values file not found: $ARGOCD_VALUES_FILE"

  ensure_namespace "$ARGOCD_NS"
  ensure_argo_helm_repo

  log "Installing/upgrading Argo CD:"
  log "  namespace: $ARGOCD_NS"
  log "  release:   $ARGOCD_RELEASE"
  log "  values:    $ARGOCD_VALUES_FILE"

  helm upgrade --install "$ARGOCD_RELEASE" argo/argo-cd \
    -n "$ARGOCD_NS" \
    -f "$ARGOCD_VALUES_FILE" \
    --kube-context "kind-${KIND_CLUSTER_NAME}" \
    --wait --timeout 15m \

  # Readiness checks (names can differ depending on chart version/values, so keep these tolerant)
  log "Waiting for Argo CD deployments to become ready..."
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" get deploy >/dev/null

  # Common deployment names in argo/argo-cd chart:
  # argocd-server, argocd-repo-server, argocd-application-controller, argocd-dex-server (optional), argocd-notifications-controller (optional)
  local d
  for d in argocd-server argocd-repo-server argocd-application-controller; do
    if kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" get deploy "$d" >/dev/null 2>&1; then
      kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" rollout status deploy/"$d" --timeout=10m
    else
      warn "Deployment '$d' not found (may be renamed by release name or chart settings)."
    fi
  done

  log "Argo CD installed/upgraded."
}

install_or_upgrade_argocd


# NAMESPACES + GENERATED SECRETS
TESK_NS="${TESK_NS:-tesk-stack}"
CERTMGR_NS="${CERTMGR_NS:-cert-manager}"

ensure_namespaces_for_tesk() {
  ensure_namespace "$TESK_NS"
  ensure_namespace "$CERTMGR_NS"
}

# Helper: read a file's contents safely
read_file_or_die() {
  local path="$1"
  [[ -f "$path" ]] || die "File not found: $path"
  [[ -r "$path" ]] || die "File not readable: $path"
  cat "$path"
}

# macOS base64 doesn't support -w; provide a portable base64 helper
b64_oneline() {
  # Prints base64 without line wraps on both GNU and BSD base64
  if base64 --help 2>&1 | grep -q -- '-w'; then
    base64 -w 0
  else
    base64 | tr -d '\n'
  fi
}

apply_cert_manager_ca_key_pair_secret_portable() {
  [[ -f "$SIGNING_CHAIN" ]] || die "SIGNING_CHAIN file missing: $SIGNING_CHAIN"
  [[ -f "$SIGNING_KEY"   ]] || die "SIGNING_KEY file missing: $SIGNING_KEY"

  log "Creating/updating cert-manager secret 'ca-key-pair' in namespace '${CERTMGR_NS}'"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$CERTMGR_NS" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ca-key-pair
type: kubernetes.io/tls
data:
  tls.crt: $(b64_oneline <"$SIGNING_CHAIN")
  tls.key: $(b64_oneline <"$SIGNING_KEY")
EOF
}

apply_tesk_aws_secret() {
  [[ -n "${S3_ENDPOINT:-}"   ]] || die "S3_ENDPOINT not set"
  [[ -n "${S3_ACCESS_KEY:-}" ]] || die "S3_ACCESS_KEY not set"
  [[ -n "${S3_SECRET_KEY:-}" ]] || die "S3_SECRET_KEY not set"

  log "Creating/updating tesk-stack secret 'aws-secret' in namespace '${TESK_NS}'"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$TESK_NS" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: aws-secret
type: Opaque
stringData:
  config: |
    [default]
    endpoint_url=${S3_ENDPOINT}
  credentials: |
    [default]
    aws_access_key_id=${S3_ACCESS_KEY}
    aws_secret_access_key=${S3_SECRET_KEY}
EOF
}

setup_namespaces_and_generated_secrets() {
  ensure_namespaces_for_tesk

  # Prefer portable base64 behavior everywhere
  apply_cert_manager_ca_key_pair_secret_portable
  apply_tesk_aws_secret

  log "Namespaces + generated secrets applied."
}

setup_namespaces_and_generated_secrets


# Wait for argocd to be ready to use
ARGOCD_NS="${ARGOCD_NS:-argocd}"
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
CILIUM_NS="${CILIUM_NS:-kube-system}"

ARGO_PROJECT_YAML="${ARGO_PROJECT_YAML:-${REPO_DIR}/files/argo/project.yaml}"
ARGO_REPO_YAML="${ARGO_REPO_YAML:-${REPO_DIR}/files/argo/repo.yaml}"

WAIT_TIMEOUT="${WAIT_TIMEOUT:-10m}"

wait_ns_ready() {
  local ns="$1" timeout="$2"
  log "Waiting for resources in namespace '$ns' to be ready (timeout $timeout)..."

  local ctx=(--context "kind-${KIND_CLUSTER_NAME}" -n "$ns")

  # Deployments -> Available
  if kubectl "${ctx[@]}" get deploy >/dev/null 2>&1; then
    kubectl "${ctx[@]}" wait --for=condition=Available deploy --all --timeout="$timeout" >/dev/null
  fi

  # StatefulSets -> Ready
  if kubectl "${ctx[@]}" get sts >/dev/null 2>&1; then
    kubectl "${ctx[@]}" wait --for=jsonpath='{.status.readyReplicas}'=1 sts --all --timeout="$timeout" >/dev/null 2>&1 || true
    # More robust: check each sts readyReplicas==replicas
    local sts
    while IFS= read -r sts; do
      [[ -n "$sts" ]] || continue
      local rep ready
      rep="$(kubectl "${ctx[@]}" get sts "$sts" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)"
      ready="$(kubectl "${ctx[@]}" get sts "$sts" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
      if [[ "$rep" != "$ready" ]]; then
        kubectl "${ctx[@]}" rollout status "sts/$sts" --timeout="$timeout" >/dev/null
      fi
    done < <(kubectl "${ctx[@]}" get sts -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  fi

  # DaemonSets -> rollout
  if kubectl "${ctx[@]}" get ds >/dev/null 2>&1; then
    local ds
    while IFS= read -r ds; do
      [[ -n "$ds" ]] || continue
      kubectl "${ctx[@]}" rollout status "ds/$ds" --timeout="$timeout" >/dev/null
    done < <(kubectl "${ctx[@]}" get ds -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  fi

  # Jobs -> Complete
  if kubectl "${ctx[@]}" get jobs >/dev/null 2>&1; then
    # Only wait if there actually are jobs
    if [[ -n "$(kubectl "${ctx[@]}" get jobs -o name 2>/dev/null || true)" ]]; then
      kubectl "${ctx[@]}" wait --for=condition=Complete job --all --timeout="$timeout" >/dev/null 2>&1 || true
    fi
  fi

  # Final guard: wait for pods that are not Completed/Succeeded to be Ready
  # (avoid hanging on Job pods)
  local pods
  pods="$(kubectl "${ctx[@]}" get pod \
    --field-selector=status.phase!=Succeeded,status.phase!=Failed \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"

  if [[ -n "$pods" ]]; then
    # shellcheck disable=SC2086
    kubectl "${ctx[@]}" wait --for=condition=Ready pod $pods --timeout="$timeout" >/dev/null 2>&1 || true
  fi
}

wait_core_components_ready() {
  log "Waiting up to $WAIT_TIMEOUT for core components (argo, cilium, ingress-nginx)..."

  wait_ns_ready "$ARGOCD_NS" "$WAIT_TIMEOUT"
  wait_ns_ready "$CILIUM_NS" "$WAIT_TIMEOUT"
  wait_ns_ready "$INGRESS_NS" "$WAIT_TIMEOUT"

  log "Core components look ready."
}

apply_argo_project_and_repo() {
  [[ -f "$ARGO_PROJECT_YAML" ]] || die "Missing Argo project YAML: $ARGO_PROJECT_YAML"
  [[ -f "$ARGO_REPO_YAML"    ]] || die "Missing Argo repo YAML: $ARGO_REPO_YAML"

  log "Applying Argo project + repo manifests..."
  kubectl --context "kind-${KIND_CLUSTER_NAME}" apply -f "$ARGO_PROJECT_YAML"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" apply -f "$ARGO_REPO_YAML"
  log "Applied project.yaml and repo.yaml."
}

wait_and_apply_argo_bootstrap() {
  wait_core_components_ready
  apply_argo_project_and_repo
}

wait_and_apply_argo_bootstrap

# TEMPLATE THE ACTUAL APP YAML
ARGO_APP_SRC="${ARGO_APP_SRC:-${REPO_DIR}/files/argo/app.yaml}"
ARGO_APP_RENDERED="${ARGO_APP_RENDERED:-${REPO_DIR}/files/argo/app.rendered.yaml}"

# ---- Endpoint parsing helpers ----
strip_scheme() {
  local s="$1"
  s="${s#http://}"
  s="${s#https://}"
  echo "$s"
}

extract_host() {
  # Input can be scheme://host:port/path or host:port/path
  local s
  s="$(strip_scheme "$1")"
  s="${s%%/*}"       # drop path
  s="${s%%:*}"       # drop port
  echo "$s"
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  # Validate octets 0-255
  local IFS=.
  read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

resolve_ipv4() {
  local host="$1"

  if is_ipv4 "$host"; then
    echo "$host"
    return 0
  fi

  # Linux: getent is usually available
  if have getent; then
    # ahostsv4 may output multiple lines; take first IP
    local ip
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)"
    if is_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  fi

  # dig (macOS often has it, Linux sometimes)
  if have dig; then
    local ip
    ip="$(dig +short A "$host" 2>/dev/null | head -n 1 || true)"
    if is_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  fi

  # Fallback: python3
  if have python3; then
    local ip
    ip="$(python3 - <<PY
import socket, sys
try:
    print(socket.gethostbyname(sys.argv[1]))
except Exception:
    print("")
PY
"$host")"
    if is_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  fi

  return 1
}

parse_extra_egress_ips() {
  local raw="$1"
  local out=()

  [[ -z "$raw" ]] && return 0

  IFS=',' read -ra items <<<"$raw"

  local item ip
  for item in "${items[@]}"; do
    item="$(echo "$item" | xargs)"   # trim
    [[ -z "$item" ]] && continue

    if is_ipv4 "$item"; then
      ip="$item"
    else
      ip="$(resolve_ipv4 "$item" || true)"
      [[ -n "$ip" ]] || die "Could not resolve extra egress host '$item' to IPv4"
    fi

    out+=("$ip")
  done

  printf '%s\n' "${out[@]}"
}

derive_s3_egress_ip() {
  [[ -n "${S3_ENDPOINT:-}" ]] || die "S3_ENDPOINT not set"
  local host ip
  host="$(extract_host "$S3_ENDPOINT")"
  [[ -n "$host" ]] || die "Could not extract host from S3_ENDPOINT='$S3_ENDPOINT'"

  ip="$(resolve_ipv4 "$host" || true)"
  [[ -n "$ip" ]] || die "Could not resolve IPv4 for S3 endpoint host '$host' (from '$S3_ENDPOINT')"
  echo "$ip"
}

get_kube_server_git_version() {
  local out ver

  out="$(kubectl --context "kind-${KIND_CLUSTER_NAME}" version -o json 2>/dev/null || true)"
  if [[ -z "${out//[[:space:]]/}" ]]; then
    out="$(kubectl --context "kind-${KIND_CLUSTER_NAME}" get --raw /version 2>/dev/null || true)"
  fi

  [[ -n "${out//[[:space:]]/}" ]] || die "Failed to retrieve Kubernetes version from cluster (context kind-${KIND_CLUSTER_NAME})."

  if have python3; then
    ver="$(printf '%s' "$out" | python3 -c 'import json,sys
d=json.load(sys.stdin)
sv=d.get("serverVersion", d)
print(sv.get("gitVersion",""))' 2>/dev/null || true)"
  else
    ver="$(printf '%s' "$out" | sed -n 's/.*"gitVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  fi

  [[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Could not parse gitVersion from Kubernetes version output"
  echo "$ver"
}

get_kind_control_plane_container_name() {
  # kind names containers like: <clustername>-control-plane
  echo "${KIND_CLUSTER_NAME}-control-plane"
}

get_docker_container_ip() {
  local container="$1"
  have docker || return 1
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container" 2>/dev/null || return 1
}

get_kubeconfig_server_host() {
  # Extract cluster.server from the current context (or explicitly your kind context)
  # Example: https://127.0.0.1:6443
  kubectl --context "kind-${KIND_CLUSTER_NAME}" config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true
}

extract_host_from_url() {
  local url="$1"
  url="${url#http://}"
  url="${url#https://}"
  url="${url%%/*}"   # drop path
  url="${url%%:*}"   # drop port
  echo "$url"
}

get_kube_api_endpoint_ip() {
  local cp ip server host

  # 1) Preferred: KIND control-plane container IP
  cp="$(get_kind_control_plane_container_name)"
  ip="$(get_docker_container_ip "$cp" || true)"
  if [[ -n "$ip" ]] && is_ipv4 "$ip"; then
    echo "$ip"
    return 0
  fi

  # 2) Fallback: kubeconfig server host -> resolve to IPv4
  server="$(get_kubeconfig_server_host)"
  [[ -n "$server" ]] || die "Could not read kubeconfig server URL for context kind-${KIND_CLUSTER_NAME}"
  host="$(extract_host_from_url "$server")"
  [[ -n "$host" ]] || die "Could not extract host from kubeconfig server URL: $server"

  ip="$(resolve_ipv4 "$host" || true)"
  [[ -n "$ip" ]] || die "Could not resolve IPv4 for kube API host '$host' (from '$server')"
  echo "$ip"
}


# ---- Template + apply ----
template_and_apply_argo_app() {
  [[ -f "$ARGO_APP_SRC" ]] || die "Argo app file not found: $ARGO_APP_SRC"
  have yq || die "yq is required for templating (install_yq in prereqs)"

  # What to template
  local ingress_host="$DNS_NAME" 
  local minio_ip kube_version kube_api_ip extra_egress_ips
  minio_ip="$(derive_s3_egress_ip)"
  kube_version="$(get_kube_server_git_version)"
  kube_api_ip="$(get_kube_api_endpoint_ip)"
  extra_egress_ips="$(parse_extra_egress_ips "$EXTRA_EGRESS_RAW")"

  [[ -n "${GRAFANA_PASSWORD:-}" ]] || die "GRAFANA_PASSWORD not set"

  log "Templating Argo Application:"
  log "  ingress host: $ingress_host"
  log "  s3 egress IP: $minio_ip"
  log "  grafana password: ${GRAFANA_PASSWORD:0:4}****"
  log "  kubernetes version: $kube_version"
  log "  kube api ip:   $kube_api_ip"
  if [[ -n "$extra_egress_ips" ]]; then
    log "  extra egress IPs:"
    printf '%s\n' "$extra_egress_ips" | sed 's/^/    - /' >&2
  fi

  cp -f "$ARGO_APP_SRC" "$ARGO_APP_RENDERED"

  # Patch the specific fields inside valuesObject
  yq -i "
    .spec.source.helm.valuesObject.global.ingress.host = \"${ingress_host}\" |
    .spec.source.helm.valuesObject.networkPolicy.egressMinioIP = \"${minio_ip}\" |
    .spec.source.helm.valuesObject.networkPolicy.kubeApiIP = \"${kube_api_ip}\" |
    .spec.source.helm.valuesObject.prometheus.grafana.adminPassword = \"${GRAFANA_PASSWORD}\" |
    .spec.source.helm.valuesObject.global.kubeVersion = \"${kube_version}\" |
    .spec.source.helm.valuesObject.networkPolicy.extraEgressIPs =
    ($(printf '%s\n' "$extra_egress_ips" | yq -R -s 'split(\"\\n\")[:-1]'))
  " "$ARGO_APP_RENDERED"

  # Quick sanity checks
  [[ "$(yq -r '.spec.source.helm.valuesObject.global.ingress.host' "$ARGO_APP_RENDERED")" == "$ingress_host" ]] \
    || die "Failed to set ingress.host in rendered app.yaml"

  [[ "$(yq -r '.spec.source.helm.valuesObject.networkPolicy.egressMinioIP' "$ARGO_APP_RENDERED")" == "$minio_ip" ]] \
    || die "Failed to set networkPolicy.egressMinioIP in rendered app.yaml"

  [[ "$(yq -r '.spec.source.helm.valuesObject.global.kubeVersion' "$ARGO_APP_RENDERED")" == "$kube_version" ]] \
    || die "Failed to set global.kubeVersion in rendered app.yaml"

  [[ "$(yq -r '.spec.source.helm.valuesObject.networkPolicy.kubeApiIP' "$ARGO_APP_RENDERED")" == "$kube_api_ip" ]] \
  || die "Failed to set networkPolicy.kubeApiIP in rendered app.yaml"

  yq -e '.spec.source.helm.valuesObject.networkPolicy.extraEgressIPs | type == "!!seq"' \
  "$ARGO_APP_RENDERED" >/dev/null || die "extraEgressIPs not rendered as list"

  log "Rendered Argo Application written to: $ARGO_APP_RENDERED"

  log "Applying rendered Argo Application..."
  kubectl --context "kind-${KIND_CLUSTER_NAME}" apply -f "$ARGO_APP_RENDERED"
  log "Applied Argo Application."
}

template_and_apply_argo_app


ARGO_APP_NAME="${ARGO_APP_NAME:-tesk-stack}"
ARGOCD_NS="${ARGOCD_NS:-argocd}"
WAIT_APP_TIMEOUT_SECS="${WAIT_APP_TIMEOUT_SECS:-1800}"  # 30 minutes

# Helpers to read status
get_app_sync_status() {
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" \
    get application "$ARGO_APP_NAME" -o jsonpath='{.status.sync.status}' 2>/dev/null || true
}
get_app_health_status() {
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" \
    get application "$ARGO_APP_NAME" -o jsonpath='{.status.health.status}' 2>/dev/null || true
}

wait_for_argocd_application_synced_healthy() {
  log "Waiting up to ${WAIT_APP_TIMEOUT_SECS}s for Argo Application '${ARGO_APP_NAME}' to be Synced + Healthy..."

  local deadline=$(( $(date +%s) + WAIT_APP_TIMEOUT_SECS ))
  local sync health

  while (( $(date +%s) < deadline )); do
    sync="$(get_app_sync_status)"
    health="$(get_app_health_status)"

    if [[ "$sync" == "Synced" && "$health" == "Healthy" ]]; then
      log "Application is Synced + Healthy."
      return 0
    fi

    log "Application status: sync='${sync:-?}' health='${health:-?}' (waiting...)"
    sleep 10
  done

  warn "Timed out waiting for Synced + Healthy."

  # Diagnostics
  warn "Current Application YAML summary:"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" get application "$ARGO_APP_NAME" -o yaml || true

  warn "Argo Application conditions:"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" get application "$ARGO_APP_NAME" \
    -o jsonpath='{range .status.conditions[*]}{.type}{" - "}{.message}{"\n"}{end}' || true

  warn "Recent events in argocd namespace:"
  kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$ARGOCD_NS" get events --sort-by=.lastTimestamp | tail -n 50 || true

  die "Argo Application did not become Synced + Healthy within ${WAIT_APP_TIMEOUT_SECS}s"
}

print_final_outputs() {
  local argo_addr="argocd.${DNS_NAME}"
  local grafana_addr="grafana.${DNS_NAME}"
  local tesk_addr="tesk.${DNS_NAME}"

  local argo_user="admin"
  local grafana_user="admin"

  echo
  echo "========================================"
  echo "TESK stack deployed successfully"
  echo "========================================"
  echo "Argo DNS addr:        ${argo_addr}"
  echo "Argo admin user:      ${argo_user}"
  echo "Argo admin pw:        ${ARGO_PASSWORD}"
  echo
  echo "Grafana DNS addr:     ${grafana_addr}"
  echo "Grafana admin user:   ${grafana_user}"
  echo "Grafana admin pw:     ${GRAFANA_PASSWORD}"
  echo
  echo "Tesk DNS addr:        ${tesk_addr}"
  echo
  echo "Rendered app.yaml:    ${ARGO_APP_RENDERED}"
  echo "========================================"
  echo
}

final_wait_and_print() {
  wait_for_argocd_application_synced_healthy
  print_final_outputs
}

final_wait_and_print


exit 0
