#!/bin/bash
set -e

# Lattice Deployment Script
# Deploys Lattice federation discovery daemon

# ============================================================================
# VISUAL OUTPUT CONFIGURATION (adapted from deploymira.sh)
# ============================================================================

LOUD_MODE=false
for arg in "$@"; do
    if [ "$arg" = "--loud" ]; then
        LOUD_MODE=true
    fi
done

# ANSI color codes
RESET='\033[0m'
DIM='\033[2m'
BOLD='\033[1m'
GRAY='\033[38;5;240m'
BLUE='\033[38;5;75m'
GREEN='\033[38;5;77m'
YELLOW='\033[38;5;186m'
RED='\033[38;5;203m'
CYAN='\033[38;5;80m'

CHECKMARK="${GREEN}✓${RESET}"
ARROW="${CYAN}→${RESET}"
WARNING="${YELLOW}⚠${RESET}"
ERROR="${RED}✗${RESET}"

print_header() {
    echo -e "\n${BOLD}${BLUE}$1${RESET}"
}

print_step() {
    echo -e "${DIM}${ARROW}${RESET} $1"
}

print_success() {
    echo -e "${CHECKMARK} ${GREEN}$1${RESET}"
}

print_warning() {
    echo -e "${WARNING} ${YELLOW}$1${RESET}"
}

print_error() {
    echo -e "${ERROR} ${RED}$1${RESET}"
}

print_info() {
    echo -e "${DIM}  $1${RESET}"
}

run_quiet() {
    if [ "$LOUD_MODE" = true ]; then
        "$@"
    else
        "$@" > /dev/null 2>&1
    fi
}

run_with_status() {
    local msg="$1"
    shift

    if [ "$LOUD_MODE" = true ]; then
        print_step "$msg"
        "$@"
    else
        echo -ne "${DIM}${ARROW}${RESET} $msg... "
        if "$@" > /dev/null 2>&1; then
            echo -e "${CHECKMARK}"
        else
            echo -e "${ERROR}"
            return 1
        fi
    fi
}

# ============================================================================
# HELPER FUNCTIONS (adapted from deploymira.sh)
# ============================================================================

check_exists() {
    local type="$1"
    local target="$2"

    case "$type" in
        file)
            [ -f "$target" ]
            ;;
        dir)
            [ -d "$target" ]
            ;;
        command)
            command -v "$target" &> /dev/null
            ;;
        service_systemctl)
            systemctl is-active --quiet "$target" 2>/dev/null
            ;;
        service_brew)
            brew services list 2>/dev/null | grep -q "${target}.*started"
            ;;
    esac
}

start_service() {
    local service_name="$1"
    local service_type="$2"

    case "$service_type" in
        systemctl)
            if check_exists service_systemctl "$service_name"; then
                print_info "$service_name already running"
                return 0
            fi
            run_with_status "Starting $service_name" \
                sudo systemctl start "$service_name"
            ;;
        brew)
            if check_exists service_brew "$service_name"; then
                print_info "$service_name already running"
                return 0
            fi
            run_with_status "Starting $service_name" \
                brew services start "$service_name"
            ;;
    esac
}

stop_service() {
    local service_name="$1"
    local service_type="$2"
    local extra="$3"

    case "$service_type" in
        systemctl)
            if ! check_exists service_systemctl "$service_name"; then
                return 0
            fi
            run_with_status "Stopping $service_name" \
                sudo systemctl stop "$service_name"
            ;;
        port)
            local port="$extra"
            if command -v lsof &> /dev/null; then
                local pids=$(lsof -ti ":$port" 2>/dev/null)
                if [ -z "$pids" ]; then
                    return 0
                fi
                kill $pids 2>/dev/null
            fi
            ;;
    esac
}

# Vault helpers
vault_is_initialized() {
    # Check via API - more reliable than checking for file
    local health_response
    health_response=$(curl -s http://127.0.0.1:8200/v1/sys/health)
    if echo "$health_response" | grep -q '"initialized":true'; then
        return 0
    fi
    return 1
}

vault_is_sealed() {
    local health_response
    health_response=$(curl -s http://127.0.0.1:8200/v1/sys/health)
    if echo "$health_response" | grep -q '"sealed":true'; then
        return 0
    fi
    return 1
}

vault_extract_credential() {
    local cred_type="$1"
    if [ ! -f "/opt/vault/init-keys.txt" ]; then
        return 1
    fi
    grep "$cred_type" /opt/vault/init-keys.txt | awk '{print $NF}'
}

vault_initialize() {
    if vault_is_initialized; then
        print_info "Vault already initialized"
        return 0
    fi

    print_step "Initializing Vault (this only happens once)"

    # Initialize with 1 key share and 1 threshold for simplicity
    local init_output
    init_output=$(vault operator init -key-shares=1 -key-threshold=1 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to initialize Vault"
        echo "$init_output"
        return 1
    fi

    # Save the keys
    sudo mkdir -p /opt/vault
    echo "$init_output" | sudo tee /opt/vault/init-keys.txt > /dev/null
    sudo chmod 600 /opt/vault/init-keys.txt

    print_success "Vault initialized - keys saved to /opt/vault/init-keys.txt"
    print_warning "IMPORTANT: Back up /opt/vault/init-keys.txt securely!"
}

vault_unseal() {
    if ! vault_is_sealed; then
        print_info "Vault already unsealed"
        return 0
    fi

    local unseal_key=$(vault_extract_credential "Unseal Key 1")
    if [ -z "$unseal_key" ]; then
        print_error "Cannot unseal: unseal key not found in /opt/vault/init-keys.txt"
        return 1
    fi

    run_with_status "Unsealing Vault" \
        vault operator unseal "$unseal_key"
}

vault_authenticate() {
    local root_token=$(vault_extract_credential "Initial Root Token")
    if [ -z "$root_token" ]; then
        print_error "Cannot authenticate: root token not found"
        return 1
    fi

    run_with_status "Authenticating with Vault" vault login "$root_token"
}

vault_setup_approle() {
    # Check if AppRole is already configured
    if [ -f "/opt/vault/role-id.txt" ] && [ -f "/opt/vault/secret-id.txt" ]; then
        print_info "AppRole credentials already exist"
        return 0
    fi

    print_step "Configuring Vault AppRole for Lattice"

    # Enable KV secrets engine if not already
    if ! vault secrets list 2>/dev/null | grep -q "^secret/"; then
        run_with_status "Enabling KV secrets engine" \
            vault secrets enable -path=secret kv-v2
    fi

    # Enable AppRole auth if not already
    if ! vault auth list 2>/dev/null | grep -q "^approle/"; then
        run_with_status "Enabling AppRole auth" \
            vault auth enable approle
    fi

    # Create policy for Lattice
    print_step "Creating Lattice policy"
    vault policy write lattice - <<POLICY
path "secret/data/lattice" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/data/lattice/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
POLICY

    # Create AppRole
    run_with_status "Creating Lattice AppRole" \
        vault write auth/approle/role/lattice \
            token_policies="lattice" \
            token_ttl=1h \
            token_max_ttl=4h

    # Get role-id and secret-id
    local role_id=$(vault read -field=role_id auth/approle/role/lattice/role-id)
    local secret_id=$(vault write -field=secret_id -f auth/approle/role/lattice/secret-id)

    # Save credentials
    echo "$role_id" | sudo tee /opt/vault/role-id.txt > /dev/null
    echo "$secret_id" | sudo tee /opt/vault/secret-id.txt > /dev/null
    sudo chmod 600 /opt/vault/role-id.txt /opt/vault/secret-id.txt

    print_success "AppRole configured - credentials saved"
}

vault_put_if_not_exists() {
    local secret_path="$1"
    shift

    if vault kv get "$secret_path" &> /dev/null; then
        print_info "Secret already exists at $secret_path"
        return 0
    fi

    run_with_status "Storing secret at $secret_path" \
        vault kv put "$secret_path" "$@"
}

# ============================================================================
# DEPLOYMENT START
# ============================================================================

# Default bootstrap server
DEFAULT_BOOTSTRAP="https://lattice.miraos.org"

clear
echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════╗"
echo "║   Lattice Deployment Script            ║"
echo "╚════════════════════════════════════════╝"
echo -e "${RESET}"
[ "$LOUD_MODE" = true ] && print_info "Running in verbose mode (--loud)"
echo ""

# Detect OS
OS_TYPE=$(uname -s)
case "$OS_TYPE" in
    Linux*)
        OS="linux"
        ;;
    Darwin*)
        OS="macos"
        ;;
    *)
        print_error "Unsupported operating system: $OS_TYPE"
        exit 1
        ;;
esac

# Set Vault address early - always use HTTP for local access
export VAULT_ADDR='http://127.0.0.1:8200'

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

print_header "Pre-flight Checks"

# Check not running as root
echo -ne "${DIM}${ARROW}${RESET} Checking user privileges... "
if [ "$EUID" -eq 0 ]; then
    echo -e "${ERROR}"
    print_error "Please do not run this script as root."
    exit 1
fi
echo -e "${CHECKMARK}"

# Check Vault installation and status
echo -ne "${DIM}${ARROW}${RESET} Checking Vault installation... "

if ! check_exists command vault; then
    echo -e "${WARNING}"
    print_warning "Vault is not installed"
    read -p "$(echo -e ${CYAN}Install Vault now?${RESET}) (y/n): " INSTALL_VAULT
    if [[ "$INSTALL_VAULT" =~ ^[Yy](es)?$ ]]; then
        if [ "$OS" = "macos" ]; then
            run_with_status "Installing Vault via Homebrew" brew install vault
        else
            # Linux installation
            run_with_status "Adding HashiCorp GPG key" \
                bash -c 'wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg'
            run_with_status "Adding HashiCorp repository" \
                bash -c 'echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list'
            run_with_status "Updating package list" sudo apt-get update
            run_with_status "Installing Vault" sudo apt-get install -y vault
        fi
        print_success "Vault installed"
    else
        print_error "Vault is required for Lattice. Please install Vault and try again."
        exit 1
    fi
else
    echo -e "${CHECKMARK}"
fi

# Check if Vault is running
echo -ne "${DIM}${ARROW}${RESET} Checking Vault status... "

# Check if Vault is running on HTTPS (misconfigured for our use)
if curl -sk https://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
    echo -e "${WARNING}"
    print_warning "Vault is running with HTTPS but we need HTTP for local access"
    read -p "$(echo -e ${CYAN}Reconfigure Vault for HTTP?${RESET}) (y/n): " RECONFIG_VAULT
    if [[ "$RECONFIG_VAULT" =~ ^[Yy](es)?$ ]]; then
        if [ "$OS" = "linux" ]; then
            run_with_status "Stopping Vault" sudo systemctl stop vault
            VAULT_NEEDS_START="yes"
        else
            print_error "Please stop Vault manually and re-run this script"
            exit 1
        fi
    else
        print_error "Vault must be accessible via HTTP at $VAULT_ADDR"
        exit 1
    fi
fi

VAULT_NEEDS_START="${VAULT_NEEDS_START:-no}"
if [ "$VAULT_NEEDS_START" = "yes" ] || ! curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
    if [ "$VAULT_NEEDS_START" != "yes" ]; then
        echo -e "${WARNING}"
        print_warning "Vault is not running at $VAULT_ADDR"
    fi
    read -p "$(echo -e ${CYAN}Start Vault now?${RESET}) (y/n): " START_VAULT
    if [[ "$START_VAULT" =~ ^[Yy](es)?$ ]]; then
        if [ "$OS" = "macos" ]; then
            # Check if Vault config exists
            if [ ! -f "/opt/vault/config/vault.hcl" ]; then
                print_step "Creating Vault configuration directory"
                sudo mkdir -p /opt/vault/config /opt/vault/data
                sudo chown -R $(whoami) /opt/vault

                print_step "Creating default Vault configuration"
                cat > /opt/vault/config/vault.hcl <<VAULTCONF
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

disable_mlock = true
api_addr      = "http://127.0.0.1:8200"
VAULTCONF
            fi

            print_step "Starting Vault server in background"
            nohup vault server -config=/opt/vault/config/vault.hcl > /opt/vault/vault.log 2>&1 &
            sleep 3

            if curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
                print_success "Vault started"
            else
                print_error "Failed to start Vault. Check /opt/vault/vault.log"
                exit 1
            fi
        else
            # Linux - configure Vault for local HTTP access
            print_step "Configuring Vault for local access"

            # Create Vault config directory if needed
            sudo mkdir -p /opt/vault/config /opt/vault/data

            # Create a config that allows local HTTP (no TLS for localhost)
            sudo tee /opt/vault/config/vault.hcl > /dev/null <<VAULTCONF
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

disable_mlock = true
api_addr      = "http://127.0.0.1:8200"
VAULTCONF

            # Create systemd override to use our config
            sudo mkdir -p /etc/systemd/system/vault.service.d
            sudo tee /etc/systemd/system/vault.service.d/override.conf > /dev/null <<OVERRIDE
[Service]
ExecStart=
ExecStart=/usr/bin/vault server -config=/opt/vault/config/vault.hcl
OVERRIDE

            sudo systemctl daemon-reload
            run_with_status "Starting Vault service" sudo systemctl start vault
            sleep 2

            if ! curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
                print_error "Failed to start Vault. Check: journalctl -u vault"
                exit 1
            fi
            print_success "Vault started"
        fi
    else
        print_error "Vault must be running for Lattice. Please start Vault and try again."
        exit 1
    fi
else
    echo -e "${CHECKMARK}"
fi

# Initialize Vault if needed (first-time setup)
vault_initialize || exit 1

# Unseal Vault if needed
vault_unseal || exit 1

# Check port 1113
echo -ne "${DIM}${ARROW}${RESET} Checking port 1113... "
if command -v lsof &> /dev/null; then
    if lsof -Pi :1113 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${WARNING}"
        print_warning "Port 1113 is already in use"
        read -p "$(echo -e ${YELLOW}Stop existing service on port 1113?${RESET}) (y/n): " STOP_PORT
        if [[ "$STOP_PORT" =~ ^[Yy](es)?$ ]]; then
            stop_service "Lattice" port 1113
        else
            print_info "Continuing anyway - service may fail to start"
        fi
    else
        echo -e "${CHECKMARK}"
    fi
else
    echo -e "${DIM}(skipped - lsof not available)${RESET}"
fi

print_success "Pre-flight checks passed"

# ============================================================================
# CONFIGURATION
# ============================================================================

print_header "Lattice Configuration"

# Bootstrap servers
echo -e "${BOLD}${BLUE}1. Bootstrap Servers${RESET}"
print_info "Bootstrap servers help new nodes discover the network."
print_info "Default: $DEFAULT_BOOTSTRAP"
read -p "$(echo -e ${CYAN}Enter bootstrap servers${RESET}) (comma-separated, or Enter for default): " BOOTSTRAP_SERVERS_INPUT
if [ -z "$BOOTSTRAP_SERVERS_INPUT" ]; then
    CONFIG_BOOTSTRAP_SERVERS="$DEFAULT_BOOTSTRAP"
    STATUS_BOOTSTRAP="${CHECKMARK} $DEFAULT_BOOTSTRAP (default)"
else
    CONFIG_BOOTSTRAP_SERVERS="$BOOTSTRAP_SERVERS_INPUT"
    STATUS_BOOTSTRAP="${CHECKMARK} $CONFIG_BOOTSTRAP_SERVERS"
fi

# Domain name
echo -e "${BOLD}${BLUE}2. Federation Domain${RESET} ${DIM}(OPTIONAL - your server's identity)${RESET}"
print_info "This is how other servers will identify you in the network."
print_info "Leave blank to auto-generate from your server's fingerprint."
read -p "$(echo -e ${CYAN}Enter domain name${RESET}) (or Enter for auto): " DOMAIN_INPUT
if [ -z "$DOMAIN_INPUT" ]; then
    CONFIG_DOMAIN=""
    STATUS_DOMAIN="${DIM}Auto-generate${RESET}"
else
    CONFIG_DOMAIN="$DOMAIN_INPUT"
    STATUS_DOMAIN="${CHECKMARK} $DOMAIN_INPUT"
fi

# Systemd service (Linux only)
if [ "$OS" = "linux" ]; then
    echo -e "${BOLD}${BLUE}3. Systemd Service${RESET} ${DIM}(auto-start on boot)${RESET}"
    read -p "$(echo -e ${CYAN}Install as systemd service?${RESET}) (y/n, default=y): " SYSTEMD_INPUT
    if [ -z "$SYSTEMD_INPUT" ] || [[ "$SYSTEMD_INPUT" =~ ^[Yy](es)?$ ]]; then
        CONFIG_INSTALL_SYSTEMD="yes"
        read -p "$(echo -e ${CYAN}Start Lattice now?${RESET}) (y/n, default=y): " START_NOW_INPUT
        if [ -z "$START_NOW_INPUT" ] || [[ "$START_NOW_INPUT" =~ ^[Yy](es)?$ ]]; then
            CONFIG_START_NOW="yes"
            STATUS_SYSTEMD="${CHECKMARK} Will be installed and started"
        else
            CONFIG_START_NOW="no"
            STATUS_SYSTEMD="${CHECKMARK} Will be installed (not started)"
        fi
    else
        CONFIG_INSTALL_SYSTEMD="no"
        CONFIG_START_NOW="no"
        STATUS_SYSTEMD="${DIM}Skipped${RESET}"
    fi
else
    CONFIG_INSTALL_SYSTEMD="no"
    CONFIG_START_NOW="no"
    STATUS_SYSTEMD="${DIM}N/A (macOS)${RESET}"
fi

echo ""
echo -e "${BOLD}Configuration Summary:${RESET}"
echo -e "  Bootstrap:  ${STATUS_BOOTSTRAP}"
echo -e "  Domain:     ${STATUS_DOMAIN}"
echo -e "  Systemd:    ${STATUS_SYSTEMD}"
echo ""

# ============================================================================
# VAULT SETUP
# ============================================================================

print_header "Step 1: Vault Configuration"

vault_authenticate || exit 1

# Setup AppRole if needed (creates role-id.txt and secret-id.txt)
vault_setup_approle || exit 1

# Store bootstrap servers
vault_put_if_not_exists secret/lattice \
    LATTICE_BOOTSTRAP_SERVERS="$CONFIG_BOOTSTRAP_SERVERS"

print_success "Vault configured for Lattice"

# ============================================================================
# LATTICE IDENTITY
# ============================================================================

print_header "Step 2: Initialize Lattice Identity"

# Determine working directory
if [ -d "/opt/mira/app" ]; then
    LATTICE_DIR="/opt/mira/app"
    PYTHON_CMD="/opt/mira/app/venv/bin/python3"
else
    # Use current directory (development mode)
    LATTICE_DIR="$(pwd)"
    if [ -f "venv/bin/python3" ]; then
        PYTHON_CMD="venv/bin/python3"
    else
        PYTHON_CMD="python3"
    fi
fi

cd "$LATTICE_DIR"

# Set environment for Lattice initialization
export VAULT_ROLE_ID=$(cat /opt/vault/role-id.txt)
export VAULT_SECRET_ID=$(cat /opt/vault/secret-id.txt)

if [ -n "$CONFIG_DOMAIN" ]; then
    export LATTICE_DOMAIN="$CONFIG_DOMAIN"
fi

echo -ne "${DIM}${ARROW}${RESET} Initializing federation identity... "
INIT_OUTPUT=$($PYTHON_CMD -c "
from lattice.init_lattice import ensure_lattice_identity
import json
result = ensure_lattice_identity()
print(json.dumps(result))
" 2>&1)

if [ $? -eq 0 ]; then
    echo -e "${CHECKMARK}"
    # Parse the result
    SERVER_ID=$(echo "$INIT_OUTPUT" | $PYTHON_CMD -c "import sys, json; print(json.load(sys.stdin).get('server_id', 'unknown'))")
    SERVER_UUID=$(echo "$INIT_OUTPUT" | $PYTHON_CMD -c "import sys, json; print(json.load(sys.stdin).get('server_uuid', 'unknown'))")
    print_info "Server ID: $SERVER_ID"
    print_info "UUID: $SERVER_UUID"
else
    echo -e "${ERROR}"
    print_error "Failed to initialize Lattice identity"
    if [ "$LOUD_MODE" = true ]; then
        echo "$INIT_OUTPUT"
    fi
    exit 1
fi

print_success "Lattice identity initialized"

# ============================================================================
# SYSTEMD SERVICE (Linux only)
# ============================================================================

if [ "$CONFIG_INSTALL_SYSTEMD" = "yes" ] && [ "$OS" = "linux" ]; then
    print_header "Step 3: Systemd Service Configuration"

    MIRA_USER="$(whoami)"
    MIRA_GROUP="$(id -gn)"
    VAULT_ROLE_ID=$(cat /opt/vault/role-id.txt)
    VAULT_SECRET_ID=$(cat /opt/vault/secret-id.txt)

    # Determine uvicorn path
    if [ -f "/opt/mira/app/venv/bin/uvicorn" ]; then
        UVICORN_CMD="/opt/mira/app/venv/bin/uvicorn"
        WORK_DIR="/opt/mira/app"
    else
        UVICORN_CMD="$(pwd)/venv/bin/uvicorn"
        WORK_DIR="$(pwd)"
    fi

    echo -ne "${DIM}${ARROW}${RESET} Creating systemd service file... "
    sudo tee /etc/systemd/system/lattice.service > /dev/null <<EOF
[Unit]
Description=Lattice Discovery Daemon - Federation Layer
Documentation=https://github.com/taylorsatula/mira-OSS
Requires=vault.service
After=vault.service vault-unseal.service
ConditionPathExists=$WORK_DIR/lattice/discovery_daemon.py

[Service]
Type=simple
User=$MIRA_USER
Group=$MIRA_GROUP
WorkingDirectory=$WORK_DIR
Environment="VAULT_ADDR=http://127.0.0.1:8200"
Environment="VAULT_ROLE_ID=$VAULT_ROLE_ID"
Environment="VAULT_SECRET_ID=$VAULT_SECRET_ID"
ExecStart=$UVICORN_CMD lattice.discovery_daemon:app --host 0.0.0.0 --port 1113
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lattice

[Install]
WantedBy=multi-user.target
EOF
    echo -e "${CHECKMARK}"

    run_quiet sudo systemctl daemon-reload

    run_with_status "Enabling Lattice service for auto-start" \
        sudo systemctl enable lattice.service

    print_success "Systemd service configured"

    if [ "$CONFIG_START_NOW" = "yes" ]; then
        echo ""
        start_service lattice.service systemctl
        sleep 2

        if sudo systemctl is-active --quiet lattice.service; then
            print_success "Lattice service is running"
        else
            print_warning "Lattice service may have failed to start"
            print_info "Check status: systemctl status lattice"
            print_info "View logs: journalctl -u lattice -n 50"
        fi
    fi
fi

# ============================================================================
# VERIFICATION
# ============================================================================

print_header "Step 4: Verification"

# Wait a moment for service to be ready
sleep 2

echo -ne "${DIM}${ARROW}${RESET} Checking /status endpoint... "
if curl -s http://localhost:1113/status > /dev/null 2>&1; then
    STATUS_RESPONSE=$(curl -s http://localhost:1113/status)
    echo -e "${CHECKMARK}"
    print_info "Response: $STATUS_RESPONSE"
else
    echo -e "${WARNING}"
    print_warning "Could not reach /status endpoint"
    if [ "$OS" = "linux" ] && [ "$CONFIG_INSTALL_SYSTEMD" = "yes" ]; then
        print_info "Check logs: journalctl -u lattice -f"
    else
        print_info "Start manually: cd $LATTICE_DIR && $PYTHON_CMD -m uvicorn lattice.discovery_daemon:app --port 1113"
    fi
fi

# ============================================================================
# COMPLETION
# ============================================================================

echo ""
echo ""
echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════╗"
echo "║     Lattice Deployment Complete!       ║"
echo "╚════════════════════════════════════════╝"
echo -e "${RESET}"
echo ""

print_success "Lattice installed and configured"

echo ""
echo -e "${BOLD}${BLUE}Federation Identity${RESET}"
print_info "Server ID: $SERVER_ID"
print_info "UUID: $SERVER_UUID"

echo ""
echo -e "${BOLD}${BLUE}Bootstrap Server${RESET}"
print_info "$CONFIG_BOOTSTRAP_SERVERS"

echo ""
echo -e "${BOLD}${BLUE}Endpoints${RESET}"
print_info "/status  - Public status (http://localhost:1113/status)"
print_info "/health  - Detailed health (localhost only)"

if [ "$OS" = "linux" ] && [ "$CONFIG_INSTALL_SYSTEMD" = "yes" ]; then
    echo ""
    echo -e "${BOLD}${BLUE}Service Management${RESET}"
    print_info "Status:  systemctl status lattice"
    print_info "Logs:    journalctl -u lattice -f"
    print_info "Stop:    sudo systemctl stop lattice"
    print_info "Start:   sudo systemctl start lattice"
fi

if [ "$OS" = "macos" ]; then
    echo ""
    echo -e "${BOLD}${YELLOW}macOS Notes${RESET}"
    print_info "Start manually:"
    print_info "  cd $LATTICE_DIR"
    print_info "  export VAULT_ADDR='http://127.0.0.1:8200'"
    print_info "  export VAULT_ROLE_ID=\$(cat /opt/vault/role-id.txt)"
    print_info "  export VAULT_SECRET_ID=\$(cat /opt/vault/secret-id.txt)"
    print_info "  $PYTHON_CMD -m uvicorn lattice.discovery_daemon:app --port 1113"
fi

echo ""
