#!/bin/bash
# ============================================================================
# MobileCoin-NEAR Bridge: TESTNET Deployment Script
# ============================================================================
#
# Deploys all contracts to NEAR testnet for testing.
#
# Accounts created:
#   - marseille-mob.testnet (admin)
#   - wmob-marseille.testnet (wMOB token)
#   - bridge-marseille.testnet (bridge)
#   - verifier-marseille.testnet (verifier)
#   - solver-marseille.testnet (solver)
#
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================================
# Configuration
# ============================================================================

export NEAR_ENV=testnet

# Account names
ADMIN_ACCOUNT="marseille-mob.testnet"
WMOB_ACCOUNT="wmob-marseille.testnet"
BRIDGE_ACCOUNT="bridge-marseille.testnet"
VERIFIER_ACCOUNT="verifier-marseille.testnet"
SOLVER_ACCOUNT="solver-marseille.testnet"

# Load keys from wallet-keys.json
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS_FILE="$PROJECT_DIR/secrets/wallet-keys.json"
WASM_DIR="$PROJECT_DIR/target/wasm32-unknown-unknown/release"

# Read authority keys from generated wallet
if [[ -f "$SECRETS_FILE" ]]; then
    AUTHORITY1=$(jq -r '.environment_variables.AUTHORITY1' "$SECRETS_FILE")
    AUTHORITY2=$(jq -r '.environment_variables.AUTHORITY2' "$SECRETS_FILE")
    AUTHORITY3=$(jq -r '.environment_variables.AUTHORITY3' "$SECRETS_FILE")
    MOB_CUSTODY_ADDRESS=$(jq -r '.environment_variables.MOB_CUSTODY_ADDRESS' "$SECRETS_FILE")
else
    echo -e "${RED}Error: secrets/wallet-keys.json not found${NC}"
    echo "Run: cargo run --example generate-keys -p mobilecoin-crypto"
    exit 1
fi

# Bridge threshold
THRESHOLD=2

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

print_step() {
    echo -e "${YELLOW}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# ============================================================================
# Build Contracts
# ============================================================================

build_contracts() {
    print_header "Building Contracts"

    cd "$PROJECT_DIR"

    print_step "Building all WASM contracts..."
    RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown \
        -p wmob-token -p mob-bridge -p defuse-mobilecoin 2>&1 | tail -10

    # Verify builds
    for contract in wmob_token mob_bridge defuse_mobilecoin; do
        WASM_FILE="$WASM_DIR/${contract}.wasm"
        if [[ -f "$WASM_FILE" ]]; then
            SIZE=$(ls -la "$WASM_FILE" | awk '{print $5}')
            print_success "$contract.wasm built ($SIZE bytes)"
        else
            print_error "$contract.wasm not found!"
            exit 1
        fi
    done
}

# ============================================================================
# Deploy Contracts
# ============================================================================

deploy_wmob() {
    print_header "Deploying wMOB Token Contract"

    # Find the wasm file
    WASM_FILE=$(find "$PROJECT_DIR/target" -name "wmob_token.wasm" -type f 2>/dev/null | head -1)

    if [[ -z "$WASM_FILE" ]]; then
        print_error "wmob_token.wasm not found"
        exit 1
    fi

    print_step "Deploying to $WMOB_ACCOUNT..."
    print_step "Using WASM: $WASM_FILE"

    near contract deploy $WMOB_ACCOUNT use-file "$WASM_FILE" \
        with-init-call new json-args "{\"bridge_contract\": \"$BRIDGE_ACCOUNT\", \"owner\": \"$ADMIN_ACCOUNT\"}" \
        prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
        network-config testnet sign-with-keychain send

    print_success "wMOB token deployed"
}

deploy_bridge() {
    print_header "Deploying Bridge Contract"

    WASM_FILE=$(find "$PROJECT_DIR/target" -name "mob_bridge.wasm" -type f 2>/dev/null | head -1)

    if [[ -z "$WASM_FILE" ]]; then
        print_error "mob_bridge.wasm not found"
        exit 1
    fi

    print_step "Deploying to $BRIDGE_ACCOUNT..."

    # Build the init args JSON
    INIT_ARGS=$(cat <<EOF
{
    "wmob_token": "$WMOB_ACCOUNT",
    "authorities": ["$AUTHORITY1", "$AUTHORITY2", "$AUTHORITY3"],
    "threshold": $THRESHOLD,
    "mob_custody_address": "$MOB_CUSTODY_ADDRESS"
}
EOF
)

    near contract deploy $BRIDGE_ACCOUNT use-file "$WASM_FILE" \
        with-init-call new json-args "$INIT_ARGS" \
        prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
        network-config testnet sign-with-keychain send

    print_success "Bridge deployed"
}

deploy_verifier() {
    print_header "Deploying Verifier Contract"

    WASM_FILE=$(find "$PROJECT_DIR/target" -name "defuse_mobilecoin.wasm" -type f 2>/dev/null | head -1)

    if [[ -z "$WASM_FILE" ]]; then
        print_error "defuse_mobilecoin.wasm not found"
        exit 1
    fi

    print_step "Deploying to $VERIFIER_ACCOUNT..."

    near contract deploy $VERIFIER_ACCOUNT use-file "$WASM_FILE" \
        with-init-call new json-args '{}' \
        prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
        network-config testnet sign-with-keychain send

    print_success "Verifier deployed"

    # Register MobileCoin chain
    print_step "Registering MobileCoin chain..."

    REGISTER_ARGS=$(cat <<EOF
{
    "wmob_token": "$WMOB_ACCOUNT",
    "bridge_contract": "$BRIDGE_ACCOUNT",
    "min_amount": 1000000000,
    "max_amount": 1000000000000000
}
EOF
)

    near contract call-function as-transaction $VERIFIER_ACCOUNT register_mobilecoin_chain \
        json-args "$REGISTER_ARGS" \
        prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
        sign-as $ADMIN_ACCOUNT \
        network-config testnet sign-with-keychain send

    print_success "MobileCoin chain registered"
}

# ============================================================================
# Setup Storage
# ============================================================================

setup_storage() {
    print_header "Setting Up Storage"

    print_step "Registering storage for bridge..."
    near contract call-function as-transaction $WMOB_ACCOUNT storage_deposit \
        json-args "{\"account_id\": \"$BRIDGE_ACCOUNT\"}" \
        prepaid-gas '30.0 Tgas' attached-deposit '0.01 NEAR' \
        sign-as $ADMIN_ACCOUNT \
        network-config testnet sign-with-keychain send

    print_step "Registering storage for solver..."
    near contract call-function as-transaction $WMOB_ACCOUNT storage_deposit \
        json-args "{\"account_id\": \"$SOLVER_ACCOUNT\"}" \
        prepaid-gas '30.0 Tgas' attached-deposit '0.01 NEAR' \
        sign-as $ADMIN_ACCOUNT \
        network-config testnet sign-with-keychain send

    print_step "Registering storage for admin..."
    near contract call-function as-transaction $WMOB_ACCOUNT storage_deposit \
        json-args "{\"account_id\": \"$ADMIN_ACCOUNT\"}" \
        prepaid-gas '30.0 Tgas' attached-deposit '0.01 NEAR' \
        sign-as $ADMIN_ACCOUNT \
        network-config testnet sign-with-keychain send

    print_success "Storage registered"
}

# ============================================================================
# Verify Deployment
# ============================================================================

verify_deployment() {
    print_header "Verifying Deployment"

    print_step "Checking wMOB token metadata..."
    near contract call-function as-read-only $WMOB_ACCOUNT ft_metadata json-args '{}' \
        network-config testnet now

    print_step "Checking bridge configuration..."
    near contract call-function as-read-only $BRIDGE_ACCOUNT get_threshold json-args '{}' \
        network-config testnet now
    near contract call-function as-read-only $BRIDGE_ACCOUNT get_authority_count json-args '{}' \
        network-config testnet now
    near contract call-function as-read-only $BRIDGE_ACCOUNT get_custody_address json-args '{}' \
        network-config testnet now

    print_step "Checking verifier configuration..."
    near contract call-function as-read-only $VERIFIER_ACCOUNT get_mob_config json-args '{}' \
        network-config testnet now

    print_success "All contracts verified"
}

# ============================================================================
# Print Summary
# ============================================================================

print_summary() {
    print_header "Deployment Complete!"

    echo ""
    echo "Testnet Contracts:"
    echo "  Admin:     $ADMIN_ACCOUNT"
    echo "  wMOB:      $WMOB_ACCOUNT"
    echo "  Bridge:    $BRIDGE_ACCOUNT"
    echo "  Verifier:  $VERIFIER_ACCOUNT"
    echo "  Solver:    $SOLVER_ACCOUNT"
    echo ""
    echo "Explorer Links:"
    echo "  https://explorer.testnet.near.org/accounts/$WMOB_ACCOUNT"
    echo "  https://explorer.testnet.near.org/accounts/$BRIDGE_ACCOUNT"
    echo "  https://explorer.testnet.near.org/accounts/$VERIFIER_ACCOUNT"
    echo ""
    echo "MobileCoin Custody:"
    echo "  $MOB_CUSTODY_ADDRESS"
    echo ""
    echo "Bridge Authorities (2-of-3):"
    echo "  1: $AUTHORITY1"
    echo "  2: $AUTHORITY2"
    echo "  3: $AUTHORITY3"
    echo ""
    print_success "Ready to test!"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   MobileCoin-NEAR Bridge: TESTNET Deployment                   ║${NC}"
    echo -e "${CYAN}║   Project: Marseille                                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo "This will deploy contracts to NEAR testnet:"
    echo "  • wMOB Token → $WMOB_ACCOUNT"
    echo "  • Bridge     → $BRIDGE_ACCOUNT"
    echo "  • Verifier   → $VERIFIER_ACCOUNT"
    echo ""

    read -p "Proceed? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted."
        exit 1
    fi

    build_contracts
    deploy_wmob
    deploy_bridge
    deploy_verifier
    setup_storage
    verify_deployment
    print_summary
}

# Run main
main "$@"
