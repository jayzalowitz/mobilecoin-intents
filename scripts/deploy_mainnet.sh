#!/bin/bash
# ============================================================================
# MobileCoin-NEAR Bridge: Mainnet Deployment Script
# ============================================================================
#
# This script deploys all contracts to NEAR mainnet with pseudonymous accounts.
#
# Prerequisites:
#   - near-cli installed
#   - Rust + wasm32-unknown-unknown target
#   - Accounts created and funded
#
# Usage:
#   ./deploy_mainnet.sh
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
# Configuration - CUSTOMIZE THESE
# ============================================================================

# Network
export NEAR_ENV="${NEAR_ENV:-mainnet}"

# Account names (pseudonymous)
ADMIN_ACCOUNT="${ADMIN_ACCOUNT:-marseille-mob.near}"
WMOB_ACCOUNT="${WMOB_ACCOUNT:-wmob-marseille.near}"
BRIDGE_ACCOUNT="${BRIDGE_ACCOUNT:-bridge-marseille.near}"
VERIFIER_ACCOUNT="${VERIFIER_ACCOUNT:-verifier-marseille.near}"

# MobileCoin custody address (REPLACE WITH REAL ADDRESS)
MOB_CUSTODY_ADDRESS="${MOB_CUSTODY_ADDRESS:-REPLACE_WITH_REAL_MOB_CUSTODY_ADDRESS}"

# Authority public keys (REPLACE WITH REAL KEYS)
# Format: ed25519:<base58_pubkey>
AUTHORITY1="${AUTHORITY1:-ed25519:REPLACE_WITH_AUTHORITY1_PUBKEY}"
AUTHORITY2="${AUTHORITY2:-ed25519:REPLACE_WITH_AUTHORITY2_PUBKEY}"
AUTHORITY3="${AUTHORITY3:-ed25519:REPLACE_WITH_AUTHORITY3_PUBKEY}"

# Bridge threshold (2-of-3 by default)
THRESHOLD="${THRESHOLD:-2}"

# Build directory
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WASM_DIR="$PROJECT_DIR/target/wasm32-unknown-unknown/release"

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

check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check near-cli
    if ! command -v near &> /dev/null; then
        print_error "near-cli not found. Install with: npm install -g near-cli"
        exit 1
    fi
    print_success "near-cli found"

    # Check Rust
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo not found. Install Rust from https://rustup.rs"
        exit 1
    fi
    print_success "Cargo found"

    # Check wasm target
    if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
        print_step "Installing wasm32-unknown-unknown target..."
        rustup target add wasm32-unknown-unknown
    fi
    print_success "wasm32-unknown-unknown target installed"

    # Check custody address is set
    if [[ "$MOB_CUSTODY_ADDRESS" == "REPLACE_WITH_REAL_MOB_CUSTODY_ADDRESS" ]]; then
        print_error "MOB_CUSTODY_ADDRESS not set. Set it before deployment."
        exit 1
    fi
    print_success "Custody address configured"
}

build_contracts() {
    print_header "Building Contracts"

    cd "$PROJECT_DIR"

    print_step "Building optimized WASM binaries..."
    RUSTFLAGS='-C link-arg=-s' cargo build \
        --release \
        --target wasm32-unknown-unknown \
        -p wmob-token \
        -p mob-bridge \
        -p defuse-mobilecoin

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

create_accounts() {
    print_header "Creating Accounts (if needed)"

    for account in $ADMIN_ACCOUNT $WMOB_ACCOUNT $BRIDGE_ACCOUNT $VERIFIER_ACCOUNT; do
        print_step "Checking $account..."
        if near state $account --networkId $NEAR_ENV &> /dev/null; then
            print_success "$account exists"
        else
            print_step "Creating $account..."
            # Note: On mainnet, accounts need to be created via a registrar
            # or by purchasing a .near name
            echo "  Account $account does not exist."
            echo "  Create it at https://wallet.near.org or via near-cli"
            echo ""
            read -p "  Press Enter once account is created, or Ctrl+C to abort..."
        fi
    done
}

deploy_wmob_token() {
    print_header "Deploying wMOB Token Contract"

    print_step "Deploying to $WMOB_ACCOUNT..."

    near deploy $WMOB_ACCOUNT \
        "$WASM_DIR/wmob_token.wasm" \
        --initFunction new \
        --initArgs "{
            \"bridge_contract\": \"$BRIDGE_ACCOUNT\",
            \"owner\": \"$ADMIN_ACCOUNT\"
        }" \
        --networkId $NEAR_ENV

    print_success "wMOB token deployed to $WMOB_ACCOUNT"

    # Verify deployment
    print_step "Verifying deployment..."
    near view $WMOB_ACCOUNT ft_metadata '{}' --networkId $NEAR_ENV
}

deploy_bridge() {
    print_header "Deploying Bridge Contract"

    print_step "Deploying to $BRIDGE_ACCOUNT..."

    near deploy $BRIDGE_ACCOUNT \
        "$WASM_DIR/mob_bridge.wasm" \
        --initFunction new \
        --initArgs "{
            \"wmob_token\": \"$WMOB_ACCOUNT\",
            \"authorities\": [
                \"$AUTHORITY1\",
                \"$AUTHORITY2\",
                \"$AUTHORITY3\"
            ],
            \"threshold\": $THRESHOLD,
            \"mob_custody_address\": \"$MOB_CUSTODY_ADDRESS\"
        }" \
        --networkId $NEAR_ENV

    print_success "Bridge deployed to $BRIDGE_ACCOUNT"

    # Verify deployment
    print_step "Verifying deployment..."
    near view $BRIDGE_ACCOUNT get_threshold '{}' --networkId $NEAR_ENV
    near view $BRIDGE_ACCOUNT get_authority_count '{}' --networkId $NEAR_ENV
}

deploy_verifier() {
    print_header "Deploying Verifier Contract"

    print_step "Deploying to $VERIFIER_ACCOUNT..."

    near deploy $VERIFIER_ACCOUNT \
        "$WASM_DIR/defuse_mobilecoin.wasm" \
        --initFunction new \
        --initArgs '{}' \
        --networkId $NEAR_ENV

    print_success "Verifier deployed to $VERIFIER_ACCOUNT"

    # Register MobileCoin chain
    print_step "Registering MobileCoin chain..."

    near call $VERIFIER_ACCOUNT register_mobilecoin_chain "{
        \"wmob_token\": \"$WMOB_ACCOUNT\",
        \"bridge_contract\": \"$BRIDGE_ACCOUNT\",
        \"min_amount\": 1000000000,
        \"max_amount\": 1000000000000000
    }" --accountId $ADMIN_ACCOUNT --networkId $NEAR_ENV

    print_success "MobileCoin chain registered"
}

setup_storage() {
    print_header "Setting Up Storage"

    # Register storage for bridge on wmob token
    print_step "Registering storage for bridge account..."
    near call $WMOB_ACCOUNT storage_deposit "{\"account_id\": \"$BRIDGE_ACCOUNT\"}" \
        --accountId $ADMIN_ACCOUNT --deposit 0.01 --networkId $NEAR_ENV

    # Register storage for admin
    print_step "Registering storage for admin account..."
    near call $WMOB_ACCOUNT storage_deposit "{\"account_id\": \"$ADMIN_ACCOUNT\"}" \
        --accountId $ADMIN_ACCOUNT --deposit 0.01 --networkId $NEAR_ENV

    print_success "Storage registered"
}

print_summary() {
    print_header "Deployment Complete!"

    echo ""
    echo "Deployed Contracts:"
    echo "  wMOB Token:  $WMOB_ACCOUNT"
    echo "  Bridge:      $BRIDGE_ACCOUNT"
    echo "  Verifier:    $VERIFIER_ACCOUNT"
    echo ""
    echo "Configuration:"
    echo "  Network:     $NEAR_ENV"
    echo "  Admin:       $ADMIN_ACCOUNT"
    echo "  Threshold:   $THRESHOLD of 3 authorities"
    echo ""
    echo "Next Steps:"
    echo "  1. Fund the solver account and register its storage"
    echo "  2. Start the solver: cargo run --release -p solver-mobilecoin"
    echo "  3. Run the demo: ./scripts/demo_intent_flow.sh"
    echo ""
    print_success "Ready for operation!"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   MobileCoin-NEAR Bridge: Mainnet Deployment                   ║${NC}"
    echo -e "${CYAN}║   Project: Marseille                                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo "This script will deploy the following contracts:"
    echo "  • wMOB Token     → $WMOB_ACCOUNT"
    echo "  • MOB Bridge     → $BRIDGE_ACCOUNT"
    echo "  • Verifier       → $VERIFIER_ACCOUNT"
    echo ""
    echo "Network: $NEAR_ENV"
    echo ""

    read -p "Proceed with deployment? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted."
        exit 1
    fi

    check_prerequisites
    build_contracts
    create_accounts
    deploy_wmob_token
    deploy_bridge
    deploy_verifier
    setup_storage
    print_summary
}

# Run main
main "$@"
