#!/bin/bash
# ============================================================================
# MobileCoin ↔ NEAR Intent Demonstration Script
# ============================================================================
#
# This script demonstrates the complete flow of intents between
# MobileCoin and NEAR using the Marseille bridge infrastructure.
#
# Prerequisites:
#   - near-cli installed and logged in
#   - Contracts deployed (see DEPLOYMENT_PLAN.md)
#   - Solver running
#   - MOB wallet with funds (for real transactions)
#
# Usage:
#   ./demo_intent_flow.sh [--real]
#
#   Without --real: Simulates the flow with mock data
#   With --real: Executes actual on-chain transactions
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration - UPDATE THESE FOR YOUR DEPLOYMENT
NEAR_ENV="${NEAR_ENV:-mainnet}"
ADMIN_ACCOUNT="${ADMIN_ACCOUNT:-marseille-admin.near}"
WMOB_CONTRACT="${WMOB_CONTRACT:-wmob.marseille.near}"
BRIDGE_CONTRACT="${BRIDGE_CONTRACT:-bridge.marseille.near}"
VERIFIER_CONTRACT="${VERIFIER_CONTRACT:-verifier.marseille.near}"
SOLVER_ACCOUNT="${SOLVER_ACCOUNT:-solver.marseille.near}"
DEMO_USER="${DEMO_USER:-demo-user.near}"

# Demo amounts (in picoMOB - 12 decimals)
DEMO_AMOUNT="1000000000000"  # 1 MOB = 1_000_000_000_000 picoMOB

REAL_MODE=false
if [[ "$1" == "--real" ]]; then
    REAL_MODE=true
fi

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} $1"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "${YELLOW}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

wait_for_input() {
    if [[ "$REAL_MODE" == true ]]; then
        read -p "Press Enter to continue..."
    fi
}

# ============================================================================
# Demo: View Contract State
# ============================================================================

demo_view_state() {
    print_header "Phase 0: View Current Contract State"

    print_step "Checking wMOB token metadata..."
    if [[ "$REAL_MODE" == true ]]; then
        near view $WMOB_CONTRACT ft_metadata '{}' --networkId $NEAR_ENV
    else
        echo '  {
    "spec": "ft-1.0.0",
    "name": "Wrapped MobileCoin",
    "symbol": "wMOB",
    "decimals": 12
  }'
    fi

    print_step "Checking total wMOB supply..."
    if [[ "$REAL_MODE" == true ]]; then
        near view $WMOB_CONTRACT ft_total_supply '{}' --networkId $NEAR_ENV
    else
        echo '  "0"'
    fi

    print_step "Checking bridge configuration..."
    if [[ "$REAL_MODE" == true ]]; then
        near view $BRIDGE_CONTRACT get_custody_address '{}' --networkId $NEAR_ENV
        near view $BRIDGE_CONTRACT get_threshold '{}' --networkId $NEAR_ENV
        near view $BRIDGE_CONTRACT get_authority_count '{}' --networkId $NEAR_ENV
    else
        echo '  Custody Address: <MOB_ADDRESS>'
        echo '  Threshold: 2'
        echo '  Authority Count: 3'
    fi

    print_step "Checking verifier configuration..."
    if [[ "$REAL_MODE" == true ]]; then
        near view $VERIFIER_CONTRACT get_mob_config '{}' --networkId $NEAR_ENV
    else
        echo '  {
    "wmob_token": "wmob.marseille.near",
    "bridge_contract": "bridge.marseille.near",
    "min_amount": 1000000000,
    "max_amount": 1000000000000000,
    "active": true
  }'
    fi

    print_success "Contract state verified"
}

# ============================================================================
# Demo: MOB → wMOB Deposit Flow
# ============================================================================

demo_deposit_flow() {
    print_header "Phase 1: MOB → wMOB Deposit Flow"
    echo ""
    echo "This demonstrates how a user deposits MOB and receives wMOB on NEAR."
    echo ""

    # Step 1: User creates intent
    print_step "Step 1: User creates intent to deposit MOB"
    echo ""
    echo "  Intent Details:"
    echo "    Source:      1 MOB"
    echo "    Destination: wMOB on NEAR"
    echo "    Recipient:   $DEMO_USER"
    echo ""

    INTENT_ID="intent_deposit_$(date +%s)"
    DEADLINE=$(($(date +%s) + 3600))  # 1 hour from now

    echo "  Intent ID: $INTENT_ID"
    echo "  Deadline:  $DEADLINE"
    echo ""

    # Step 2: Sign the intent with MobileCoin key
    print_step "Step 2: User signs intent with MobileCoin private key"
    echo ""
    echo "  Message to sign:"
    echo '    MobileCoin Intent v1'
    echo "    intent_id: $INTENT_ID"
    echo '    source_asset: MOB'
    echo "    source_amount: $DEMO_AMOUNT"
    echo '    dest_asset: wMOB'
    echo "    dest_address: $DEMO_USER"
    echo "    deadline: $DEADLINE"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        print_info "In real mode, you would sign this with your MOB wallet"
        wait_for_input
    else
        echo "  Signature: ed25519:SIMULATED_SIGNATURE_ABC123..."
    fi

    # Step 3: Submit to verifier
    print_step "Step 3: Submit signed intent to verifier contract"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        # In real mode, this would call the verifier contract
        near call $VERIFIER_CONTRACT process_mob_intent '{
            "signed_intent": {
                "intent": {
                    "intent_id": "'$INTENT_ID'",
                    "source_asset": "MOB",
                    "source_amount": "'$DEMO_AMOUNT'",
                    "dest_asset": "wMOB",
                    "min_dest_amount": "'$DEMO_AMOUNT'",
                    "dest_address": "'$DEMO_USER'",
                    "refund_address": "MOB_REFUND_ADDRESS",
                    "deadline": '$DEADLINE',
                    "signer_public_key": "USER_MOB_PUBKEY_HEX"
                },
                "signature": "USER_SIGNATURE_HEX"
            }
        }' --accountId $DEMO_USER --networkId $NEAR_ENV
    else
        echo "  [SIMULATED] Intent submitted to verifier"
        echo "  EVENT: mob_intent {intent_id: $INTENT_ID}"
    fi

    # Step 4: Solver provides quote
    print_step "Step 4: Solver provides quote via solver bus"
    echo ""
    echo "  Quote from solver:"
    echo "    Solver ID:   marseille-solver-1"
    echo "    Dest Amount: 999500000000 (0.5% fee)"
    echo "    Expiry:      $((DEADLINE - 60))"
    echo ""

    # Step 5: Intent assigned to solver
    print_step "Step 5: Best quote wins, intent assigned to solver"
    echo ""
    echo "  Assigned to: marseille-solver-1"
    echo ""

    # Step 6: User sends MOB to custody
    print_step "Step 6: User sends MOB to bridge custody address"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        # Get custody address
        CUSTODY=$(near view $BRIDGE_CONTRACT get_custody_address '{}' --networkId $NEAR_ENV 2>/dev/null | tr -d '"')
        echo "  Custody Address: $CUSTODY"
        echo ""
        print_info "Send 1 MOB to the custody address using your MOB wallet"
        wait_for_input
    else
        echo "  [SIMULATED] 1 MOB sent to custody address"
        echo "  MOB TX Hash: mob_tx_123abc..."
    fi

    # Step 7: Authorities verify deposit
    print_step "Step 7: Bridge authorities verify MOB deposit"
    echo ""
    echo "  Authority 1: ✓ Verified"
    echo "  Authority 2: ✓ Verified"
    echo "  (2/3 threshold met)"
    echo ""

    # Step 8: Submit deposit proof
    print_step "Step 8: Solver submits deposit proof to bridge"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        # This would be called by the solver with real signatures
        print_info "Solver submitting deposit proof..."
        # near call $BRIDGE_CONTRACT deposit '{...}' ...
    else
        echo "  [SIMULATED] Deposit proof submitted"
        echo '  {
    "tx_hash": "mob_tx_123abc...",
    "amount": "'$DEMO_AMOUNT'",
    "recipient": "'$DEMO_USER'",
    "signatures": [...]
  }'
    fi

    # Step 9: wMOB minted to user
    print_step "Step 9: Bridge mints wMOB to user's NEAR account"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        # Check user's wMOB balance
        BALANCE=$(near view $WMOB_CONTRACT ft_balance_of '{"account_id": "'$DEMO_USER'"}' --networkId $NEAR_ENV 2>/dev/null)
        echo "  User wMOB balance: $BALANCE"
    else
        echo "  EVENT: ft_mint {owner: $DEMO_USER, amount: 999500000000}"
        echo "  User wMOB balance: 999500000000 (~0.9995 wMOB)"
    fi

    echo ""
    print_success "Deposit flow complete! User now has wMOB on NEAR."
}

# ============================================================================
# Demo: wMOB → MOB Withdrawal Flow
# ============================================================================

demo_withdrawal_flow() {
    print_header "Phase 2: wMOB → MOB Withdrawal Flow"
    echo ""
    echo "This demonstrates how a user withdraws wMOB to receive MOB."
    echo ""

    # Step 1: User creates withdrawal intent
    print_step "Step 1: User creates withdrawal request"
    echo ""

    # Example MobileCoin address (Base58Check, 66+ chars)
    MOB_DEST_ADDRESS="2mGjuQNPWLJQABHNBaQoUgqmC3ZZYqYLqvHUxKJZX9KYvFSoiqwHnm7D2uCZNfcbgvWsNXE"

    echo "  Withdrawal Details:"
    echo "    Amount:      1 wMOB ($DEMO_AMOUNT picoMOB)"
    echo "    Destination: $MOB_DEST_ADDRESS"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        print_step "Submitting withdrawal to bridge..."
        near call $BRIDGE_CONTRACT withdraw '{
            "mob_destination": "'$MOB_DEST_ADDRESS'",
            "amount": "'$DEMO_AMOUNT'"
        }' --accountId $DEMO_USER --deposit 0.01 --networkId $NEAR_ENV
    else
        echo "  [SIMULATED] Withdrawal request submitted"
        echo "  Withdrawal ID: 0"
        echo "  Status: Burning"
    fi

    # Step 2: wMOB burned
    print_step "Step 2: Bridge burns user's wMOB"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        # Check if burn succeeded
        WITHDRAWAL=$(near view $BRIDGE_CONTRACT get_withdrawal '{"withdrawal_id": 0}' --networkId $NEAR_ENV 2>/dev/null)
        echo "  Withdrawal status: $WITHDRAWAL"
    else
        echo "  EVENT: ft_burn {owner: $DEMO_USER, amount: $DEMO_AMOUNT}"
        echo "  Status: Pending"
    fi

    # Step 3: Authorities process withdrawal
    print_step "Step 3: Bridge authorities process withdrawal off-chain"
    echo ""
    echo "  Authority 1: Processing..."
    echo "  Authority 2: Processing..."
    echo ""

    # Step 4: MOB sent to user
    print_step "Step 4: Authorities send MOB to user's stealth address"
    echo ""
    echo "  MOB TX Hash: mob_withdrawal_xyz789..."
    echo ""

    # Step 5: Completion proof submitted
    print_step "Step 5: Authorities submit completion proof"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        print_info "Authorities would submit completion proof here"
        # near call $BRIDGE_CONTRACT complete_withdrawal '{...}'
    else
        echo "  [SIMULATED] Completion proof submitted"
        echo '  {
    "withdrawal_id": 0,
    "mob_tx_hash": "mob_withdrawal_xyz789...",
    "signatures": [...]
  }'
    fi

    # Step 6: Verify completion
    print_step "Step 6: Verify withdrawal completed"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        WITHDRAWAL=$(near view $BRIDGE_CONTRACT get_withdrawal '{"withdrawal_id": 0}' --networkId $NEAR_ENV 2>/dev/null)
        echo "  Withdrawal: $WITHDRAWAL"
    else
        echo '  Status: Completed'
        echo '  MOB TX: mob_withdrawal_xyz789...'
    fi

    echo ""
    print_success "Withdrawal flow complete! User received MOB."
}

# ============================================================================
# Demo: Cross-Chain Intent (MOB → USDC via wMOB)
# ============================================================================

demo_cross_chain_swap() {
    print_header "Phase 3: Cross-Chain Swap (MOB → USDC)"
    echo ""
    echo "This demonstrates a more complex swap: MOB → wMOB → USDC"
    echo "The solver handles this as two internal steps."
    echo ""

    print_step "Step 1: User creates MOB → USDC intent"
    echo ""
    echo "  Intent Details:"
    echo "    Source:      1 MOB"
    echo "    Destination: USDC"
    echo "    Min Output:  0.49 USDC (assuming MOB ≈ \$0.50)"
    echo ""

    print_step "Step 2: Solver breaks down into steps"
    echo ""
    echo "  Internal flow:"
    echo "    1. MOB → wMOB (via bridge)"
    echo "    2. wMOB → USDC (via DEX swap on NEAR)"
    echo ""

    print_step "Step 3: Solver executes..."
    echo ""
    echo "  [a] User deposits MOB to custody"
    echo "  [b] Solver mints wMOB via bridge"
    echo "  [c] Solver swaps wMOB → USDC on Ref Finance"
    echo "  [d] Solver sends USDC to user"
    echo ""

    print_step "Step 4: Settlement complete"
    echo ""
    echo "  User received: 0.49 USDC"
    echo "  Solver profit: ~0.005 USDC (1%)"
    echo ""

    print_success "Cross-chain swap complete!"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     MobileCoin ↔ NEAR Intent Bridge Demonstration             ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}║     Project: Marseille                                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$REAL_MODE" == true ]]; then
        echo -e "${RED}⚠  REAL MODE ENABLED - Actual transactions will be executed!${NC}"
        echo ""
        echo "Configuration:"
        echo "  NEAR_ENV:      $NEAR_ENV"
        echo "  Admin:         $ADMIN_ACCOUNT"
        echo "  wMOB Contract: $WMOB_CONTRACT"
        echo "  Bridge:        $BRIDGE_CONTRACT"
        echo "  Verifier:      $VERIFIER_CONTRACT"
        echo ""
        read -p "Continue with real transactions? (yes/no): " confirm
        if [[ "$confirm" != "yes" ]]; then
            echo "Aborted."
            exit 1
        fi
    else
        echo -e "${YELLOW}SIMULATION MODE - No actual transactions will be executed${NC}"
        echo "Run with --real to execute actual on-chain transactions"
        echo ""
    fi

    # Run demo phases
    demo_view_state
    echo ""
    wait_for_input

    demo_deposit_flow
    echo ""
    wait_for_input

    demo_withdrawal_flow
    echo ""
    wait_for_input

    demo_cross_chain_swap

    # Summary
    print_header "Demo Complete!"
    echo ""
    echo "Summary of demonstrated flows:"
    echo ""
    echo "  1. MOB → wMOB (Deposit)"
    echo "     User deposits MOB, receives wMOB on NEAR"
    echo ""
    echo "  2. wMOB → MOB (Withdrawal)"
    echo "     User burns wMOB, receives MOB via stealth address"
    echo ""
    echo "  3. MOB → USDC (Cross-chain)"
    echo "     Complex swap handled by solver in multiple steps"
    echo ""
    echo "For more information:"
    echo "  - See DEPLOYMENT_PLAN.md for deployment instructions"
    echo "  - See docs/architecture.md for system design"
    echo "  - See docs/solver-guide.md for running a solver"
    echo ""
    print_success "Thank you for watching the Marseille demo!"
}

# Run main
main "$@"
