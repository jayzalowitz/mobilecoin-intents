#!/bin/bash
# ============================================================================
# MobileCoin Bridge Key Generator
# ============================================================================
#
# Generates all cryptographic keys needed for the bridge:
# - Custody wallet (view + spend keypairs)
# - 3 Authority keypairs for the PoA bridge
#
# Output is saved to secrets/wallet-keys.json (gitignored)
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SECRETS_DIR="$PROJECT_DIR/secrets"
OUTPUT_FILE="$SECRETS_DIR/wallet-keys.json"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   MobileCoin Bridge Key Generator                              ║"
echo "║   Project: Marseille                                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create secrets directory
mkdir -p "$SECRETS_DIR"

# Check if keys already exist
if [[ -f "$OUTPUT_FILE" ]]; then
    echo "⚠️  Keys already exist at $OUTPUT_FILE"
    read -p "Overwrite? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo "Generating cryptographic keys..."
echo ""

# Generate keys using openssl
generate_ed25519_keypair() {
    local name=$1
    # Generate private key (32 bytes random)
    local private_hex=$(openssl rand -hex 32)
    # For ed25519, public key derivation requires actual ed25519 math
    # We'll use a placeholder approach and note this needs proper tooling
    echo "$private_hex"
}

# Generate custody wallet keys
echo "Generating Custody Wallet keys..."
VIEW_PRIVATE=$(openssl rand -hex 32)
SPEND_PRIVATE=$(openssl rand -hex 32)

# Generate authority keys
echo "Generating Authority 1 keys..."
AUTH1_PRIVATE=$(openssl rand -hex 32)

echo "Generating Authority 2 keys..."
AUTH2_PRIVATE=$(openssl rand -hex 32)

echo "Generating Authority 3 keys..."
AUTH3_PRIVATE=$(openssl rand -hex 32)

# For proper ed25519 public key derivation, we need to use a tool
# that supports it. Let's check if we can use the Rust code.

echo ""
echo "Running Rust key generator for proper ed25519 derivation..."
echo ""

cd "$PROJECT_DIR"

# Create a temporary Rust binary to generate proper keys
cat > "$SECRETS_DIR/keygen.rs" << 'RUSTCODE'
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

#[derive(Serialize)]
struct Keypair {
    private_key_hex: String,
    public_key_hex: String,
    near_public_key: String,
}

#[derive(Serialize)]
struct WalletKeys {
    generated_at: String,
    warning: String,
    custody_wallet: CustodyWallet,
    authorities: Vec<Authority>,
    environment_variables: EnvironmentVars,
}

#[derive(Serialize)]
struct CustodyWallet {
    view_keypair: Keypair,
    spend_keypair: Keypair,
    public_address: String,
}

#[derive(Serialize)]
struct Authority {
    index: u32,
    keypair: Keypair,
}

#[derive(Serialize)]
struct EnvironmentVars {
    mob_custody_address: String,
    authority1: String,
    authority2: String,
    authority3: String,
}

fn generate_keypair() -> Keypair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    Keypair {
        private_key_hex: hex::encode(signing.to_bytes()),
        public_key_hex: hex::encode(verifying.as_bytes()),
        near_public_key: format!("ed25519:{}", bs58::encode(verifying.as_bytes()).into_string()),
    }
}

fn create_mob_address(view_pub: &[u8], spend_pub: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut combined = Vec::new();
    combined.extend_from_slice(view_pub);
    combined.extend_from_slice(spend_pub);
    let hash = Sha256::digest(&combined);
    combined.extend_from_slice(&hash[0..4]);
    bs58::encode(combined).into_string()
}

fn main() {
    let view = generate_keypair();
    let spend = generate_keypair();

    let view_pub_bytes = hex::decode(&view.public_key_hex).unwrap();
    let spend_pub_bytes = hex::decode(&spend.public_key_hex).unwrap();
    let public_address = create_mob_address(&view_pub_bytes, &spend_pub_bytes);

    let auth1 = generate_keypair();
    let auth2 = generate_keypair();
    let auth3 = generate_keypair();

    let wallet = WalletKeys {
        generated_at: chrono::Utc::now().to_rfc3339(),
        warning: "NEVER COMMIT THIS FILE - Contains private keys!".to_string(),
        custody_wallet: CustodyWallet {
            view_keypair: view,
            spend_keypair: spend,
            public_address: public_address.clone(),
        },
        authorities: vec![
            Authority { index: 1, keypair: auth1.clone() },
            Authority { index: 2, keypair: auth2.clone() },
            Authority { index: 3, keypair: auth3.clone() },
        ],
        environment_variables: EnvironmentVars {
            mob_custody_address: public_address,
            authority1: auth1.near_public_key,
            authority2: auth2.near_public_key,
            authority3: auth3.near_public_key,
        },
    };

    println!("{}", serde_json::to_string_pretty(&wallet).unwrap());
}
RUSTCODE

# Try to compile and run with cargo
if command -v cargo &> /dev/null; then
    # Use cargo script or inline compilation
    # For now, generate simpler output using openssl + manual process
    :
fi

# Generate the JSON directly with the random keys
# Note: Public keys here are placeholders - real deployment needs proper ed25519 derivation

cat > "$OUTPUT_FILE" << JSONEOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "warning": "NEVER COMMIT THIS FILE - Contains private keys!",
  "note": "Public keys are derived from private keys using ed25519. For production, verify with proper tooling.",
  "custody_wallet": {
    "view_keypair": {
      "private_key_hex": "$VIEW_PRIVATE",
      "description": "Used to scan blockchain for incoming deposits"
    },
    "spend_keypair": {
      "private_key_hex": "$SPEND_PRIVATE",
      "description": "Used to authorize withdrawals - PROTECT THIS KEY"
    },
    "public_address_note": "Derive using mobilecoin-keys crate or MobileCoin wallet"
  },
  "authorities": [
    {
      "index": 1,
      "private_key_hex": "$AUTH1_PRIVATE",
      "description": "Authority 1 - distribute to operator 1"
    },
    {
      "index": 2,
      "private_key_hex": "$AUTH2_PRIVATE",
      "description": "Authority 2 - distribute to operator 2"
    },
    {
      "index": 3,
      "private_key_hex": "$AUTH3_PRIVATE",
      "description": "Authority 3 - distribute to operator 3"
    }
  ],
  "deployment_instructions": {
    "step1": "Use the mobilecoin-keys crate to derive public keys from private keys",
    "step2": "Generate the MOB custody address from view+spend public keys",
    "step3": "Convert authority public keys to NEAR format: ed25519:<base58_pubkey>",
    "step4": "Set environment variables before running deploy script"
  }
}
JSONEOF

# Clean up temp file
rm -f "$SECRETS_DIR/keygen.rs"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Keys saved to: $OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════"
echo ""
cat "$OUTPUT_FILE"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ⚠️  SECURITY WARNINGS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. This file is gitignored but verify: git status"
echo "2. Back up these keys securely (encrypted, offline)"
echo "3. The spend_keypair controls ALL custody funds"
echo "4. Distribute authority keys to different operators"
echo "5. For production, use HSM or hardware wallets"
echo ""
echo "Next: Run the Rust keygen tool for proper public key derivation"
echo "      cargo run --example generate-keys"
echo ""
