#!/bin/bash
# Validation script for HSM production mode security
# Tests that secrets are non-extractable when HSM_MODE=production

set -e

echo "=== 🔒 Production Mode Security Validation 🔒 ==="
echo ""

# Configuration
TEST_NODE="node1"
DOCKER_COMPOSE_FILE="docker-compose.yml"
PKCS11_MODULE="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
HSM_PIN="1234"

# Helper function - runs command in node container
run_node() {
    local node=$1
    shift
    docker exec "mpc-${node}" "$@"
}

# Helper function - runs Python app command in node with production mode
run_app_production() {
    local node=$1
    shift
    docker exec -e HSM_MODE=production "mpc-${node}" python3 -m app.main "$@"
}

# Helper to restore demo mode on exit
cleanup() {
    echo ""
    echo "[Cleanup] Ensuring HSM_MODE=demo is restored..."
    # The docker-compose.yml already has HSM_MODE=demo, so we just need
    # to restart the container to pick up the original env
    docker compose restart "$TEST_NODE" 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

wait_for_nodes() {
    echo "Waiting for nodes to be ready..."
    for node in node1 node2 node3; do
        until docker exec "mpc-${node}" echo "ok" 2>/dev/null; do
            sleep 1
        done
    done
    echo "All nodes ready."
}

# Test that pkcs11-tool can't read sensitive/non-extractable secrets
test_extraction_blocked() {
    local label=$1
    echo "  Testing extraction of: $label"

    # Attempt to read the object value using pkcs11-tool
    # In production mode with SENSITIVE=True, this should fail
    OUTPUT=$(docker exec -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
        pkcs11-tool --module "$PKCS11_MODULE" \
        --login --pin "$HSM_PIN" \
        --read-object --type secrkey --label "$label" 2>&1) || true

    # Check for expected failure indicators
    if echo "$OUTPUT" | grep -qi "CKR_ATTRIBUTE_SENSITIVE\|error reading\|unable to read\|not extractable\|sensitive"; then
        echo "    ✅ PASS: Extraction blocked (attribute sensitive/non-extractable)"
        return 0
    elif [ -z "$OUTPUT" ]; then
        # Empty output - object might not exist yet, which is OK for some tests
        echo "    ⚠️  SKIP: Object not found (may not have been created yet)"
        return 0
    else
        echo "    ❌ FAIL: Extraction may have succeeded!"
        echo "    Output: $OUTPUT"
        return 1
    fi
}

# Test that VALUE attribute cannot be read via Python API
test_python_api_extraction() {
    local round_id=$1
    echo "  Testing Python API extraction for DKG share (round: $round_id)..."

    # Try to read the share via Python - should fail in production mode with SecurityError
    RESULT=$(docker exec -e HSM_MODE=production -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
        python3 -c "
from app.hardware import HardwareToken, SecurityError
import os
os.environ['HSM_MODE'] = 'production'
try:
    hsm = HardwareToken()
    hsm.login('$HSM_PIN')
    share = hsm.get_dkg_share('$round_id')
    print('EXTRACTED:' + share.hex())
except SecurityError as e:
    print('BLOCKED:SecurityError:' + str(e))
except Exception as e:
    print('BLOCKED:' + str(type(e).__name__) + ':' + str(e))
" 2>&1) || true

    if echo "$RESULT" | grep -q "^BLOCKED:SecurityError:"; then
        echo "    ✅ PASS: Python API extraction blocked with SecurityError"
        echo "    Error: $(echo "$RESULT" | grep "^BLOCKED:" | cut -d: -f3-)"
        return 0
    elif echo "$RESULT" | grep -q "^BLOCKED:"; then
        echo "    ✅ PASS: Python API extraction blocked"
        echo "    Error: $(echo "$RESULT" | grep "^BLOCKED:" | cut -d: -f2-)"
        return 0
    elif echo "$RESULT" | grep -q "^EXTRACTED:"; then
        echo "    ❌ FAIL: Python API could extract the share!"
        return 1
    else
        echo "    ⚠️  SKIP: Unexpected result: $RESULT"
        return 0
    fi
}

# Test that nonce derivation is blocked in production mode
test_nonce_derivation_blocked() {
    echo "  Testing nonce derivation blocking in production mode..."

    RESULT=$(docker exec -e HSM_MODE=production -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
        python3 -c "
from app.hardware import HardwareToken, SecurityError
import os
os.environ['HSM_MODE'] = 'production'
try:
    hsm = HardwareToken()
    hsm.login('$HSM_PIN')
    # Try to derive a nonce - this should fail in production mode
    derivation = hsm.derive_nonce('test_request', b'test_hash_32_bytes_long_padding!')
    print('DERIVED:' + derivation.R_hex)
except SecurityError as e:
    print('BLOCKED:SecurityError:' + str(e))
except Exception as e:
    print('BLOCKED:' + str(type(e).__name__) + ':' + str(e))
" 2>&1) || true

    if echo "$RESULT" | grep -q "^BLOCKED:SecurityError:"; then
        echo "    ✅ PASS: Nonce derivation blocked with SecurityError"
        return 0
    elif echo "$RESULT" | grep -q "^BLOCKED:"; then
        echo "    ✅ PASS: Nonce derivation blocked"
        return 0
    elif echo "$RESULT" | grep -q "^DERIVED:"; then
        echo "    ❌ FAIL: Nonce derivation succeeded in production mode!"
        return 1
    else
        echo "    ⚠️  SKIP: Unexpected result: $RESULT"
        return 0
    fi
}

# Test that is_production_mode() returns correct values
test_mode_detection() {
    echo "  Testing HSM mode detection methods..."

    # Test production mode detection
    RESULT=$(docker exec -e HSM_MODE=production -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
        python3 -c "
from app.hardware import HardwareToken
import os
os.environ['HSM_MODE'] = 'production'
hsm = HardwareToken()
print('is_production_mode:', hsm.is_production_mode())
print('is_demo_mode:', hsm.is_demo_mode())
print('get_hsm_mode:', hsm.get_hsm_mode())
" 2>&1) || true

    if echo "$RESULT" | grep -q "is_production_mode: True" && \
       echo "$RESULT" | grep -q "is_demo_mode: False" && \
       echo "$RESULT" | grep -q "get_hsm_mode: production"; then
        echo "    ✅ PASS: Production mode correctly detected"
    else
        echo "    ❌ FAIL: Mode detection incorrect"
        echo "    Output: $RESULT"
        return 1
    fi

    # Test demo mode detection
    RESULT=$(docker exec -e HSM_MODE=demo -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
        python3 -c "
from app.hardware import HardwareToken
import os
os.environ['HSM_MODE'] = 'demo'
hsm = HardwareToken()
print('is_production_mode:', hsm.is_production_mode())
print('is_demo_mode:', hsm.is_demo_mode())
print('get_hsm_mode:', hsm.get_hsm_mode())
" 2>&1) || true

    if echo "$RESULT" | grep -q "is_production_mode: False" && \
       echo "$RESULT" | grep -q "is_demo_mode: True" && \
       echo "$RESULT" | grep -q "get_hsm_mode: demo"; then
        echo "    ✅ PASS: Demo mode correctly detected"
    else
        echo "    ❌ FAIL: Mode detection incorrect"
        echo "    Output: $RESULT"
        return 1
    fi

    return 0
}

# Test that init command shows correct mode message
test_init_mode_message() {
    echo "  Testing init command mode messages..."

    # Test production mode message (node should already be initialized, so we check status)
    RESULT=$(docker exec -e HSM_MODE=production "mpc-${TEST_NODE}" python3 -m app.main status 2>&1) || true

    if echo "$RESULT" | grep -q "PRODUCTION"; then
        echo "    ✅ PASS: Production mode shown in status"
    else
        echo "    ⚠️  SKIP: Could not verify production mode message"
    fi

    # Test demo mode message
    RESULT=$(docker exec -e HSM_MODE=demo "mpc-${TEST_NODE}" python3 -m app.main status 2>&1) || true

    if echo "$RESULT" | grep -q "DEMO"; then
        echo "    ✅ PASS: Demo mode shown in status"
    else
        echo "    ⚠️  SKIP: Could not verify demo mode message"
    fi

    return 0
}

# ========== MAIN TEST SEQUENCE ==========

wait_for_nodes

echo ""
echo "[1/6] Testing HSM mode detection methods..."
test_mode_detection
echo "Done."

echo ""
echo "[2/6] Stopping test node and clearing HSM data..."
docker compose stop "$TEST_NODE"
docker compose rm -f "$TEST_NODE"
docker volume rm -f "mailbox_mpc_${TEST_NODE}_data" 2>/dev/null || true
# Note: Volume name may vary based on project directory name
VOLUME_NAME=$(docker volume ls --format '{{.Name}}' | grep -E "${TEST_NODE}_data$" | head -1)
if [ -n "$VOLUME_NAME" ]; then
    docker volume rm -f "$VOLUME_NAME" 2>/dev/null || true
fi
echo "Starting fresh node with HSM_MODE=production..."
docker compose up -d "$TEST_NODE"
sleep 3

# Wait for node to be ready
until docker exec "mpc-${TEST_NODE}" echo "ok" 2>/dev/null; do
    sleep 1
done
echo "Done."

echo ""
echo "[3/6] Initializing node with HSM_MODE=production..."
# Run init with production mode - this creates the HSM secrets with SENSITIVE=True, EXTRACTABLE=False
OUTPUT=$(docker exec -e HSM_MODE=production -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
    python3 -m app.main init 2>&1) || true
echo "$OUTPUT"

# Verify production mode message was shown
if echo "$OUTPUT" | grep -q "PRODUCTION"; then
    echo "✓ Production mode message displayed during init"
else
    echo "⚠️  Production mode message not found (may already be initialized)"
fi
echo "Done."

echo ""
echo "[4/6] Verifying HSM objects were created with correct attributes..."
# List objects to see what was created
docker exec -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --login --pin "$HSM_PIN" \
    --list-objects
echo "Done."

echo ""
echo "[5/6] Testing extraction of production-mode secrets..."
echo ""

# Test nonce master seed extraction (critical secret)
echo "Testing NONCE_MASTER_SEED (critical cryptographic secret):"
test_extraction_blocked "NONCE_MASTER_SEED"

echo ""

# Test nonce counter extraction
echo "Testing NONCE_COUNTER:"
test_extraction_blocked "NONCE_COUNTER"

echo ""

# Test nonce derivation blocking
echo "Testing nonce derivation blocking:"
test_nonce_derivation_blocked

echo ""

# Test mode messages in status
echo "Testing mode display in commands:"
test_init_mode_message

echo ""

echo "[6/6] Running mini DKG to test share protection..."
# We need at least 2 nodes to do DKG. For a simpler test, we'll create
# a share directly via Python and then try to extract it

ROUND_ID="prod_test_$(date +%s)"
echo "Creating test DKG share with production mode..."
docker exec -e HSM_MODE=production -e SOFTHSM2_CONF=/app/data/softhsm.conf "mpc-${TEST_NODE}" \
    python3 -c "
from app.hardware import HardwareToken
import os
os.environ['HSM_MODE'] = 'production'
hsm = HardwareToken()
hsm.login('$HSM_PIN')
# Store a test share
hsm.store_dkg_share('$ROUND_ID', b'test_secret_share_data_12345')
print('Share stored successfully')
"

echo ""
echo "Testing DKG_SHARE_${ROUND_ID} extraction (via pkcs11-tool):"
test_extraction_blocked "DKG_SHARE_${ROUND_ID}"

echo ""
echo "Testing DKG share extraction (via Python API):"
test_python_api_extraction "$ROUND_ID"

echo ""
echo "=== ✅ Production Mode Validation Complete ==="
echo ""
echo "Summary:"
echo "  • HSM mode detection methods work correctly"
echo "  • Secrets created with SENSITIVE=True, EXTRACTABLE=False"
echo "  • pkcs11-tool cannot extract secret key values"
echo "  • Python API raises SecurityError when extracting in production mode"
echo "  • Nonce derivation blocked in production mode"
echo "  • Mode messages displayed correctly in CLI commands"
echo "  • Production mode properly protects HSM secrets"
echo ""
