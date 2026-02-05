#!/bin/bash
# Automated test of the full MPC ceremony

set -e

echo "=== 🛡️  MPC Ceremony Test 🛡️  ==="
echo ""

# Helper function - properly handles argument passing
run_node() {
    local node=$1
    shift
    docker exec "mpc-${node}" python3 -m app.main "$@"
}

# Helper for interactive commands (reads stdin)
run_node_interactive() {
    local node=$1
    shift
    docker exec -i "mpc-${node}" python3 -m app.main "$@"
}

wait_for_nodes() {
    echo "Waiting for nodes to be ready..."
    for node in node1 node2 node3; do
        until docker exec "mpc-${node}" echo "ok" 2>/dev/null; do
            sleep 1
        done
    done
    echo "All nodes ready."
}

# Verify HSM mode is set correctly for demo
verify_demo_mode() {
    echo "Verifying HSM_MODE=demo is set..."
    for node in node1 node2 node3; do
        MODE=$(docker exec "mpc-${node}" printenv HSM_MODE 2>/dev/null || echo "not set")
        if [ "$MODE" != "demo" ]; then
            echo "❌ ERROR: $node has HSM_MODE=$MODE (expected 'demo')"
            echo "   The test requires HSM_MODE=demo in docker-compose.yml"
            exit 1
        fi
    done
    echo "✓ All nodes running in demo mode (HSM_MODE=demo)"
}

wait_for_nodes
verify_demo_mode

echo -e "\n[1/7] Initializing Nodes..."
# Init should show demo mode warning
OUTPUT=$(run_node node1 init 2>&1)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q "WARNING: Running in DEMO MODE"; then
    echo "✓ Demo mode warning displayed"
else
    echo "⚠️  Demo mode warning not found in output (may already be initialized)"
fi
run_node node2 init
run_node node3 init
echo "Done."

echo -e "\n[2/7] DKG Phase 1 (Commitments)..."
run_node node1 dkg-start --round-id demo --threshold 2 --total 3
run_node node2 dkg-start --round-id demo --threshold 2 --total 3
run_node node3 dkg-start --round-id demo --threshold 2 --total 3
echo "Done."

echo -e "\n[3/7] DKG Phase 2 (Distribution)..."
run_node node1 dkg-distribute --round-id demo
run_node node2 dkg-distribute --round-id demo
run_node node3 dkg-distribute --round-id demo
echo "Done."

echo -e "\n[4/7] DKG Phase 3 (Finalization)..."
run_node node1 dkg-finalize --round-id demo
run_node node2 dkg-finalize --round-id demo
run_node node3 dkg-finalize --round-id demo
echo "Done."

echo -e "\n[5/7] Creating Signing Request..."
OUTPUT=$(run_node node1 sign-request --message "Pay 100 BTC to Satoshi")
REQ_ID=$(echo "$OUTPUT" | grep -o "tx_[a-f0-9]*" | head -1)
echo "Request ID: $REQ_ID"

echo -e "\n[6/7] Approving (2-of-3 threshold)..."
# Use yes to auto-confirm with interactive stdin
echo "y" | run_node_interactive node1 sign-approve --request-id "$REQ_ID"
echo "y" | run_node_interactive node2 sign-approve --request-id "$REQ_ID"
echo "Done. (node3 not needed for 2-of-3)"

echo -e "\n[7/7] Finalizing Signature..."
# Both approving nodes need to finalize to post their partial signatures
run_node node1 sign-finalize --request-id "$REQ_ID"
run_node node2 sign-finalize --request-id "$REQ_ID"

echo -e "\n=== ✅ Ceremony Complete ==="
