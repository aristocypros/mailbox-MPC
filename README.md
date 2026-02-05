# Mailbox MPC - Asynchronous Threshold Custody Demo

## Table of Contents

- [Project Context: An AI-Assisted Ideation Experiment](#-project-context-an-ai-assisted-ideation-experiment)
- [Why Asynchronous MPC? The "Mailbox" Paradigm](#why-asynchronous-mpc-the-mailbox-paradigm)
  - [The Problem with Synchronous MPC](#the-problem-with-synchronous-mpc)
  - [The Mailbox MPC Alternative](#the-mailbox-mpc-alternative)
  - [Real-World Scenarios Where Async Shines](#real-world-scenarios-where-async-shines)
  - [Trade-offs](#trade-offs)
- [Research Foundations](#-research-foundations)
  - [Core AMPC Theory](#core-ampc-theory)
  - [Advanced AMPC Models](#advanced-ampc-models)
  - [How This Demo Relates to Academic Research](#how-this-demo-relates-to-academic-research)
  - [Further Reading](#further-reading)
- [What This Demo Implements](#what-this-demo-implements)
- [Prerequisites](#prerequisites)
  - [Step 1: Generate Strong PINs](#step-1-generate-strong-pins)
  - [Step 2: Create Node-Specific Environment Files](#step-2-create-node-specific-environment-files)
  - [Step 3: Verify Configuration](#step-3-verify-configuration)
- [Quick Start](#quick-start)
- [Ceremony Flow Diagram](#ceremony-flow-diagram)
- [Architecture](#architecture)
  - [Infrastructure Components](#infrastructure-components)
  - [Key Files per Node](#key-files-per-node)
- [Git Server (Bulletin Board)](#git-server-bulletin-board)
  - [How It Works](#how-it-works)
  - [Board Repository Structure](#board-repository-structure)
  - [Docker Integration](#docker-integration)
- [Manual Ceremony](#manual-ceremony)
- [Security Notes](#security-notes)
  - [Deterministic Nonce Derivation (SLIP-10/BIP32 Style)](#deterministic-nonce-derivation-slip-10bip32-style)
  - [Multi-Layer Nonce Protection](#multi-layer-nonce-protection)
  - [Flexible Participant Coordination](#flexible-participant-coordination)
- [Troubleshooting](#troubleshooting)
  - [Reset everything](#reset-everything)
  - [Check node status](#check-node-status)
  - [View git bulletin board](#view-git-bulletin-board)
  - [Disaster Recovery](#disaster-recovery)
- [Production Security Advisory](#production-security-advisory)
  - [What This Demo Is Missing for Production](#what-this-demo-is-missing-for-production)
  - [Secrets Management for Production](#1-secrets-management-for-production)
  - [PIN Rotation Procedures](#2-pin-rotation-procedures)
  - [Hardware HSM Recommendations](#3-hardware-hsm-recommendations)
  - [Additional Production Security Hardening](#4-additional-production-security-hardening)
  - [Compliance Considerations](#5-compliance-considerations)
  - [Security Audit Checklist](#security-audit-checklist)
  - [Reporting Security Issues](#reporting-security-issues)

---

## 🧪 Project Context: An AI-Assisted Ideation Experiment

**This is primarily an ideation and experimentation project.** I used both **Claude** and **Gemini** to explore how far I could push the implementation of an asynchronous MPC system, observing where the models converge in their approaches, where they diverge, and how they handle the intricate cryptographic and distributed systems challenges involved.

The goal wasn't to build production-ready custody infrastructure, but to:
- Test the boundaries of AI-assisted cryptographic system design
- Compare reasoning approaches between different LLMs on complex protocol implementation
- Explore whether independent AI models would arrive at similar architectural decisions
- Document the journey as a reference for others exploring AI-assisted development

---

## Why Asynchronous MPC? The "Mailbox" Paradigm

### The Problem with Synchronous MPC

Most Multi-Party Computation (MPC) protocols assume **synchronous communication**—all participants must be online simultaneously, exchanging messages in real-time rounds. Popular implementations include:

| Protocol | Type | Communication Model | Use Case |
|----------|------|---------------------|----------|
| **GG18/GG20** | Threshold ECDSA | Synchronous (multiple rounds) | Fireblocks, ZenGo |
| **CGGMP21** | Threshold ECDSA | Synchronous (optimized rounds) | Coinbase, modern wallets |
| **FROST** | Threshold Schnorr | Synchronous (2 rounds) | Bitcoin Taproot multisig |
| **Lindell17** | 2-party ECDSA | Synchronous | Simple 2-of-2 setups |

**Synchronous protocols require:**
```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Party A │◄───►│ Party B │◄───►│ Party C │
└─────────┘     └─────────┘     └─────────┘
     │               │               │
     └───────────────┼───────────────┘
                     │
              All online NOW
              Low latency required
              Network partitions = failure
```

### The Mailbox MPC Alternative

**Mailbox MPC** takes a fundamentally different approach: participants communicate through a shared **bulletin board** (like a "dead drop"), enabling **fully asynchronous operation**:

```
┌─────────────────────────────────────────────────────────────┐
│                    BULLETIN BOARD (Git)                      │
│                                                              │
│  📬 Party A drops message at 9:00 AM                        │
│  📬 Party B picks up at 2:00 PM, drops response             │
│  📬 Party C picks up at 11:00 PM, completes their part      │
│                                                              │
│  No simultaneous online requirement!                         │
└─────────────────────────────────────────────────────────────┘
```

### Real-World Scenarios Where Async Shines

**1. Geographically Distributed Custody (Time Zones)**
```
Scenario: A crypto fund with key holders in Tokyo, London, and New York
- Tokyo holder: Available 9 AM - 6 PM JST (midnight in NYC)
- London holder: Available 9 AM - 6 PM GMT (4 AM in Tokyo)
- New York holder: Available 9 AM - 6 PM EST (2 AM in London)

Synchronous MPC: Need a 30-minute window where all three are awake
Mailbox MPC: Each signs during their business hours, signature completes within 24h
```

**2. Air-Gapped Cold Storage**
```
Scenario: Ultra-secure custody where signers use air-gapped machines
- Signer machines have NO network connectivity
- Messages transferred via USB drives or QR codes
- Each "round" might take hours or days

Synchronous MPC: Impossible (requires real-time network)
Mailbox MPC: Export message → sneakernet → import response → repeat
```

**3. Human-in-the-Loop Approval Workflows**
```
Scenario: Enterprise treasury requiring board approval for large transfers
- CFO reviews transaction Monday morning
- CEO traveling, reviews Tuesday evening
- Board member reviews Wednesday

Synchronous MPC: Everyone must be in a Zoom call together
Mailbox MPC: Each approves on their own schedule, threshold reached when ready
```

**4. Disaster Recovery / Partial Availability**
```
Scenario: 3-of-5 threshold where some signers may be unreachable
- Signer 1: Online ✓
- Signer 2: On vacation (responds in 3 days)
- Signer 3: Online ✓
- Signer 4: Hardware failure (weeks to recover)
- Signer 5: Online ✓

Synchronous MPC: Must wait for exactly 3 to be online simultaneously
Mailbox MPC: First 3 to respond complete the signature, others can join later
```

**5. Regulatory/Compliance Workflows**
```
Scenario: Multi-jurisdiction custody requiring sequential approvals
- Compliance officer in Singapore must approve first
- Legal review in Switzerland must follow
- Final execution by operations in Delaware

Synchronous MPC: Complex scheduling across 3 jurisdictions
Mailbox MPC: Each step completes independently, audit trail preserved in Git
```

### Trade-offs

| Aspect | Synchronous MPC | Mailbox MPC |
|--------|-----------------|-------------|
| **Latency** | Seconds to minutes | Hours to days |
| **Availability** | All parties online | Any party, any time |
| **Network** | Reliable, low-latency | Tolerates high latency, partitions |
| **Complexity** | Session management | Bulletin board infrastructure |
| **Security** | Established proofs | Requires careful nonce handling |
| **Use Case** | Hot wallets, DeFi | Cold storage, enterprise treasury |

---

## 📚 Research Foundations

This project draws inspiration from recent advances in asynchronous MPC research. The following papers represent the state-of-the-art in this rapidly evolving field:

### Core AMPC Theory

| Paper | Authors | Key Contribution |
|-------|---------|------------------|
| [**Constant-Round Asynchronous MPC with Optimal Resilience and Linear Communication**](https://eprint.iacr.org/2025/1032) | Li, Song (Tsinghua) | First constant-round AMPC achieving O(\|C\|nκ) communication with malicious security. Introduces MPC-in-the-head framework adaptation for async networks. |
| [**Practical Asynchronous MPC from Lightweight Cryptography**](https://eprint.iacr.org/2024/1717) | Momose (Quitee Research) | Achieves practical AMPC using only hash functions and symmetric encryption. Adapts player-elimination framework to async settings with optimal n=3t+1 resilience. |

### Advanced AMPC Models

| Paper | Authors | Key Contribution |
|-------|---------|------------------|
| [**Breaking the Barrier for Asynchronous MPC with a Friend**](https://eprint.iacr.org/2025/1736) | Karmakar, Kate, Patil, Patra, Patranabis, Paul, Ravi | Helper-aided model breaking the 2/3-majority barrier. Achieves fairness in both honest and dishonest majority settings. |
| [**AD-MPC: Asynchronous Dynamic MPC with Guaranteed Output Delivery**](https://eprint.iacr.org/2024/1653) | Yu, Xu, Wu, Duan, Cheng | First async dynamic MPC where participants can join/leave mid-computation. Demonstrates practical performance across 20 geo-distributed nodes. |

### How This Demo Relates to Academic Research

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ACADEMIC AMPC vs THIS DEMO                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Academic AMPC Research:              This Mailbox MPC Demo:            │
│  ┌─────────────────────────┐          ┌─────────────────────────┐       │
│  │ • Provable security     │          │ • Practical exploration │       │
│  │ • Optimal resilience    │          │ • Git-based bulletin    │       │
│  │ • Communication bounds  │          │ • HSM integration       │       │
│  │ • Malicious adversaries │          │ • Human-in-the-loop     │       │
│  │ • Byzantine agreement   │          │ • Deterministic nonces  │       │
│  └─────────────────────────┘          └─────────────────────────┘       │
│              │                                    │                      │
│              └──────────┬─────────────────────────┘                      │
│                         ▼                                                │
│              ┌─────────────────────────┐                                │
│              │  SHARED CORE INSIGHT:   │                                │
│              │  Bulletin board model   │                                │
│              │  enables async without  │                                │
│              │  simultaneous presence  │                                │
│              └─────────────────────────┘                                │
│                                                                          │
│  Key Differences:                                                        │
│  • Academic: Proves security against Byzantine adversaries               │
│  • Demo: Explores practical UX for human custody workflows               │
│  • Academic: Optimizes communication complexity                          │
│  • Demo: Prioritizes auditability (Git history)                         │
│  • Academic: General MPC for arbitrary circuits                          │
│  • Demo: Focused on threshold Schnorr signing                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Further Reading

For deeper understanding of the cryptographic foundations:

- **Feldman VSS**: Feldman, P. (1987). "A Practical Scheme for Non-interactive Verifiable Secret Sharing"
- **Threshold Schnorr**: Stinson & Strobl (2001). "Provably Secure Distributed Schnorr Signatures"
- **FROST**: Komlo & Goldberg (2020). "FROST: Flexible Round-Optimized Schnorr Threshold Signatures"
- **Asynchronous Consensus**: Cachin, Kursawe, Shoup (2005). "Random Oracles in Constantinople"

---

## What This Demo Implements

This demo implements:
- **Feldman VSS** for Distributed Key Generation (no dealer)
- **Threshold Schnorr Signing** (no key reconstruction)
- **Git-based "Bulletin Board"** for async communication
- **SoftHSM** for hardware security simulation
- **Deterministic Nonce Derivation** (SLIP-10/BIP32 style) for disaster recovery

## Prerequisites

**⚠️ IMPORTANT: You MUST configure unique strong PINs for each node before starting the system.**

The HSM requires two types of PINs per node:
- **User PIN (`PIN`)**: Protects all cryptographic operations (DKG, signing)
- **Security Officer PIN (`SO_PIN`)**: Administrative access for token management (reset user PIN, destroy keys)

### Step 1: Generate Strong PINs

Use the provided template and generate cryptographically random 8-digit PINs:

```bash
# Review the PIN requirements and security guidance
cat .env.example

# Generate strong PINs (Python method)
python3 << 'EOF'
import secrets
for i in range(1, 4):
    pin = secrets.randbelow(90000000) + 10000000
    so_pin = secrets.randbelow(90000000) + 10000000
    print(f"Node {i}: PIN={pin}  SO_PIN={so_pin}")
EOF
```

### Step 2: Create Node-Specific Environment Files

Create three separate `.env` files, one for each node (with both PIN and SO_PIN):

```bash
# Create .env.node1
cat > .env.node1 << 'EOF'
PIN=<your-generated-pin-1>
SO_PIN=<your-generated-so-pin-1>
EOF

# Create .env.node2
cat > .env.node2 << 'EOF'
PIN=<your-generated-pin-2>
SO_PIN=<your-generated-so-pin-2>
EOF

# Create .env.node3
cat > .env.node3 << 'EOF'
PIN=<your-generated-pin-3>
SO_PIN=<your-generated-so-pin-3>
EOF
```

**Security Requirements:**
- Each PIN and SO_PIN must be **exactly 8 digits** (range: 10000000-99999999)
- All 6 PINs (3 nodes × 2 PINs) must be **unique**
- PIN and SO_PIN on the same node must be **different**
- PINs must be **cryptographically random** (not sequential, dates, or common patterns)

### Step 3: Verify Configuration

```bash
# Ensure .env files are created and gitignored
ls -la .env.node*
git check-ignore .env.node1 .env.node2 .env.node3

# Verify all 6 PINs are unique (3 nodes × 2 PINs = 6 lines)
cat .env.node* | sort -u | wc -l  # Should output: 6
```

**Production Security Notes:**
- Never commit `.env.node*` files to version control (already in `.gitignore`)
- Use secrets management systems (HashiCorp Vault, AWS Secrets Manager) in production
- Implement PIN rotation policies
- Consider hardware HSM with multi-factor authentication for production deployments
- The SO_PIN should be stored separately from the user PIN in production (different access controls)

## Quick Start

```bash
# Build and start (requires .env.node* files from Prerequisites)
docker compose up -d --build

# Run automated test (requires HSM_MODE=demo in docker-compose.yml - this is the default)
./test_ceremony.sh
```

**Note:** The automated test requires `HSM_MODE=demo` for share verification. This is already set in the default `docker-compose.yml`.

## Ceremony Flow Diagram

The following diagram shows the complete flow of the MPC ceremony from initialization through signing:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            INFRASTRUCTURE STARTUP                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   docker compose up -d --build                                                   │
│           │                                                                      │
│           ▼                                                                      │
│   ┌───────────────┐                                                              │
│   │  git-server   │ ◄── Exports SSH host key to shared volume                   │
│   │  (mpc-git)    │     Initializes bare repo board.git                         │
│   └───────┬───────┘     Creates: identity/, dkg/, signing/ directories          │
│           │ healthcheck: pgrep sshd                                              │
│           ▼                                                                      │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                       │
│   │    node1      │  │    node2      │  │    node3      │                       │
│   │  (mpc-node1)  │  │  (mpc-node2)  │  │  (mpc-node3)  │                       │
│   └───────────────┘  └───────────────┘  └───────────────┘                       │
│           │                  │                  │                                │
│           └──────────────────┼──────────────────┘                                │
│                              ▼                                                   │
│                    Entrypoint runs:                                              │
│                    • Verify git-server host key (MITM protection)                │
│                    • Generate SSH keys                                           │
│                    • Register with git-server                                    │
│                    • Initialize SoftHSM token                                    │
│                    • Generate IDENTITY_KEY (RSA 2048)                            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PHASE 1: INITIALIZATION                                  │
│                            (app.main init)                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   node1                    node2                    node3                        │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  ┌──────┐                ┌──────┐                ┌──────┐                        │
│  │ HSM  │                │ HSM  │                │ HSM  │                        │
│  │login │                │login │                │login │                        │
│  └──┬───┘                └──┬───┘                └──┬───┘                        │
│     │                       │                       │                            │
│     ▼                       ▼                       ▼                            │
│  Export RSA             Export RSA             Export RSA                        │
│  public key             public key             public key                        │
│     │                       │                       │                            │
│     ▼                       ▼                       ▼                            │
│  Initialize             Initialize             Initialize                        │
│  nonce master           nonce master           nonce master                      │
│  seed + counter         seed + counter         seed + counter                    │
│     │                       │                       │                            │
│     └───────────────────────┼───────────────────────┘                            │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    │   (git-server)  │                                           │
│                    ├─────────────────┤                                           │
│                    │ identity/       │                                           │
│                    │ ├─ node1.json   │ ◄── {node_id, pubkey_pem, timestamp}     │
│                    │ ├─ node2.json   │                                           │
│                    │ └─ node3.json   │                                           │
│                    └─────────────────┘                                           │
│                                                                                  │
│   HSM State: NONCE_MASTER_SEED (32 bytes), NONCE_COUNTER = 0                    │
│   State: initialized=True, identity_key_posted=True                              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 2: DKG - COMMITMENT                                    │
│                  (app.main dkg-start --round-id demo)                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Each node generates a random polynomial f_i(x) of degree t-1:                  │
│   f_i(x) = a_i0 + a_i1*x + ... + a_i(t-1)*x^(t-1)                               │
│                                                                                  │
│   node1                    node2                    node3                        │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  Generate               Generate               Generate                          │
│  coefficients           coefficients           coefficients                      │
│  [a10, a11]             [a20, a21]             [a30, a31]                        │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  Compute                Compute                Compute                           │
│  commitments            commitments            commitments                       │
│  C1j = a1j*G            C2j = a2j*G            C3j = a3j*G                       │
│     │                        │                        │                          │
│     └───────────────────────┼───────────────────────┘                            │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ dkg/demo/       │                                           │
│                    │ └─commitments/  │                                           │
│                    │   ├─ node1.json │ ◄── {commitments: [C10, C11], ...}       │
│                    │   ├─ node2.json │                                           │
│                    │   └─ node3.json │                                           │
│                    └─────────────────┘                                           │
│                                                                                  │
│   State: dkg.phase='committed'                                                   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 3: DKG - DISTRIBUTION                                  │
│                  (app.main dkg-distribute --round-id demo)                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Each node computes shares for others: s_ij = f_i(j)                            │
│   Encrypts with recipient's RSA public key from identity/                        │
│                                                                                  │
│   node1                    node2                    node3                        │
│     │                        │                        │                          │
│     ├─── s12=f1(2) ────────►│                        │                          │
│     ├─── s13=f1(3) ─────────┼───────────────────────►│                          │
│     │                        │                        │                          │
│     │◄─── s21=f2(1) ────────┤                        │                          │
│     │                        ├─── s23=f2(3) ────────►│                          │
│     │                        │                        │                          │
│     │◄─── s31=f3(1) ────────┼────────────────────────┤                          │
│     │                        │◄─── s32=f3(2) ────────┤                          │
│     │                        │                        │                          │
│     └───────────────────────┼───────────────────────┘                            │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ dkg/demo/       │                                           │
│                    │ └─shares/       │                                           │
│                    │   ├─ node1_to_node2.enc │ ◄── RSA-encrypted s12            │
│                    │   ├─ node1_to_node3.enc │                                   │
│                    │   ├─ node2_to_node1.enc │                                   │
│                    │   ├─ node2_to_node3.enc │                                   │
│                    │   ├─ node3_to_node1.enc │                                   │
│                    │   └─ node3_to_node2.enc │                                   │
│                    └─────────────────┘                                           │
│                                                                                  │
│   State: dkg.phase='distributed'                                                 │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 4: DKG - FINALIZATION                                  │
│                  (app.main dkg-finalize --round-id demo)                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Each node:                                                                     │
│   1. Decrypts received shares using HSM                                          │
│   2. Verifies: s_ij * G == Σ(j^k * C_ik) for k=0..t-1                           │
│   3. Computes final share: S_j = Σ s_ij (including own contribution)            │
│   4. Stores S_j in HSM                                                           │
│                                                                                  │
│   node1                    node2                    node3                        │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  Decrypt &              Decrypt &              Decrypt &                         │
│  Verify shares          Verify shares          Verify shares                     │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  S1 = s11+s21+s31       S2 = s12+s22+s32       S3 = s13+s23+s33                 │
│     │                        │                        │                          │
│     ▼                        ▼                        ▼                          │
│  ┌──────┐                ┌──────┐                ┌──────┐                        │
│  │ HSM  │                │ HSM  │                │ HSM  │                        │
│  │store │                │store │                │store │                        │
│  │  S1  │                │  S2  │                │  S3  │                        │
│  └──────┘                └──────┘                └──────┘                        │
│                                                                                  │
│   Group Public Key: Y = C10 + C20 + C30                                          │
│   (All nodes compute the same Y)                                                 │
│                                                                                  │
│   State: dkg.phase='finalized', dkg.group_pubkey_hex='03d67c...'                │
│                                                                                  │
│   ╔═══════════════════════════════════════════════════════════════════════╗     │
│   ║  SECURITY: No single node knows the full private key!                  ║     │
│   ║  Private key x = s11+s12+s13 + s21+s22+s23 + s31+s32+s33               ║     │
│   ║  But each node only has S_j = s1j + s2j + s3j                          ║     │
│   ╚═══════════════════════════════════════════════════════════════════════╝     │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 5: SIGNING REQUEST                                     │
│            (app.main sign-request --message "Pay 100 BTC")                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   node1 (requester)                                                              │
│     │                                                                            │
│     ▼                                                                            │
│   Create request:                                                                │
│   • request_id = "tx_a1cf0b1c"                                                   │
│   • message_hash = SHA256("Pay 100 BTC")                                         │
│     │                                                                            │
│     └───────────────────────────────────────────────────────────────────────►    │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ signing/        │                                           │
│                    │ └─tx_a1cf0b1c/  │                                           │
│                    │   └─request.json│ ◄── {request_id, message_hash, ...}      │
│                    └─────────────────┘                                           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 6: SIGNING APPROVAL                                    │
│            (app.main sign-approve --request-id tx_a1cf0b1c)                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Human review: "Pay 100 BTC to Satoshi" → Approve? [y/N]                        │
│                                                                                  │
│   node1                    node2                                                 │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐     │
│  │  DETERMINISTIC NONCE DERIVATION (SLIP-10/BIP32 style)                  │     │
│  │  k = HMAC-SHA512(master_seed, 0x00 || counter || req_id || msg_hash)   │     │
│  │  Counter atomically increments (can NEVER go backwards)                │     │
│  └────────────────────────────────────────────────────────────────────────┘     │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  Derive k1             Derive k2                                                 │
│  (counter=N)           (counter=M)                                               │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  R1 = k1 * G           R2 = k2 * G                                              │
│     │                        │                                                   │
│     │  ⚠️ TRIPLE-LAYER:     │  ⚠️ TRIPLE-LAYER:                                 │
│     │  1. Store R1 in HSM   │  1. Store R2 in HSM                               │
│     │  2. Record in state   │  2. Record in state                               │
│     │  3. Post to board     │  3. Post to board                                 │
│     │                        │                                                   │
│     └────────────────────────┼──────────────────────────────────────────────►    │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ signing/        │                                           │
│                    │ └─tx_a1cf0b1c/  │                                           │
│                    │   ├─request.json│                                           │
│                    │   └─commitments/│                                           │
│                    │     ├─node1.json│ ◄── {R_commitment: "02f5bc..."}          │
│                    │     └─node2.json│                                           │
│                    └─────────────────┘                                           │
│                                                                                  │
│   HSM: NONCE_DERIV_{counter} = {request_id, R_hex, message_hash}                │
│   State: signing.nonce_derivations[request_id] = {counter, R_hex}               │
│                                                                                  │
│   ╔═══════════════════════════════════════════════════════════════════════╗     │
│   ║  NONCE REUSE = CATASTROPHIC KEY LEAK                                   ║     │
│   ║  If k_i is reused with different messages, private key leaks!          ║     │
│   ║  Protected by: Monotonic counter + HSM + local state + board (4 layers)║     │
│   ╚═══════════════════════════════════════════════════════════════════════╝     │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 7: SIGNING FINALIZATION                                │
│            (app.main sign-finalize --request-id tx_a1cf0b1c)                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   First finalizer locks participant set, others use the locked set:              │
│                                                                                  │
│   node1 (first finalizer)    node2                                               │
│     │                          │                                                 │
│     ▼                          │                                                 │
│  Lock session.json             │                                                 │
│  participants=[node1,node2]    │                                                 │
│     │                          │                                                 │
│     ▼                          ▼                                                 │
│  Load R1, R2              Read session.json                                      │
│  (locked set)             Load R1, R2 (same!)                                    │
│     │                          │                                                 │
│     ▼                          ▼                                                 │
│  R = R1 + R2              R = R1 + R2 (consistent!)                              │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  e = H(R || Y || m)     e = H(R || Y || m)                                       │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  λ1 = Lagrange          λ2 = Lagrange                                            │
│  coefficient            coefficient                                              │
│     │                        │                                                   │
│     ▼                        ▼                                                   │
│  s1 = k1 + e*λ1*S1      s2 = k2 + e*λ2*S2                                        │
│     │                        │                                                   │
│     │  WIPE k1!              │  WIPE k2!                                         │
│     │                        │                                                   │
│     └────────────────────────┼──────────────────────────────────────────────►    │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ signing/        │                                           │
│                    │ └─tx_a1cf0b1c/  │                                           │
│                    │   ├─request.json│                                           │
│                    │   ├─session.json│ ◄── {participants: [node1,node2]}        │
│                    │   ├─commitments/│                                           │
│                    │   │ ├─node1.json│                                           │
│                    │   │ └─node2.json│                                           │
│                    │   └─partials/   │                                           │
│                    │     ├─node1.json│ ◄── {partial_s: "738d5e..."}             │
│                    │     └─node2.json│                                           │
│                    └─────────────────┘                                           │
│                                                                                  │
│   When threshold (2) reached:                                                    │
│     │                                                                            │
│     ▼                                                                            │
│   s = s1 + s2 (mod n)                                                            │
│   Signature = (R, s)                                                             │
│     │                                                                            │
│     ▼                                                                            │
│   Verify: s*G == R + e*Y  →  ✅ VALID SIGNATURE!                                 │
│     │                                                                            │
│     └───────────────────────────────────────────────────────────────────────►    │
│                             ▼                                                    │
│                    ┌─────────────────┐                                           │
│                    │  BULLETIN BOARD │                                           │
│                    ├─────────────────┤                                           │
│                    │ signing/        │                                           │
│                    │ └─tx_a1cf0b1c/  │                                           │
│                    │   └─result.json │ ◄── {R: "03f5bc...", s: "738d5e..."}     │
│                    └─────────────────┘                                           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CEREMONY COMPLETE                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Output:                                                                        │
│   ┌───────────────────────────────────────────────────────────────────────────┐ │
│   │ ✅ VALID SIGNATURE!                                                        │ │
│   │    R: 03f5bcf115df144330ab4577ed54273200095a006412fd2948244cdb243c3c32d5  │ │
│   │    s: 738d5ec706e8bfe49e318bcfd060bfaca27505009c18c7dec1bbd6ba559ddab0    │ │
│   └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│   The signature (R, s) can be verified against:                                  │
│   • Group Public Key: Y (known publicly after DKG)                               │
│   • Message hash: H("Pay 100 BTC to Satoshi")                                    │
│                                                                                  │
│   Without ever reconstructing the private key!                                   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    node1     │     │    node2     │     │    node3     │
│  (Python)    │     │  (Python)    │     │  (Python)    │
│  ┌────────┐  │     │  ┌────────┐  │     │  ┌────────┐  │
│  │SoftHSM │  │     │  │SoftHSM │  │     │  │SoftHSM │  │
│  │(PKCS11)│  │     │  │(PKCS11)│  │     │  │(PKCS11)│  │
│  └────────┘  │     │  └────────┘  │     │  └────────┘  │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │ SSH (git clone/push/pull)               │
       └────────────────────┼────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  git-server   │
                    │   (Alpine)    │
                    │ ┌───────────┐ │
                    │ │ board.git │ │  ← Bare Git repository
                    │ │ (Bulletin │ │    (identity/, dkg/, signing/)
                    │ │  Board)   │ │
                    │ └───────────┘ │
                    └───────────────┘
                           │
                    Docker Volumes:
                    • git_data (bulletin board)
                    • shared_keys (SSH bootstrap)
                    • node1/2/3_data (node state)
```

### Infrastructure Components

| Component | Base Image | Purpose |
|-----------|------------|---------|
| `git-server` | Alpine Linux | SSH + Git server hosting bulletin board |
| `node1/2/3` | Python 3.11-slim | MPC node with SoftHSM |

### Key Files per Node

| File | Lines | Purpose |
|------|-------|---------|
| `main.py` | 858 | CLI entry point (init, dkg-*, sign-*) |
| `hardware.py` | 669 | PKCS#11 HSM interface |
| `crypto.py` | 371 | Feldman DKG, Threshold Signing |
| `transport.py` | 165 | Git-based mailbox with retries |
| `state.py` | 142 | Atomic state management |
| `protocol.py` | 87 | Message type definitions |

## Git Server (Bulletin Board)

The git-server acts as an asynchronous "dead drop" for MPC communication:

### How It Works

1. **SSH Host Key Distribution**: Git-server exports its host key to `shared_keys` volume for node verification
2. **SSH Key Bootstrap**: Nodes verify git-server identity, then write their SSH public keys to the shared volume
3. **Key Watcher Daemon**: Git-server runs a background loop that auto-registers new node keys to `authorized_keys`
4. **Asynchronous Communication**: Nodes push/pull messages via Git with verified host - no MITM attacks possible

### Board Repository Structure

```
board.git/
├── identity/               # Node RSA public keys (for encrypting shares)
│   ├── node1.json
│   ├── node2.json
│   └── node3.json
├── dkg/{round_id}/         # DKG ceremony messages
│   ├── commitments/        # Polynomial commitments (C_ij = a_ij * G)
│   │   ├── node1.json
│   │   └── ...
│   └── shares/             # Encrypted shares (RSA)
│       ├── node1_to_node2.enc
│       └── ...
└── signing/{request_id}/   # Signing ceremony messages
    ├── request.json        # What to sign
    ├── session.json        # Locked participant set (first finalizer creates)
    ├── commitments/        # Nonce commitments (R_i = k_i * G)
    ├── partials/           # Partial signatures (s_i)
    └── result.json         # Final combined signature
```

### Docker Integration

```yaml
# From docker-compose.yml
git-server:
  volumes:
    - git_data:/var/lib/git           # Persistent repository
    - shared_keys:/shared_keys:rw     # Host key export + node SSH key bootstrap
  ports:
    - "2222:22"                        # SSH access
  healthcheck:
    test: ["CMD", "pgrep", "sshd"]     # Verify SSH daemon running
```

## Manual Ceremony

### Initialize nodes (in separate terminals)
```bash
docker exec -it mpc-node1 python3 -m app.main init
docker exec -it mpc-node2 python3 -m app.main init
docker exec -it mpc-node3 python3 -m app.main init
```

### DKG Ceremony
```bash
# Phase 1: Commitments (all nodes)
docker exec -it mpc-node1 python3 -m app.main dkg-start --round-id mykey --threshold 2 --total 3
docker exec -it mpc-node2 python3 -m app.main dkg-start --round-id mykey --threshold 2 --total 3
docker exec -it mpc-node3 python3 -m app.main dkg-start --round-id mykey --threshold 2 --total 3

# Phase 2: Distribution (all nodes)
docker exec -it mpc-node1 python3 -m app.main dkg-distribute --round-id mykey
docker exec -it mpc-node2 python3 -m app.main dkg-distribute --round-id mykey
docker exec -it mpc-node3 python3 -m app.main dkg-distribute --round-id mykey

# Phase 3: Finalization (all nodes)
docker exec -it mpc-node1 python3 -m app.main dkg-finalize --round-id mykey
docker exec -it mpc-node2 python3 -m app.main dkg-finalize --round-id mykey
docker exec -it mpc-node3 python3 -m app.main dkg-finalize --round-id mykey
```

### Signing
```bash
# Create request
docker exec -it mpc-node1 python3 -m app.main sign-request --message "Pay 10 BTC"

# Approve (need 2 of 3)
docker exec -it mpc-node1 python3 -m app.main sign-approve --request-id tx_xxxx
docker exec -it mpc-node2 python3 -m app.main sign-approve --request-id tx_xxxx

# Finalize (both approving nodes must run this)
docker exec -it mpc-node1 python3 -m app.main sign-finalize --request-id tx_xxxx
docker exec -it mpc-node2 python3 -m app.main sign-finalize --request-id tx_xxxx
```

## Security Notes

- This is a **DEMO**. Not for production use.
- SoftHSM simulates hardware; use real HSM in production.
- Share extraction enabled for debugging; disable in production.
- SSH host key verification is enabled (nodes verify git-server identity via shared volume).

### Deterministic Nonce Derivation (SLIP-10/BIP32 Style)

Instead of generating random nonces, this demo uses **deterministic derivation** from a master seed:

```
┌─────────────────────────────────────────────────────────────────┐
│           DETERMINISTIC NONCE DERIVATION                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  HSM stores (one-time setup during 'init'):                     │
│  • NONCE_MASTER_SEED (32 bytes, random)                         │
│  • NONCE_COUNTER (monotonic, only increments)                   │
│                                                                  │
│  Derivation formula:                                             │
│  k = HMAC-SHA512(seed, 0x00||counter||request_id||msg_hash)[0:32] mod n
│                                                                  │
│  Benefits:                                                       │
│  • Disaster recovery: regenerate nonces from master + counter   │
│  • HSM capacity: O(1) storage instead of O(n) per signing       │
│  • Security: monotonic counter prevents reuse (never decrements)│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Layer Nonce Protection

Nonce reuse in Schnorr signing leaks the private key. This demo implements **four layers** of protection:

```
┌─────────────────────────────────────────────────────────────────┐
│                    NONCE REUSE PROTECTION                       │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1: Monotonic counter   → can NEVER go backwards           │
│ Layer 2: Local state.json    → survives board rewind attacks    │
│ Layer 3: HSM-backed storage  → survives filesystem restore      │
│ Layer 4: Bulletin board check → survives local state corruption │
├─────────────────────────────────────────────────────────────────┤
│ Recording order: Counter → HSM → Local → Board                  │
└─────────────────────────────────────────────────────────────────┘
```

**Attack scenarios protected against:**
| Attack | Protection |
|--------|------------|
| Git server force-push | Local state + HSM counter remember nonces |
| VM snapshot restore | HSM counter persists + board has record |
| Local state corruption | HSM counter + board catch the mismatch |
| HSM capacity exhaustion | Derivation uses O(1) storage |

Run `python3 -m app.main status` to audit nonce consistency and view derivation info.

### Flexible Participant Coordination

In asynchronous human-in-the-loop workflows, more nodes may approve (post commitments) than actually finalize. The system handles this gracefully:

```
┌─────────────────────────────────────────────────────────────────┐
│           PARTICIPANT SET LOCKING (session.json)                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Problem: 3 nodes approve, but only 2 finalize                  │
│  • If partials use R=R1+R2+R3 but combine uses R=R1+R2          │
│  • Result: INVALID SIGNATURE (R values don't match!)            │
│                                                                  │
│  Solution: First finalizer locks the participant set            │
│  • Creates session.json with participants=[node1, node2]        │
│  • All subsequent finalizers use the locked set                 │
│  • Consistent R calculation across all partials                 │
│                                                                  │
│  Benefits:                                                       │
│  • Any threshold nodes can finalize (no enforced order)         │
│  • Extra approvals don't block signing                          │
│  • Asynchronous human-in-the-loop workflow supported            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Reset everything
```bash
docker compose down -v
docker compose up -d --build
```

### Check node status
```bash
docker exec mpc-node1 python3 -m app.main status
```

Example output:
```
📊 Node Status: node1
========================================
Initialized:     ✓
Identity Posted: ✓

📋 DKG:
   Round: demo
   Phase: finalized
   Share: ✓
   PubKey: 0243feb461c8488558d3d8109cd6a9cb...

🔏 Nonce Security Audit:
   Local state nonces: 1
   HSM nonces:         1
   Consistency:        ✓ MATCHED

🎲 Deterministic Nonce Derivation (SLIP-10/BIP32):
   Master seed:        ✓ Initialized
   Monotonic counter:  1
   Derivation records: 1
   Local derivations:  1
   Derivation match:   ✓ MATCHED

📬 Board: node1, node2, node3
```

### View git bulletin board
```bash
docker exec mpc-node1 ls -la /app/data/board/
docker exec mpc-node1 git -C /app/data/board log --oneline
```

### Disaster Recovery

With deterministic nonce derivation, you can recover nonces if you have:
1. The HSM master seed (NONCE_MASTER_SEED)
2. The counter value at time of signing
3. The request_id and message_hash

The HSM stores derivation records (`NONCE_DERIV_{counter}`) that map counter values to signing requests, enabling audit and recovery.

---

## Production Security Advisory

> **⚠️ WARNING: This is a DEMO implementation for educational purposes only.**
>
> This codebase demonstrates MPC concepts and should NOT be used in production without significant security hardening.

### What This Demo Is Missing for Production

| Demo Limitation | Production Requirement |
|-----------------|----------------------|
| SoftHSM (software simulation) | Hardware HSM (YubiHSM, AWS CloudHSM, Thales Luna) |
| Key shares are extractable | Non-extractable keys with `EXTRACTABLE: False` |
| No PIN rotation mechanism | Automated PIN rotation with key re-wrap |
| Local .env files | Secrets management (Vault, AWS Secrets Manager) |
| No audit logging | Tamper-evident audit logs with digital signatures |
| No access control | Role-based access control (RBAC) with MFA |
| Single Git server | Redundant, authenticated bulletin boards |

### 1. Secrets Management for Production

**Never store PINs in `.env` files in production.** Use a proper secrets management system:

#### HashiCorp Vault (Recommended)
```bash
# Store PIN in Vault
vault kv put secret/mpc/node1 pin="$(python3 -c 'import secrets; print(secrets.randbelow(90000000)+10000000)')"

# Retrieve at container startup (in entrypoint)
export PIN=$(vault kv get -field=pin secret/mpc/node1)
```

#### AWS Secrets Manager
```bash
# Create secret
aws secretsmanager create-secret \
    --name "mpc/node1/pin" \
    --secret-string '{"pin":"83749261"}'

# In entrypoint.sh
export PIN=$(aws secretsmanager get-secret-value \
    --secret-id "mpc/node1/pin" \
    --query 'SecretString' --output text | jq -r '.pin')
```

#### Kubernetes Secrets (with encryption at rest)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mpc-node1-secrets
type: Opaque
data:
  pin: ODM3NDkyNjE=  # base64 encoded
```

### 2. PIN Rotation Procedures

PINs should be rotated regularly (at minimum annually, or immediately upon suspected compromise).

#### Rotation Steps
1. **Generate new PIN** using cryptographically secure random generation
2. **Re-wrap existing HSM keys** with new PIN (if HSM supports it)
3. **Update secrets manager** with new PIN value
4. **Rolling restart** of nodes (one at a time to maintain quorum)
5. **Verify** each node can authenticate and perform operations
6. **Audit** old PIN is no longer valid

#### Sample Rotation Script (Conceptual)
```bash
#!/bin/bash
# PIN rotation for MPC node - ADAPT FOR YOUR ENVIRONMENT

NODE_ID=$1
NEW_PIN=$(python3 -c 'import secrets; print(secrets.randbelow(90000000)+10000000)')

# 1. Update secrets manager
vault kv put secret/mpc/${NODE_ID} pin="${NEW_PIN}"

# 2. Trigger node restart to pick up new PIN
kubectl rollout restart deployment/mpc-${NODE_ID}

# 3. Verify node is healthy
kubectl wait --for=condition=ready pod -l app=mpc-${NODE_ID} --timeout=120s

# 4. Test HSM authentication
kubectl exec deploy/mpc-${NODE_ID} -- python3 -m app.main status

echo "PIN rotation complete for ${NODE_ID}"
```

### 3. Hardware HSM Recommendations

For production crypto custody, use FIPS 140-2 Level 3+ certified hardware:

| HSM Option | Use Case | Notes |
|------------|----------|-------|
| **YubiHSM 2** | Small deployments | USB-attached, affordable (~$650), PKCS#11 compatible |
| **AWS CloudHSM** | Cloud-native | Managed, FIPS 140-2 Level 3, $1.50/hr |
| **Thales Luna** | Enterprise | Network-attached, high availability, HSM clustering |
| **Utimaco** | Enterprise | FIPS 140-2 Level 4 available |

#### HSM Integration Changes Required

```python
# In hardware.py - Production changes needed:

# 1. Use real PKCS#11 library instead of SoftHSM
PKCS11_LIB = "/usr/lib/libyubihsm_pkcs11.so"  # YubiHSM example

# 2. Make keys non-extractable
Attribute.EXTRACTABLE: False,  # CRITICAL: Prevents key theft
Attribute.SENSITIVE: True,     # CRITICAL: Prevents reading VALUE

# 3. Enable tamper response (HSM-specific)
# YubiHSM: automatic zeroization on tamper
# Luna: configurable tamper policies
```

### 4. Additional Production Security Hardening

#### Network Security
- [x] SSH host key verification (nodes verify git-server identity) ✓ Implemented
- [ ] Isolate MPC nodes in private VPC/VLAN
- [ ] Use mTLS for all inter-node communication
- [ ] Implement allowlist for Git server SSH access
- [ ] Deploy intrusion detection (fail2ban, OSSEC)

#### Access Control
- [ ] Implement multi-factor authentication for operators
- [ ] Require multiple operators for signing approval (M-of-N)
- [ ] Use separate credentials for each operator
- [ ] Implement session timeouts and re-authentication

#### Monitoring & Audit
- [ ] Log all HSM operations with timestamps
- [ ] Implement tamper-evident logging (append-only)
- [ ] Alert on failed authentication attempts
- [ ] Monitor for nonce reuse attempts
- [ ] Regular security audits by third party

#### Operational Security
- [ ] Secure key ceremony for initial DKG
- [ ] Document incident response procedures
- [ ] Test disaster recovery regularly
- [ ] Implement share refresh (proactive secret sharing)

### 5. Compliance Considerations

For regulated environments (financial services, healthcare, etc.):

- **SOC 2 Type II**: Requires audit logging, access controls, change management
- **PCI DSS**: If handling payment data, requires HSM key management procedures
- **GDPR/CCPA**: Data protection impact assessment may be required
- **NIST 800-57**: Key management lifecycle guidance

### Security Audit Checklist

Before deploying to production, verify:

```bash
# 1. No hardcoded secrets
grep -r "PIN=" . --include="*.yml" --include="*.py" | grep -v ".env"

# 2. Keys are non-extractable (check hardware.py)
grep "EXTRACTABLE" node/app/hardware.py  # Should show False

# 3. SSH host key verification enabled
grep "StrictHostKeyChecking" node/entrypoint.sh  # Should show "yes"

# 4. Audit logging enabled
grep -r "logging" . --include="*.py"

# 5. No debug modes
grep -r "DEBUG\|SENSITIVE: False" . --include="*.py"
```

### Reporting Security Issues

If you discover a security vulnerability in this demo, please:
1. **Do not** create a public GitHub issue
2. Email the maintainers directly with details
3. Allow reasonable time for response before disclosure

---
