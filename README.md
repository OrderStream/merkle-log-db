# merkle-log-db

High-throughput, zero-dependency embedded append-only audit database in pure Rust with automated SHA-256 Merkle root computation on every write.

## Key Properties
- **Zero External Dependencies**: Pure Rust standard library implementation containing custom RFC 6234 compliant SHA-256 engine.
- **Automated Merkle Root**: Computes updated Merkle root in $O(\log N)$ on every disk append without full tree recomputations.
- **Cryptographic Inclusion Proofs**: Generates compact $O(\log N)$ audit paths proving that any given record is indelibly committed.
- **Crash Recovery**: Formats records into a framed Write-Ahead Log (WAL) with per-record SHA-256 checksums; automatically verifies and reconstructs the Merkle tree upon opening.

## CLI Usage
```bash
# Append an audit log event
merkle-log-db append audit.db "TX-1002: Transfer 500 USDC to CDLZ..."

# View current cryptographic Merkle root
merkle-log-db root audit.db

# Generate & verify inclusion proof for record #0
merkle-log-db verify audit.db 0

# Dump all committed audit logs
merkle-log-db dump audit.db
```
