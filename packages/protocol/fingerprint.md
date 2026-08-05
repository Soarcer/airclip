# Fingerprint phrase algorithm (P3 task fills reference impls)

fp_bytes = SHA-256(x25519_public_key)          // 32 bytes
words[i] = EFF_SHORT_WORDLIST[ be_u16(fp_bytes[2i .. 2i+2]) % 1296 ]   for i in 0..4
display  = words joined with "-"; hex fp for mDNS TXT = first 16 hex chars of fp_bytes.

Vendor eff_short_wordlist_1.txt (1296 words, CC-BY 3.0, credit EFF) into this directory.
Reference implementations (JS + Rust) and the 3 keypair→phrase fixtures: P3 acceptance criteria.
