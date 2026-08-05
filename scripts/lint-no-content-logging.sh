#!/usr/bin/env bash
# CLAUDE.md rule 4 / T-02 acceptance: clipboard content, keys and tokens must never
# reach a log line — debug builds included. Log lengths, types, and BLAKE3 prefixes.
#
# Heuristic: flag any tracing macro invocation mentioning a high-risk identifier.
# Deliberate exceptions carry a trailing `// lint-allow: no-content` comment.
set -uo pipefail
cd "$(dirname "$0")/.."

# Identifiers that must never be interpolated into a log line.
RISKY='body|plaintext|clip_text|\btext\b|secret|seed|passphrase|password|\btoken\b|\bsk\b|sk_|private_key|pasteboard'
MACROS='(tracing::)?(trace|debug|info|warn|error)!'

fail=0
while IFS= read -r hit; do
  case "$hit" in
    *'lint-allow: no-content'*) continue ;;
  esac
  if [ $fail -eq 0 ]; then
    echo "ERROR: potential clipboard/key content in a log line (CLAUDE.md rule 4):" >&2
    fail=1
  fi
  echo "  $hit" >&2
done < <(grep -rn --include='*.rs' -E "${MACROS}" crates/ apps/ 2>/dev/null \
         | grep -v '/target/' \
         | while IFS= read -r line; do
             # Rule 4 explicitly permits lengths and hashes, so neutralise those forms
             # before testing for risky identifiers: `body.len()` and `blake3(body)` are
             # fine, a bare `body` is not.
             probe=$(printf '%s' "$line" \
                     | sed -E 's/[A-Za-z_][A-Za-z0-9_.]*\.len\(\)//g; s/(content_digest|short_hash|blake3[A-Za-z0-9_]*)\([^)]*\)//g')
             if printf '%s' "$probe" | grep -qE "${MACROS}[^;]*(${RISKY})"; then
               printf '%s\n' "$line"
             fi
           done)

if [ $fail -ne 0 ]; then
  echo >&2
  echo "Log a length, a type, or blake3(content)[..8] instead. If this is a false" >&2
  echo "positive, append '// lint-allow: no-content' to the line." >&2
  exit 1
fi

echo "OK: no clipboard content, keys, or tokens in log statements."
