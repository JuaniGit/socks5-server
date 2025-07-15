#!/bin/bash

CONCURRENT=600
PROXY="socks5h://localhost:1080"
USER="charlie:chocolate"
URL="http://127.0.0.1:3000"
MAX_RETRIES=0

# Log files
SUCCESS_LOG="success.log"
FAIL_LOG="fail.log"

# Clear old logs
> "$SUCCESS_LOG"
> "$FAIL_LOG"

fetch() {
  local id=$1
  local attempt=0

  while [ $attempt -le $MAX_RETRIES ]; do
    curl --silent --output /dev/null --proxy "$PROXY" --proxy-user "$USER" "$URL"
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
      echo "[$id] ✅ Success" >> "$SUCCESS_LOG"
      return 0
    else
      echo "[$id] ❌ Failed attempt $((attempt + 1)) (curl exit $exit_code)" >&2
      attempt=$((attempt + 1))
      sleep 1
    fi
  done

  echo "[$id] ❌ Final failure after $MAX_RETRIES retries" >> "$FAIL_LOG"
  return 1
}

export -f fetch
export PROXY USER URL MAX_RETRIES SUCCESS_LOG FAIL_LOG

# Run all in parallel
seq $CONCURRENT | xargs -n1 -P$CONCURRENT -I{} bash -c 'fetch "$@"' _ {}

# Summary
echo ""
echo "✅ Successes: $(wc -l < $SUCCESS_LOG)"
echo "❌ Failures:  $(wc -l < $FAIL_LOG)"
