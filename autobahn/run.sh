#!/usr/bin/env bash
# Runs the Autobahn testsuite against the echo server and the echo client.
# Needs Docker and jq. Reports are written to autobahn/reports.
# Fails if any case ends with a result other than OK, NON-STRICT or INFORMATIONAL.
set -euo pipefail

cd "$(dirname "$0")/.."
image=crossbario/autobahn-testsuite:25.10.1
reports=autobahn/reports

cargo build --release --example autobahn_server --example autobahn_client
rm -rf "$reports"
mkdir -p "$reports"

container=autobahn-embedded-io-websocket
server_pid=

cleanup() {
    docker stop "$container" >/dev/null 2>&1 || true
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

wstest() {
    docker run --rm --name "$container" --network host --user "$(id -u):$(id -g)" \
        -v "$PWD/autobahn:/config:ro" -v "$PWD/$reports:/reports" \
        "$image" wstest "$@"
}

target/release/examples/autobahn_server &
server_pid=$!
wstest -m fuzzingclient -s /config/fuzzingclient.json
kill "$server_pid"
server_pid=

wstest -m fuzzingserver -s /config/fuzzingserver.json &
until (exec 3<>/dev/tcp/127.0.0.1/9001) 2>/dev/null; do sleep 1; done
target/release/examples/autobahn_client 2>/dev/null
docker stop "$container" >/dev/null

failed=0
for side in server client; do
    echo "== $side"
    jq -r '.[] | to_entries[] | "\(.value.behavior) \(.value.behaviorClose) \(.key)"' \
        "$reports/$side/index.json" | sort -V -k3 > "$reports/$side/summary.txt"
    awk '{print $1}' "$reports/$side/summary.txt" | sort | uniq -c
    if grep -vE '^(OK|NON-STRICT|INFORMATIONAL) (OK|INFORMATIONAL) ' "$reports/$side/summary.txt"; then
        failed=1
    fi
done
exit $failed
