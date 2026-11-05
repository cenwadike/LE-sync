#!/usr/bin/env bash
set -euo pipefail

# Serves recorded Beacon API and execution JSON-RPC responses using Bash, socat, and jq.
# socat forks a Bash handler for each connection, so concurrent RPC requests are independent.
# Requests not present in the fixture set receive explicit errors; no response is guessed.
FIXTURES=""; HOST="127.0.0.1"; PORT=5052
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
WORKER=0
if [[ "${1:-}" == "--handle-connection" ]]; then
  WORKER=1
  FIXTURES="${LE_SYNC_REPLAY_FIXTURES:?missing replay fixture directory}"
  shift
fi
while (($#)); do
  case "$1" in
    --fixtures) (($# >= 2)) || { echo "--fixtures needs a directory" >&2; exit 2; }; FIXTURES="$2"; shift 2 ;;
    --host) (($# >= 2)) || { echo "--host needs a value" >&2; exit 2; }; HOST="$2"; shift 2 ;;
    --port) (($# >= 2)) || { echo "--port needs a value" >&2; exit 2; }; PORT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --fixtures <dir> [--host 127.0.0.1] [--port 5052]"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$FIXTURES" ]] || { echo "--fixtures is required" >&2; exit 2; }
[[ -d "$FIXTURES/beacon" ]] || { echo "no beacon/ in $FIXTURES: run scripts/record-fixtures.sh first" >&2; exit 1; }
for tool in jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required for replay mode" >&2; exit 1; }
done
if ((WORKER == 0)); then
  command -v socat >/dev/null 2>&1 || { echo "socat is required for concurrent replay requests" >&2; exit 1; }
fi
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT > 0 && PORT < 65536)) || { echo "invalid port: $PORT" >&2; exit 2; }

BEACON="$FIXTURES/beacon"
EXECUTION="$FIXTURES/execution"

http_response() {
  local status="$1" content_type="$2" body_file="${3:-}" body="${4:-}" length
  if [[ -n "$body_file" ]]; then
    length="$(wc -c < "$body_file" | tr -d ' ')"
    printf 'HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' \
      "$status" "$content_type" "$length"
    cat "$body_file"
  else
    length="$(printf '%s' "$body" | wc -c | tr -d ' ')"
    printf 'HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "$status" "$content_type" "$length" "$body"
  fi
}

handle_request() {
  local request_line method path line content_length=0 body="" flat file request rpc_method rpc_params rpc_id
  IFS= read -r request_line || return 0
  read -r method path _ <<< "$request_line"
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && break
    if [[ "$(printf '%s' "${line%%:*}" | tr '[:upper:]' '[:lower:]')" == "content-length" ]]; then
      content_length="${line#*:}"
      content_length="${content_length//[[:space:]]/}"
    fi
  done
  if [[ ! "$content_length" =~ ^[0-9]+$ ]] || ((content_length > 16777216)); then
    http_response "413 Payload Too Large" application/json "" '{"error":"invalid or oversized request body"}'
    return
  fi
  if ((content_length > 0)); then
    body="$(dd bs=1 count="$content_length" 2>/dev/null || true)"
  fi

  case "$method" in
    GET)
      flat="$(printf '%s' "$path" | tr '/?&=' '____')"
      if [[ "${path%%\?*}" == "/eth/v1/beacon/light_client/updates" ]]; then
        file="$(printf '%s\n' "$BEACON"/_eth_v1_beacon_light_client_updates* | sort | head -n 1)"
        [[ -f "$file" ]] || file=""
      else
        file="$BEACON/$flat"
      fi
      if [[ -n "$file" && -f "$file" ]]; then
        http_response "200 OK" application/json "$file"
      else
        request="$(jq -cn --arg path "$path" '{code:404,message:("not recorded: "+$path)}')"
        http_response "404 Not Found" application/json "" "$request"
      fi
      ;;
    POST)
      if ! request="$(jq -c . <<< "$body" 2>/dev/null)"; then
        http_response "400 Bad Request" application/json "" '{"error":"bad request: invalid JSON"}'
        return
      fi
      rpc_method="$(jq -r '.method // ""' <<< "$request")"
      rpc_params="$(jq -c '.params // []' <<< "$request")"
      rpc_id="$(jq -c '.id // 1' <<< "$request")"
      for file in "$EXECUTION"/*.request.json; do
        [[ -f "$file" ]] || continue
        local fixture_method fixture_params response_file
        fixture_method="$(jq -r '.method // ""' "$file")"
        [[ "$fixture_method" == "$rpc_method" ]] || continue
        fixture_params="$(jq -cS 'walk(if type == "string" then ascii_downcase else . end)' "$file" | jq -cS '.params // []')"
        if [[ "$fixture_params" == "$(jq -cS 'walk(if type == "string" then ascii_downcase else . end)' <<< "$rpc_params")" ]]; then
          response_file="${file%.request.json}.response.json"
          if [[ -f "$response_file" ]]; then
            http_response "200 OK" application/json "$response_file"
            return
          fi
        fi
      done
      request="$(jq -cn --argjson id "$rpc_id" --arg method "$rpc_method" --argjson params "$rpc_params" \
        '{jsonrpc:"2.0",id:$id,error:{code:-32601,message:("not recorded: "+$method+" "+($params|tojson))}}')"
      http_response "200 OK" application/json "" "$request"
      ;;
    *)
      http_response "405 Method Not Allowed" application/json "" '{"error":"method not allowed"}'
      ;;
  esac
}

if ((WORKER)); then
  handle_request
  exit
fi

echo "replay server on http://$HOST:$PORT" >&2
export LE_SYNC_REPLAY_FIXTURES="$FIXTURES"
printf -v SCRIPT_PATH_QUOTED '%q' "$SCRIPT_PATH"
exec socat "TCP-LISTEN:$PORT,bind=$HOST,reuseaddr,fork" \
  "SYSTEM:$SCRIPT_PATH_QUOTED --handle-connection"
