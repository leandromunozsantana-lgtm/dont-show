#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
NGROK_BIN="$ROOT/.bin/ngrok"
ENV_FILE="$ROOT/.env"
NGROK_PID_FILE="/tmp/tunnel_open_apis_ngrok.pid"
PROXY_PID_FILE="/tmp/tunnel_open_apis_proxy.pid"
NGROK_LOG="/tmp/ngrok-tunnel.log"

# --- Load .env ---
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERROR] .env not found. Copy .env.example to .env and fill in your values."
  exit 1
fi
set -a; source "$ENV_FILE"; set +a

if [[ -z "${NGROK_AUTHTOKEN:-}" || "$NGROK_AUTHTOKEN" == "your_authtoken_here" ]]; then
  echo "Ngrok authtoken no configurado."
  echo "Obtén el tuyo en: https://dashboard.ngrok.com/get-started/your-authtoken"
  read -rp "Introduce tu NGROK_AUTHTOKEN: " NGROK_AUTHTOKEN
  if [[ -z "$NGROK_AUTHTOKEN" ]]; then
    echo "[ERROR] No se introdujo ningún token. Saliendo."; exit 1
  fi
  sed -i "s|^NGROK_AUTHTOKEN=.*|NGROK_AUTHTOKEN=$NGROK_AUTHTOKEN|" "$ENV_FILE"
  echo "[*] Token guardado en .env"
fi

if [[ -z "${PROXY_API_KEY:-}" || "$PROXY_API_KEY" == "your_secret_key_here" ]]; then
  echo "API key de protección no configurada."
  read -rp "Introduce tu PROXY_API_KEY (clave que usarás desde fuera): " PROXY_API_KEY
  if [[ -z "$PROXY_API_KEY" ]]; then
    echo "[ERROR] No se introdujo ninguna clave. Saliendo."; exit 1
  fi
  sed -i "s|^PROXY_API_KEY=.*|PROXY_API_KEY=$PROXY_API_KEY|" "$ENV_FILE"
  echo "[*] API key guardada en .env"
fi

PROXY_PORT="${PROXY_PORT:-8080}"
export PROXY_API_KEY PROXY_PORT INTERNAL_API_KEY="${INTERNAL_API_KEY:-skills-network}"

# Opcional: NGROK_API_KEY (https://dashboard.ngrok.com/api-keys) — distinto al
# authtoken. Si está definido, podemos matar sesiones agente / endpoints que
# estén activos en la cuenta desde OTRA máquina, sin esperar los ~60s de
# heartbeat. Si no está, caemos al reclaim local de siempre.
NGROK_API_KEY="${NGROK_API_KEY:-}"

# --- Install ngrok if missing ---
if [[ ! -x "$NGROK_BIN" ]]; then
  echo "[*] ngrok not found, downloading..."
  mkdir -p "$(dirname "$NGROK_BIN")"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  NGROK_ARCH="amd64" ;;
    aarch64) NGROK_ARCH="arm64" ;;
    armv7l)  NGROK_ARCH="arm"   ;;
    *)       echo "[ERROR] Unsupported arch: $ARCH"; exit 1 ;;
  esac
  curl -sSL "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-${NGROK_ARCH}.tgz" \
    | tar -xz -C "$(dirname "$NGROK_BIN")"
  chmod +x "$NGROK_BIN"
  echo "[*] ngrok installed: $($NGROK_BIN version)"
fi

"$NGROK_BIN" config add-authtoken "$NGROK_AUTHTOKEN" --log=false > /dev/null

# --- Helpers ---
read_pid() { [[ -f "$1" ]] && cat "$1" 2>/dev/null || echo ""; }
is_alive() { local pid=$1; [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; }
kill_pid_file() {
  local pid; pid=$(read_pid "$1")
  if is_alive "$pid"; then kill "$pid" 2>/dev/null || true; fi
  rm -f "$1"
}

cleanup() {
  echo ""
  echo "[*] Shutting down..."
  kill_pid_file "$PROXY_PID_FILE"
  kill_pid_file "$NGROK_PID_FILE"
  # Belt-and-suspenders: nuke any stragglers we might have spawned
  pkill -f "$ROOT/proxy.py" 2>/dev/null || true
  pkill -f "$NGROK_BIN http" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Kill any previous proxy.py / ngrok left running by an earlier shell so
# that a fresh `run.sh` in a new terminal doesn't collide on the port or
# trip ngrok limits. proxy.py already reclaims its own port; this also
# covers ngrok which the proxy can't touch.
#
# ngrok specifically needs a *graceful* shutdown: a SIGKILL leaves the
# endpoint published in ngrok cloud for ~60s of heartbeat timeout, and
# the next `ngrok http` against the same authtoken fails with
# ERR_NGROK_334 ("endpoint already online"). We send SIGTERM, wait for
# the process to actually exit (up to NGROK_GRACE seconds), then ping
# the local agent API as a fallback to force-disconnect from cloud.
NGROK_GRACE="${NGROK_GRACE:-8}"

# Mata todo lo que la cuenta tenga activo en ngrok cloud usando la API HTTPS.
# Funciona aunque la sesión venga de otra máquina: detiene tunnel_sessions
# y borra endpoints colgados. Cuando esto corre, el endpoint queda libre
# casi al instante, sin esperar el heartbeat de ~60s.
cloud_kill() {
  [[ -z "$NGROK_API_KEY" ]] && return 0
  echo "[*] Matando sesiones/endpoints remotos vía ngrok API cloud..."

  # 1) Stop de tunnel_sessions activas (agentes conectados).
  local sessions
  sessions=$(curl -sf --max-time 5 \
    -H "Authorization: Bearer $NGROK_API_KEY" \
    -H "Ngrok-Version: 2" \
    https://api.ngrok.com/tunnel_sessions 2>/dev/null \
    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for s in d.get('tunnel_sessions', []) or []:
        print(s.get('id',''))
except Exception:
    pass
" 2>/dev/null) || sessions=""

  for sid in $sessions; do
    [[ -z "$sid" ]] && continue
    if curl -sf --max-time 5 -X POST \
        -H "Authorization: Bearer $NGROK_API_KEY" \
        -H "Ngrok-Version: 2" \
        "https://api.ngrok.com/tunnel_sessions/$sid/stop" > /dev/null 2>&1; then
      echo "[*]   tunnel_session $sid → stop"
    else
      echo "[!]   tunnel_session $sid no se pudo detener"
    fi
  done

  # 2) Borrar endpoints residuales (a veces el endpoint sigue listado
  #    aunque la sesión ya esté caída, sobre todo con free tier).
  local endpoints
  endpoints=$(curl -sf --max-time 5 \
    -H "Authorization: Bearer $NGROK_API_KEY" \
    -H "Ngrok-Version: 2" \
    https://api.ngrok.com/endpoints 2>/dev/null \
    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for e in d.get('endpoints', []) or []:
        print(e.get('id',''))
except Exception:
    pass
" 2>/dev/null) || endpoints=""

  for eid in $endpoints; do
    [[ -z "$eid" ]] && continue
    if curl -sf --max-time 5 -X DELETE \
        -H "Authorization: Bearer $NGROK_API_KEY" \
        -H "Ngrok-Version: 2" \
        "https://api.ngrok.com/endpoints/$eid" > /dev/null 2>&1; then
      echo "[*]   endpoint $eid → deleted"
    fi
  done
}

reclaim_previous() {
  # Proxy is cheap to kill — port reclaim in proxy.py covers stragglers.
  if pgrep -f "$ROOT/proxy.py" > /dev/null 2>&1; then
    pkill -f "$ROOT/proxy.py" 2>/dev/null || true
    sleep 0.3
    pkill -9 -f "$ROOT/proxy.py" 2>/dev/null || true
  fi

  # Si tenemos API key, primero limpiamos lo que esté activo en la cuenta
  # (sirve incluso si el túnel previo vive en OTRA máquina).
  cloud_kill

  # ngrok needs the graceful path.
  if pgrep -f "$NGROK_BIN http" > /dev/null 2>&1; then
    echo "[*] Existing ngrok session found; asking it to disconnect cleanly..."
    # Try the local agent API first — this is the cleanest path because
    # ngrok sends a proper goodbye to the cloud and the endpoint frees
    # almost immediately.
    curl -sf --max-time 2 -X DELETE http://127.0.0.1:4040/api/tunnels > /dev/null 2>&1 || true
    pkill -TERM -f "$NGROK_BIN http" 2>/dev/null || true
    # Wait up to NGROK_GRACE seconds for the process to actually exit.
    for _ in $(seq 1 "$NGROK_GRACE"); do
      pgrep -f "$NGROK_BIN http" > /dev/null 2>&1 || break
      sleep 1
    done
    # If it's still stuck, force it.
    if pgrep -f "$NGROK_BIN http" > /dev/null 2>&1; then
      echo "[!] ngrok did not exit gracefully; sending SIGKILL"
      pkill -9 -f "$NGROK_BIN http" 2>/dev/null || true
    fi
  fi

  # Stale PID files would confuse is_alive() in the watch loop.
  rm -f "$PROXY_PID_FILE" "$NGROK_PID_FILE"
}

start_proxy() {
  python3 "$ROOT/proxy.py" &
  echo $! > "$PROXY_PID_FILE"
}

start_ngrok() {
  "$NGROK_BIN" http "http://127.0.0.1:${PROXY_PORT}" --log=stdout > "$NGROK_LOG" 2>&1 &
  echo $! > "$NGROK_PID_FILE"
}

fetch_tunnel_url() {
  curl -sf --max-time 3 http://127.0.0.1:4040/api/tunnels 2>/dev/null \
    | python3 -c "
import sys, json
try:
    t = json.load(sys.stdin).get('tunnels') or []
    print(t[0]['public_url'] if t else '')
except Exception:
    print('')
" 2>/dev/null || echo ""
}

wait_for_proxy() {
  for i in $(seq 1 30); do
    sleep 0.5
    if curl -sf --max-time 2 "http://127.0.0.1:${PROXY_PORT}/health" > /dev/null 2>&1; then
      return 0
    fi
    if ! is_alive "$(read_pid "$PROXY_PID_FILE")"; then
      return 1
    fi
  done
  return 1
}

wait_for_tunnel() {
  for i in $(seq 1 30); do
    sleep 1
    local url; url=$(fetch_tunnel_url)
    if [[ -n "$url" ]]; then
      echo "$url"
      return 0
    fi
    if ! is_alive "$(read_pid "$NGROK_PID_FILE")"; then
      return 1
    fi
  done
  return 1
}

print_info() {
  local url=$1
  cat <<EOF

==========================================
  TUNNELS READY

  [Anthropic]
  Base URL : ${url}/anthropic
  API Key  : ${PROXY_API_KEY}

  [OpenAI]
  Base URL : ${url}/openai
  API Key  : ${PROXY_API_KEY}
==========================================

Export variables:
  export ANTHROPIC_API_KEY=${PROXY_API_KEY}
  export ANTHROPIC_BASE_URL=${url}/anthropic
  export OPENAI_API_KEY=${PROXY_API_KEY}
  export OPENAI_BASE_URL=${url}/openai

Press Ctrl+C to stop.
EOF
}

# --- Boot ---
reclaim_previous
echo "[*] Starting proxy..."
start_proxy
if ! wait_for_proxy; then
  echo "[ERROR] Proxy did not become healthy. Check proxy.py output."
  exit 1
fi
echo "[*] Proxy ready."

echo "[*] Starting ngrok tunnel..."
# ngrok cloud can hold the endpoint as "online" for up to ~60s after a
# previous (non-graceful) shutdown. Retry start with backoff so we ride
# through that window instead of bailing immediately on ERR_NGROK_334.
URL=""
for attempt in 1 2 3 4 5; do
  start_ngrok
  if URL=$(wait_for_tunnel); then
    break
  fi
  if grep -q "ERR_NGROK_334\|already online\|ERR_NGROK_108\|simultaneous" "$NGROK_LOG" 2>/dev/null; then
    echo "[!] ngrok endpoint aún ocupado (intento $attempt/5)."
    pkill -f "$NGROK_BIN http" 2>/dev/null || true
    if [[ -n "$NGROK_API_KEY" ]]; then
      # Con API key intentamos el desalojo remoto al instante en vez
      # de esperar el heartbeat de ~60s.
      cloud_kill
      sleep 2
    else
      wait_secs=$((attempt * 10))
      echo "[!] sin NGROK_API_KEY; esperando ${wait_secs}s al heartbeat de ngrok..."
      sleep "$wait_secs"
    fi
  else
    break
  fi
done
[[ -z "$URL" ]] && {
  echo "[ERROR] Tunnel did not start. Check $NGROK_LOG"
  cat "$NGROK_LOG" 2>/dev/null || true
  exit 1
}
print_info "$URL"
LAST_URL="$URL"

# --- Watch loop ---
while true; do
  sleep 10

  # Proxy health
  if ! curl -sf --max-time 3 "http://127.0.0.1:${PROXY_PORT}/health" > /dev/null 2>&1; then
    echo "[!] Proxy not responding, restarting..."
    kill_pid_file "$PROXY_PID_FILE"
    sleep 1
    start_proxy
    if ! wait_for_proxy; then
      echo "[!] Proxy restart failed; will retry next cycle."
      continue
    fi
    echo "[*] Proxy back up."
  fi

  # Tunnel via ngrok local API
  TUNNEL_URL=$(fetch_tunnel_url)
  if [[ -z "$TUNNEL_URL" ]]; then
    echo "[!] Tunnel not responding, restarting..."
    kill_pid_file "$NGROK_PID_FILE"
    sleep 1
    start_ngrok
    NEW_URL=$(wait_for_tunnel) && {
      LAST_URL="$NEW_URL"
      print_info "$NEW_URL"
    } || echo "[!] Failed to restart tunnel, retrying in 10s..."
  elif [[ "$TUNNEL_URL" != "$LAST_URL" ]]; then
    LAST_URL="$TUNNEL_URL"
    print_info "$TUNNEL_URL"
  fi
done
