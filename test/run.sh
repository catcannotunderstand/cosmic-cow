#!/bin/bash
# 偽の CIRCL と中継サーバーを起動し、MCP クライアントで全ツールを呼んで確かめる。
# 使い方: bash test/run.sh   (requirements.txt を入れた Python で)
set -euo pipefail
cd "$(dirname "$0")/.."

FAKE_PORT=18901
MCP_PORT=18902
SECRET=test-secret-0123456789abcdef

python test/fake_circl.py "$FAKE_PORT" &
FAKE_PID=$!
CIRCL_URL="http://127.0.0.1:${FAKE_PORT}/api" MCP_SECRET="$SECRET" PORT="$MCP_PORT" python server.py &
MCP_PID=$!
trap 'kill $FAKE_PID $MCP_PID 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${MCP_PORT}/healthz" >/dev/null 2>&1 && \
  curl -fsS "http://127.0.0.1:${FAKE_PORT}/_calls" >/dev/null 2>&1 && break
  sleep 0.2
done

# 秘密の文字列が違う入口は 404 になること
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${MCP_PORT}/mcp/wrong")
[ "$CODE" = "404" ] || { echo "違う入口が $CODE を返しました"; exit 1; }
echo "  ok  違う入口は 404"

python test/client_test.py "http://127.0.0.1:${MCP_PORT}/mcp/${SECRET}" "http://127.0.0.1:${FAKE_PORT}"
