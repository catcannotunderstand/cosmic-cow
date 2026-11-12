#!/bin/bash
# Azure Cloud Shell (Bash) で実行する。GitHub Actions が ghcr.io に作ったイメージを Azure Container Apps で動かす。
#
# 使い方:  bash deploy_azure.sh
#   初回も更新も同じ。2回目以降は GitHub の最新のイメージに入れ替える(URL は変わらない)。
#   CIRCL の API キーを使うときだけ:  CIRCL_API_KEY=xxxx bash deploy_azure.sh
set -euo pipefail

REPO="${REPO:-catcannotunderstand/cosmic-cow}"
IMAGE="${IMAGE:-ghcr.io/${REPO,,}:latest}"
RG="cve-rg"
LOC="japaneast"
ENV_NAME="cve-env"
APP="circl-mcp"
ANTHROPIC_IPS="160.79.104.0/21"   # Claude のコネクタからの通信元(Anthropic公開のIP範囲)

echo "== 準備(拡張機能のインストール。1〜2分かかります)"
# 確認の質問で止まらないようにする(質問が出ても画面に見えず、待ち続けてしまうため)
az config set extension.use_dynamic_install=yes_without_prompt >/dev/null 2>&1 || true
az extension add -n containerapp --upgrade -y </dev/null

# 秘密の文字列は初回に作って保存し、2回目以降も同じものを使う(URLが変わらないように)
STATE="$HOME/.circl-mcp.env"
# shellcheck disable=SC1090
[ -f "$STATE" ] && . "$STATE"
# Cloud Shell のファイルが消えていても、Azure に登録済みの値を取り戻す
if [ -z "${MCP_SECRET:-}" ]; then
  MCP_SECRET=$(az containerapp secret show -n "$APP" -g "$RG" --secret-name mcp-secret \
                 --query value -o tsv </dev/null 2>/dev/null || true)
fi
MCP_SECRET="${MCP_SECRET:-$(openssl rand -hex 20)}"   # 40文字のランダムな英数字
printf 'MCP_SECRET=%s\n' "$MCP_SECRET" > "$STATE"; chmod 600 "$STATE"

echo "== サービスの登録(初回は数分かかります)"
for p in Microsoft.App Microsoft.OperationalInsights; do
  az provider register -n "$p" --wait >/dev/null
done
az group create -n "$RG" -l "$LOC" -o none

# ログの保存先(Log Analytics)は作らない。保存に料金がかかるため。画面の「ログストリーム」でリアルタイムの出力は見られる
echo "== 実行環境(初回は数分かかります)"
az containerapp env show -n "$ENV_NAME" -g "$RG" -o none 2>/dev/null || \
  az containerapp env create -n "$ENV_NAME" -g "$RG" -l "$LOC" --logs-destination none -o none

SECRETS=(mcp-secret="$MCP_SECRET")
ENVS=(MCP_SECRET=secretref:mcp-secret CACHE_SECONDS=600)
if [ -n "${CIRCL_API_KEY:-}" ]; then
  SECRETS+=(circl-api-key="$CIRCL_API_KEY")
  ENVS+=(CIRCL_API_KEY=secretref:circl-api-key)
fi

echo "== コンテナ"
if az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null; then
  az containerapp secret set -n "$APP" -g "$RG" --secrets "${SECRETS[@]}" -o none
  # revision-suffix を毎回変えて、:latest でも新しいイメージを取り直させる
  az containerapp update -n "$APP" -g "$RG" --image "$IMAGE" --set-env-vars "${ENVS[@]}" \
    --revision-suffix "r$(date +%m%d%H%M%S)" -o none
else
  # 小さなサーバーなので、いちばん小さい大きさ(0.25 vCPU / 0.5GB)で足りる
  az containerapp create -n "$APP" -g "$RG" --environment "$ENV_NAME" \
    --image "$IMAGE" \
    --secrets "${SECRETS[@]}" --env-vars "${ENVS[@]}" \
    --cpu 0.25 --memory 0.5Gi --min-replicas 0 --max-replicas 1 \
    --ingress external --target-port 8080 -o none
fi

echo "== Claude からの通信だけを通す"
az containerapp ingress access-restriction set -n "$APP" -g "$RG" \
  --rule-name anthropic --ip-address "$ANTHROPIC_IPS" --action Allow \
  --description "Claude connectors" -o none

FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
echo
echo "できました。claude.ai の 設定 → コネクタ → カスタムコネクタを追加 に、次のURLを登録してください。"
echo "(このURLはパスワードと同じです。人に見せないでください)"
echo
echo "  https://${FQDN}/mcp/${MCP_SECRET}"
echo
