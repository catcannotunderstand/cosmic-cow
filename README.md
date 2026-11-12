# CIRCL 脆弱性情報コネクタ

CIRCL(ルクセンブルクのCSIRT)が無料で公開している [Vulnerability-Lookup](https://vulnerability.circl.lu) を Claude のカスタムコネクタにする。登録すると、チャットで「CVE-2024-3400 はどれくらい危ない？」と聞くだけで、Claude が CVSS・EPSS・悪用の記録・観測情報を調べて答えられる。

```
GitHub (main にプッシュ) ──Actions──▶ テスト → ghcr.io にイメージ → Azure を入れ替え
                                                     │
Claude ──(コネクタ)──▶ Azure Container Apps(中継サーバー、8080番)──▶ vulnerability.circl.lu/api
```

CIRCL の API は認証なしで使えるので、鍵やストレージの準備は要らない。

## 構築手順

作業はすべてブラウザの中(GitHub と Azure Cloud Shell)でできる。PC のブラウザのほうが楽。

### 0. イメージを公開にする(1回だけ)

最初に main にプッシュすると、GitHub Actions がイメージを作る(Actions タブで緑になるまで数分)。
そのあと、GitHub のプロフィール → Packages → `cosmic-cow` → Package settings → Change visibility → **Public**。
コードにもイメージにも秘密の情報は入っていない。公開にすると Azure が認証なしでイメージを取れる。

### 1. Azure:コンテナを動かす(約10分)

1. https://portal.azure.com 上部の Cloud Shell(`>_`)を開き、**Bash** を選ぶ。
2. 次を実行する。
   ```
   git clone https://github.com/catcannotunderstand/cosmic-cow && cd cosmic-cow
   bash deploy_azure.sh
   ```
3. 最後に `https://〜/mcp/〜` のURLが表示される。**これはパスワードと同じなので人に見せない。**

### 2. claude.ai に登録する

1. claude.ai(Web)→ 設定 → コネクタ → 「カスタムコネクタを追加」
2. 名前は `CIRCL`、URL は手順1で表示されたもの。認証の設定は空のまま。
3. チャットのツール一覧で CIRCL をオンにする。

## 更新するとき(自動)

main にプッシュすると、GitHub Actions がテストしてイメージを作り、そのまま Azure のアプリを入れ替える(数分)。

そのために、最初に1回だけ Azure Cloud Shell で次を実行し、表示された3行のIDを `.github/workflows/build.yml` の `env:` に書く(Claude に貼れば書いてくれる)。

```
cd ~/cosmic-cow && git pull
bash setup_github_deploy.sh
```

- Entra ID に「cosmic-cow-deploy」というアプリを登録し、**このリポジトリの main ブランチから実行されたときだけ**ログインできるようにする(OIDC。パスワードや鍵は作らない)。
- 権限は **リソースグループ cve-rg の中だけ**(共同作成者)。VOICEVOX の voicevox-rg などには触れない。
- 3つのIDはパスワードではない。
- やめるときは Entra ID のアプリの登録から「cosmic-cow-deploy」を削除する。

手動で入れ替えたいときは `bash deploy_azure.sh` を実行し直せばよい(URL は変わらない)。

## 守りの設定

- 入口のURLに **40文字のランダムな文字列** が入っていて、知らない人は呼べない。
- Azure の通信制限で、**Anthropic の IP 範囲(160.79.104.0/21)からしか届かない**。自分のブラウザで URL を開いて 403 になるのは正常。
- 読み取り専用。CIRCL への書き込み(コメントや観測の登録)はしない。
- ツールに渡された ID や製品名は形を確かめてから URL に入れる(`../` などで別の API を呼ばせない)。
- 同じ問い合わせは10分間覚えておき、CIRCL に負担をかけない。

## 費用の目安

- Azure Container Apps:0.25 vCPU / 0.5GB の最小構成で、使っていないときは0台に縮む。毎月の無料枠に収まる見込み。
- GitHub(Actions・ghcr.io):公開リポジトリなら無料。
- CIRCL:無料。

使わなくなったら Azure Cloud Shell で `az group delete -n cve-rg` を実行すれば Azure 側は全部消える。

## ツール(Claude から見たもの)

| ツール | 内容 |
|---|---|
| `triage_cve` | 1件の CVE の概要・CVSS・CWE・影響製品・EPSS・悪用の記録・観測情報と、目安の優先度をまとめて返す |
| `get_vulnerability` | 1件の詳細(CVE / GHSA / PYSEC / EUVD などのID)。関連する別IDの記録も付けられる |
| `get_epss` | EPSS(30日以内に悪用される確率)。最大30件まとめて |
| `get_kev` | 悪用が確認された(疑われる)脆弱性の記録。期間や理由で絞り込める |
| `get_sightings` | 観測情報(悪用された・PoC が公開された・SNS で話題 など) |
| `search_vulnerabilities` | キーワードで全文検索 |
| `search_by_product` | ベンダー名と製品名で検索 |
| `list_vendors` / `list_products` | CIRCL でのベンダー名・製品名の表記を調べる |
| `recent_vulnerabilities` | 最近公開・更新された脆弱性 |
| `most_sighted` | 期間内によく観測された脆弱性のランキング |
| `get_cwe` | CWE(弱点の種類)の説明 |

`triage_cve` の優先度は、CISA KEV や悪用の観測があれば「最優先」、EPSS が 0.1 以上か PoC があれば「高」、という単純な目安。実際の優先度は、その製品を使っているか・外部に公開しているかで変わる。

## ファイル

| ファイル | 内容 |
|---|---|
| `server.py` | 中継サーバー(MCP) |
| `Dockerfile`, `requirements.txt` | Python の小さなイメージ |
| `.github/workflows/build.yml` | main へのプッシュでテスト→イメージ作成→Azure の入れ替え |
| `setup_github_deploy.sh` | GitHub Actions から Azure を操作できるようにする(1回だけ) |
| `deploy_azure.sh` | Azure Container Apps に配置する |
| `test/` | 偽の CIRCL を使った動作確認(`bash test/run.sh`) |

## 出典の表記

データは CIRCL Vulnerability-Lookup(https://vulnerability.circl.lu)から取得している。EPSS は FIRST.org、KEV の一部は CISA のデータ。
