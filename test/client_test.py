"""MCPクライアントとして中継サーバーを呼び、各ツールが偽の CIRCL の応答を正しくまとめるか確かめる。"""
import asyncio
import json
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = sys.argv[1]
FAKE = sys.argv[2]
failures = []


def check(cond, msg):
    print(("  ok  " if cond else "  NG  ") + msg)
    if not cond:
        failures.append(msg)


async def call(s, name, args):
    r = await s.call_tool(name, args)
    text = r.content[0].text if r.content else ""
    return r.isError, (json.loads(text) if not r.isError else text)


async def main():
    async with streamablehttp_client(URL) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            print("tools:", tools)
            check(len(tools) == 12, "ツールが12個")

            err, t = await call(s, "triage_cve", {"vuln_id": "cve-2021-44228"})
            check(not err and t["id"] == "CVE-2021-44228", "triage: ID を大文字にして引ける")
            check(t["cvss"][0]["score"] == 10 and t["cvss"][0]["source"] == "CISA-ADP", "triage: ADP の CVSS を拾う")
            check(t["cisa_kev"]["date_added"] == "2021-12-10", "triage: CISA KEV を拾う")
            check(t["cisa_ssvc"]["decision_points"]["Exploitation"] == "active", "triage: SSVC を拾う")
            check(t["epss"]["epss"] == 0.99999, "triage: EPSS を数値にする")
            check(t["kev_records"][0]["exploited"] is True and "notes" not in t["kev_records"][0].get("scope", {}),
                  "triage: KEV 記録を要約(長いメモは除く)")
            check(t["sightings"]["counts_in_latest_100"]["exploited"] == 3, "triage: 観測を種類ごとに数える")
            check(t["priority"]["level"].startswith("最優先"), "triage: 悪用ありなら最優先")
            kinds = [r["kind"] for r in t["poc_reports"]["items"]]
            check(kinds == ["scanner", "exploit_claim", "unclear"], f"triage: PoC の報告を分類する {kinds}")
            check(t["poc_reports"]["items"][0]["via"].startswith("GitHub の新着"), "triage: PoC の出どころを示す")
            check(t["exploited_reports"]["total"] == 3, "triage: 悪用の報告は種類を指定して数える")
            rs = " / ".join(t["priority"]["reasons"])
            check("スキャナー・検出ツールの公開 1件" in rs and "名乗る(か中身が不明な)公開の報告 2件" in rs,
                  "triage: スキャナーと攻撃コードを分けて理由に書く")
            check("全CVEの 100.0% がこれ以下" in rs and "上位" not in rs, "triage: EPSS の位置の表記")
            check("seen" in t["sightings"]["meaning"], "triage: 観測の種類の意味を添える")
            check(len(t["description"]) < 1600, "triage: 長い説明文を切る")
            check(len(t["references"]) == 15, "triage: 参考URLを15件までにする")
            check(t["cwe"] == ["CWE-502 Deserialization of Untrusted Data"], "triage: CWE")
            print("  triage size:", len(json.dumps(t, ensure_ascii=False)), "chars")

            err, t = await call(s, "triage_cve", {"vuln_id": "CVE-2099-0001"})
            check(not err and t["found"] is False, "triage: 無いIDは found=false")

            err, t = await call(s, "triage_cve", {"vuln_id": "../../etc"})
            check(err, "triage: おかしなIDは拒否")

            err, t = await call(s, "get_vulnerability", {"vuln_id": "GHSA-jfh8-c2jp-5v3q"})
            check(not err and t["affected"][0]["name"].endswith("log4j-core"), "get_vulnerability: OSV 形式を要約")

            err, t = await call(s, "get_vulnerability", {"vuln_id": "CVE-2021-44228", "with_linked": True})
            check(not err and t["linked"][0]["id"] == "GHSA-jfh8-c2jp-5v3q", "get_vulnerability: 関連IDも付く")

            err, t = await call(s, "get_epss", {"vuln_ids": ["CVE-2021-44228", "CVE-2099-0001"]})
            check(not err and t["epss"]["CVE-2099-0001"] == "記録なし", "get_epss: 複数ID、無いものは記録なし")

            err, t = await call(s, "get_kev", {"exploited": "true", "date_from": "2026-11-01"})
            check(not err and t["items"][0]["status_reason"] == "confirmed", "get_kev: 一覧")
            err, _ = await call(s, "get_kev", {"date_from": "11/01"})
            check(err, "get_kev: 日付の形式を確かめる")

            err, t = await call(s, "get_sightings", {"vuln_id": "CVE-2021-44228", "type": "exploited"})
            check(not err and t["metadata"]["count"] == 3, "get_sightings: 件数情報を返す")
            err, t = await call(s, "get_sightings", {"vuln_id": "CVE-2021-44228", "type": "published-proof-of-concept"})
            check(not err and t["items"][0]["kind"] == "scanner" and "meaning" in t, "get_sightings: PoC は分類して返す")
            err, _ = await call(s, "get_sightings", {"type": "hacked"})
            check(err, "get_sightings: 種類を確かめる")

            err, t = await call(s, "search_vulnerabilities", {"query": "log4j"})
            check(not err and t["items"][0]["id"] == "CVE-2019-17571", "search_vulnerabilities: 旧形式のIDを拾う")

            err, t = await call(s, "search_by_product", {"vendor": "apache", "product": "log4j"})
            check(not err and len(t["items"]) == 1 and t["items"][0]["sources"] == ["nvd", "cvelistv5"],
                  "search_by_product: 出どころ違いの同じCVEを1件にまとめる")
            err, t = await call(s, "search_by_product", {"vendor": "nobody", "product": "x"})
            check(not err and t["items"] == [], "search_by_product: 見つからないときは空")
            err, _ = await call(s, "search_by_product", {"vendor": "a/b", "product": "x"})
            check(err, "search_by_product: / を含む名前は拒否")

            err, t = await call(s, "list_vendors", {"q": "forti"})
            check(not err and t["items"][0]["vendor"] == "fortinet", "list_vendors")
            err, t = await call(s, "list_products", {"vendor": "fortinet"})
            check(not err and t["items"][0]["product"] == "fortios", "list_products")

            err, t = await call(s, "recent_vulnerabilities", {"since": "2026-11-01", "date_sort": "published"})
            check(not err and t["items"][0]["kev"] is True, "recent_vulnerabilities")

            err, t = await call(s, "most_sighted", {"sighting_type": "exploited", "limit": 5})
            check(not err and t["ranking"][0]["count"] == 42, "most_sighted")

            err, t = await call(s, "get_cwe", {"cwe_id": "CWE-79"})
            check(not err and t["found"] and "cwe.mitre.org" in t["url"], "get_cwe")

    calls = httpx.get(FAKE + "/_calls").json()
    check(sum(1 for c in calls if c.startswith("vuln CVE-2021-44228")) <= 2, "同じ問い合わせはキャッシュから返す")
    check(any("'exploited': 'all'" in c for c in calls), "triage は KEV を exploited=all で聞く")


asyncio.run(main())
print()
print("NG:", failures if failures else "なし")
sys.exit(1 if failures else 0)
