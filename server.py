"""CIRCL Vulnerability-Lookup を Claude のカスタムコネクタ(リモートMCPサーバー)として使うための中継サーバー。

CIRCL(ルクセンブルクのCSIRT)が無料で公開している https://vulnerability.circl.lu/api を呼び、
Claude が読みやすい大きさに要約して返す。CIRCL のAPIは認証なしで使える。

ツール:
  triage_cve              1件のCVEの概要・CVSS・EPSS・悪用状況(KEV)・観測情報をまとめて返す
  get_vulnerability       1件の脆弱性の詳細(CVE / GHSA / PYSEC などのID)
  get_epss                EPSS(30日以内に悪用される確率)。複数IDも可
  get_kev                 悪用が確認された脆弱性(KEV)の記録
  get_sightings           観測情報(悪用された・PoCが公開された・見かけた など)
  search_vulnerabilities  キーワードで全文検索
  search_by_product       ベンダー名と製品名で検索
  list_vendors            ベンダー名の一覧・検索
  list_products           ベンダーの製品名の一覧・検索
  recent_vulnerabilities  最近更新・公開された脆弱性
  most_sighted            期間内によく観測された脆弱性(話題の脆弱性)
  get_cwe                 CWE(弱点の種類)の説明

環境変数:
  MCP_SECRET     必須。MCPの入口のURLに入れる秘密の文字列(/mcp/<MCP_SECRET>)
  CIRCL_URL      既定 https://vulnerability.circl.lu/api
  CIRCL_API_KEY  任意。CIRCL のアカウントのAPIキー(あれば X-API-KEY ヘッダーで送る)
  CACHE_SECONDS  同じ問い合わせの結果を覚えておく秒数(既定 600)
  PORT           既定 8080
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any, Optional
from urllib.parse import quote

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

log = logging.getLogger("circl-mcp")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)   # 問い合わせ1件ごとのログは出さない

CIRCL_URL = os.getenv("CIRCL_URL", "https://vulnerability.circl.lu/api").rstrip("/")
CIRCL_API_KEY = os.getenv("CIRCL_API_KEY", "")
MCP_SECRET = os.getenv("MCP_SECRET", "")
CACHE_SECONDS = float(os.getenv("CACHE_SECONDS", "600"))
PORT = int(os.getenv("PORT", "8080"))

DESC_MAX = 1500          # 説明文はこの文字数で切る
REFS_MAX = 15            # 参考URLはこの件数まで
AFFECTED_MAX = 20        # 影響を受ける製品はこの件数まで
SIGHTING_TYPES = ("seen", "exploited", "published-proof-of-concept", "not-exploited",
                  "confirmed", "not-confirmed", "patched", "not-patched")

if not re.fullmatch(r"[A-Za-z0-9_-]{24,}", MCP_SECRET):
    raise SystemExit("MCP_SECRET に24文字以上の英数字(と - _)を設定してください")

VULN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,79}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


# ---------------------------------------------------------------- CIRCL への問い合わせ

_headers = {"User-Agent": "circl-mcp-connector/1.0 (+Claude custom connector)",
            "Accept": "application/json"}
if CIRCL_API_KEY:
    _headers["X-API-KEY"] = CIRCL_API_KEY
http = httpx.AsyncClient(base_url=CIRCL_URL, headers=_headers,
                         timeout=httpx.Timeout(30, connect=10), follow_redirects=True)

_cache: dict[str, tuple[float, Any]] = {}
CACHE_MAX = 500


class NotFound(Exception):
    pass


async def circl(method: str, path: str, params: Optional[dict] = None, body: Optional[dict] = None,
                allow_404: bool = False) -> Any:
    """CIRCL のAPIを呼んでJSONを返す。GETの結果はしばらく覚えておく(CIRCL に負担をかけないため)。"""
    params = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
    key = f"{method} {path} {sorted(params.items())} {body}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    for attempt in range(3):
        try:
            r = await http.request(method, path, params=params, json=body)
        except httpx.TransportError as e:
            if attempt == 2:
                raise RuntimeError(f"CIRCL に接続できません: {e}") from e
            await asyncio.sleep(1.5 * (attempt + 1))
            continue
        if r.status_code == 404:
            if allow_404:
                return None
            raise NotFound(path)
        if r.status_code in (429, 502, 503, 504) and attempt < 2:
            await asyncio.sleep(2 * (attempt + 1))
            continue
        if r.status_code >= 400:
            raise RuntimeError(f"CIRCL がエラーを返しました(HTTP {r.status_code}): {r.text[:300]}")
        try:
            data = r.json()
        except ValueError as e:
            raise RuntimeError("CIRCL の応答がJSONではありません") from e
        if len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (time.time(), data)
        return data
    raise AssertionError


def seg(s: str, what: str) -> str:
    """URLのパスに入れる値を確かめて、そのまま安全に入れられる形にする。"""
    s = (s or "").strip()
    if not s or len(s) > 120 or "/" in s or s in (".", ".."):
        raise ValueError(f"{what} の値が正しくありません")
    return quote(s, safe="")


def check_id(v: str) -> str:
    v = (v or "").strip()
    if not VULN_ID_RE.fullmatch(v):
        raise ValueError("脆弱性IDの形式が違います(例: CVE-2021-44228, GHSA-jfh8-c2jp-5v3q)")
    return v.upper() if v.lower().startswith("cve-") else v


def date_or_none(d: Optional[str], what: str) -> Optional[str]:
    if not d:
        return None
    if not DATE_RE.fullmatch(d):
        raise ValueError(f"{what} は YYYY-MM-DD の形で指定してください")
    return d


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(n)))


def cut(s: Any, n: int = DESC_MAX) -> Any:
    if isinstance(s, str) and len(s) > n:
        return s[:n] + "…(省略)"
    return s


# ---------------------------------------------------------------- 要約

def _en_first(items: list) -> Optional[str]:
    """[{lang, value}, ...] から英語(なければ最初)の value を取る。"""
    if not isinstance(items, list) or not items:
        return None
    for it in items:
        if isinstance(it, dict) and str(it.get("lang", "")).lower().startswith("en") and it.get("value"):
            return it["value"]
    first = items[0]
    return first.get("value") if isinstance(first, dict) else None


def _containers(rec: dict) -> tuple[dict, list]:
    c = rec.get("containers") or {}
    cna = c.get("cna") or {}
    adp = c.get("adp") or []
    return (cna if isinstance(cna, dict) else {}), (adp if isinstance(adp, list) else [])


def _record_id(rec: dict) -> Optional[str]:
    meta = rec.get("cveMetadata") or {}
    if meta.get("cveId"):
        return meta["cveId"]
    cna, _ = _containers(rec)
    legacy = ((cna.get("x_legacyV4Record") or {}).get("CVE_data_meta") or {}).get("ID")
    if legacy:
        return legacy
    for g in cna.get("x_gcve") or []:
        if isinstance(g, dict) and g.get("vulnId"):
            return str(g["vulnId"]).upper()
    return rec.get("id")


def _metrics(rec: dict) -> dict:
    """CVSS(全部の版と出どころ)、SSVC、KEV、CNAの独自の深刻度を集める。"""
    cna, adp = _containers(rec)
    blocks = [("CNA:" + str((cna.get("providerMetadata") or {}).get("shortName", "")), cna)]
    blocks += [(str((a.get("providerMetadata") or {}).get("shortName", "ADP")), a)
               for a in adp if isinstance(a, dict)]
    cvss, ssvc, kev, other = [], None, None, []
    for src, b in blocks:
        for m in b.get("metrics") or []:
            if not isinstance(m, dict):
                continue
            for k, v in m.items():
                if k.startswith("cvssV") and isinstance(v, dict):
                    cvss.append({"version": v.get("version") or k[5:].replace("_", "."),
                                 "score": v.get("baseScore"), "severity": v.get("baseSeverity"),
                                 "vector": v.get("vectorString"), "source": src})
                elif k == "other" and isinstance(v, dict):
                    t, content = v.get("type"), v.get("content")
                    if t == "ssvc" and isinstance(content, dict):
                        opts = {}
                        for o in content.get("options") or []:
                            if isinstance(o, dict):
                                opts.update(o)
                        ssvc = {"decision_points": opts, "role": content.get("role"),
                                "timestamp": content.get("timestamp")}
                    elif t == "kev" and isinstance(content, dict):
                        kev = {"date_added": content.get("dateAdded"), "reference": content.get("reference")}
                    elif content:
                        other.append({"type": t, "content": cut(str(content), 200), "source": src})
    # 新しい版のCVSSを先に
    cvss.sort(key=lambda x: str(x.get("version") or ""), reverse=True)
    out: dict = {"cvss": cvss}
    if ssvc:
        out["cisa_ssvc"] = ssvc
    if kev:
        out["cisa_kev"] = kev
    if other:
        out["other_severity"] = other
    return out


def _cwes(rec: dict) -> list[str]:
    cna, adp = _containers(rec)
    seen: list[str] = []
    for b in [cna, *[a for a in adp if isinstance(a, dict)]]:
        for pt in b.get("problemTypes") or []:
            for d in (pt or {}).get("descriptions") or []:
                cid, desc = d.get("cweId"), (d.get("description") or "").strip()
                if cid and desc and not desc.startswith(cid):
                    label = f"{cid} {desc}"
                else:
                    label = desc or cid
                if label and label not in seen:
                    seen.append(label)
    return seen


def _affected(rec: dict) -> list[dict]:
    cna, _ = _containers(rec)
    out = []
    for a in (cna.get("affected") or [])[:AFFECTED_MAX]:
        if not isinstance(a, dict):
            continue
        versions = []
        for v in (a.get("versions") or [])[:10]:
            if not isinstance(v, dict):
                continue
            s = v.get("version", "")
            if v.get("lessThan"):
                s += f" 〜 {v['lessThan']} 未満"
            elif v.get("lessThanOrEqual"):
                s += f" 〜 {v['lessThanOrEqual']} 以下"
            if v.get("status"):
                s += f" [{v['status']}]"
            versions.append(s.strip())
        out.append({k: v for k, v in {
            "vendor": a.get("vendor"), "product": a.get("product") or a.get("packageName"),
            "versions": versions, "default_status": a.get("defaultStatus")}.items() if v})
    return out


def _refs(rec: dict) -> list[dict]:
    cna, adp = _containers(rec)
    out, seen = [], set()
    for b in [cna, *[a for a in adp if isinstance(a, dict)]]:
        for r in b.get("references") or []:
            url = (r or {}).get("url")
            if url and url not in seen:
                seen.add(url)
                item = {"url": url}
                if r.get("tags"):
                    item["tags"] = [t for t in r["tags"] if t != "x_transferred"] or None
                out.append({k: v for k, v in item.items() if v})
    return out[:REFS_MAX]


def summarize(rec: Any) -> Any:
    """CIRCL の1件の記録を、Claude が読みやすい大きさにまとめる。形が分からなければ大きさだけ抑えて返す。"""
    if not isinstance(rec, dict):
        return rec
    if "containers" in rec or "cveMetadata" in rec:          # CVE JSON 5.x
        meta = rec.get("cveMetadata") or {}
        cna, _ = _containers(rec)
        return {k: v for k, v in {
            "id": _record_id(rec),
            "state": meta.get("state"),
            "title": cna.get("title"),
            "description": cut(_en_first(cna.get("descriptions") or [])),
            "assigner": meta.get("assignerShortName"),
            "published": meta.get("datePublished"),
            "updated": meta.get("dateUpdated"),
            **_metrics(rec),
            "cwe": _cwes(rec),
            "affected": _affected(rec),
            "references": _refs(rec),
        }.items() if v not in (None, [], {})}
    if "affected" in rec and ("summary" in rec or "details" in rec):   # OSV (GHSA / PYSEC など)
        sev = [{"type": s.get("type"), "score": s.get("score")} for s in rec.get("severity") or []
               if isinstance(s, dict)]
        pk = []
        for a in (rec.get("affected") or [])[:AFFECTED_MAX]:
            p = (a or {}).get("package") or {}
            ranges = []
            for rg in (a or {}).get("ranges") or []:
                for ev in (rg or {}).get("events") or []:
                    ranges.append(", ".join(f"{k}={v}" for k, v in ev.items()))
            pk.append({"ecosystem": p.get("ecosystem"), "name": p.get("name"), "events": ranges[:10]})
        return {k: v for k, v in {
            "id": rec.get("id"), "aliases": rec.get("aliases"), "summary": rec.get("summary"),
            "details": cut(rec.get("details")), "published": rec.get("published"),
            "modified": rec.get("modified"), "severity": sev,
            "cwe": (rec.get("database_specific") or {}).get("cwe_ids"),
            "affected": pk,
            "references": [r.get("url") for r in (rec.get("references") or [])[:REFS_MAX] if isinstance(r, dict)],
        }.items() if v not in (None, [], {})}
    return shrink(rec)


def shrink(x: Any, depth: int = 0) -> Any:
    """形の分からないJSONを、長い文字列と長い配列を切って小さくする。"""
    if depth > 6:
        return "…"
    if isinstance(x, dict):
        return {k: shrink(v, depth + 1) for k, v in list(x.items())[:60]}
    if isinstance(x, list):
        out = [shrink(v, depth + 1) for v in x[:25]]
        if len(x) > 25:
            out.append(f"…ほか{len(x) - 25}件")
        return out
    return cut(x, 800)


def brief(rec: Any) -> Any:
    """一覧用のさらに短い要約。"""
    s = summarize(rec)
    if not isinstance(s, dict) or "id" not in s:
        return s
    top = (s.get("cvss") or [{}])[0]
    return {k: v for k, v in {
        "id": s.get("id"), "title": s.get("title") or s.get("summary"),
        "description": cut(s.get("description") or s.get("details"), 300),
        "cvss": f'{top.get("score")} {top.get("severity") or ""} (v{top.get("version")})'.strip()
                if top.get("score") is not None else None,
        "kev": bool(s.get("cisa_kev")) or None,
        "published": s.get("published"), "updated": s.get("updated") or s.get("modified"),
        "products": [f'{a.get("vendor", "")} {a.get("product", "")}'.strip() for a in s.get("affected", [])[:5]]
                    or None,
    }.items() if v not in (None, [], "")}


def _list_of(data: Any) -> tuple[list, dict]:
    """{"metadata":…, "data":[…]} などの一覧の応答から、項目の配列と件数情報を取り出す。"""
    if isinstance(data, list):
        return data, {}
    if isinstance(data, dict):
        for k in ("data", "results", "items"):
            if isinstance(data.get(k), list):
                return data[k], data.get("metadata") or {k2: data[k2] for k2 in
                                                         ("total", "total_count", "count", "page", "per_page")
                                                         if k2 in data}
    return [], {}


# ---------------------------------------------------------------- MCP

mcp = FastMCP(
    "CIRCL Vulnerability-Lookup",
    instructions=(
        "脆弱性情報の検索(CIRCL Vulnerability-Lookup)。CVEが1件決まっているときは、まず triage_cve を使う"
        "(概要・CVSS・EPSS・悪用の有無・観測情報が一度に分かる)。製品の脆弱性を探すときは "
        "list_vendors / list_products で正しい名前を確かめてから search_by_product を使う。"
        "名前が分からないときは search_vulnerabilities で全文検索する。"
        "EPSS は30日以内に悪用される確率(0〜1)、KEV は実際に悪用が確認された記録。"
        "答えるときは出典として https://vulnerability.circl.lu/vuln/<ID> を示すとよい。"
    ),
    stateless_http=True,
    json_response=True,
    streamable_http_path=f"/mcp/{MCP_SECRET}",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _epss_item(data: Any) -> Optional[dict]:
    items, _ = _list_of(data)
    if not items or not isinstance(items[0], dict):
        return None
    it = items[0]
    try:
        return {"epss": float(it.get("epss")), "percentile": float(it.get("percentile")), "date": it.get("date")}
    except (TypeError, ValueError):
        return shrink(it)


def _kev_item(it: dict) -> dict:
    st = it.get("status") or {}
    ts = it.get("timestamps") or {}
    ev = it.get("evidence") or []
    return {k: v for k, v in {
        "vuln_id": (it.get("vulnerability") or {}).get("vulnId"),
        "exploited": st.get("exploited"), "status_reason": st.get("status_reason"),
        "status_updated_at": st.get("status_updated_at"),
        "first_seen_at": ts.get("first_seen_at"), "last_seen_at": ts.get("last_seen_at"),
        "characteristics": it.get("characteristics"),
        "scope": {k: v for k, v in (it.get("scope") or {}).items() if k != "notes"} or None,
        "evidence": [{k: e.get(k) for k in ("type", "source", "signal", "confidence")}
                     for e in ev[:5] if isinstance(e, dict)],
        "references": [r.get("url") for r in (it.get("references") or [])[:5] if isinstance(r, dict)],
    }.items() if v not in (None, [], {})}


def _sighting_item(it: dict) -> dict:
    return {k: v for k, v in {
        "type": it.get("type"), "source": cut(it.get("source"), 300),
        "date": it.get("creation_timestamp"), "vuln_id": it.get("vulnerability"),
        "author": (it.get("author") or {}).get("login"), "content": cut(it.get("content"), 300),
    }.items() if v}


def _priority(s: dict, epss: Optional[dict], kev_entries: list, sighting_counts: dict) -> dict:
    """目安の優先度。判断材料を一緒に返す(最終判断は使う人の環境しだい)。"""
    reasons = []
    top = (s.get("cvss") or [{}])[0].get("score")
    exploited = bool(s.get("cisa_kev")) or any(k.get("exploited") for k in kev_entries) \
        or sighting_counts.get("exploited", 0) > 0
    p = epss.get("epss") if isinstance(epss, dict) and isinstance(epss.get("epss"), float) else None
    if s.get("cisa_kev"):
        reasons.append(f'CISA KEV に掲載({s["cisa_kev"].get("date_added")})')
    if any(k.get("exploited") for k in kev_entries):
        reasons.append("CIRCL の KEV 記録で悪用あり")
    if sighting_counts.get("exploited"):
        reasons.append(f'悪用の観測 {sighting_counts["exploited"]}件')
    if sighting_counts.get("published-proof-of-concept"):
        reasons.append(f'PoC 公開の観測 {sighting_counts["published-proof-of-concept"]}件')
    if p is not None:
        reasons.append(f"EPSS {p:.3f}(上位 {100 * (1 - epss['percentile']):.1f}%)")
    if top is not None:
        reasons.append(f"CVSS {top}")
    if exploited:
        level = "最優先(悪用が確認されている)"
    elif (p is not None and p >= 0.1) or sighting_counts.get("published-proof-of-concept"):
        level = "高(悪用の可能性が高い、またはPoCがある)"
    elif top is not None and top >= 9:
        level = "中〜高(深刻度は高いが、悪用の兆候は見つからない)"
    elif top is not None and top >= 7:
        level = "中"
    else:
        level = "低〜中"
    return {"level": level, "reasons": reasons,
            "note": "目安。実際の優先度は、該当製品を使っているか・外部に公開しているかで変わる"}


@mcp.tool()
async def triage_cve(vuln_id: str) -> dict:
    """1件の脆弱性について、概要・CVSS・CWE・影響製品・EPSS・悪用の記録(KEV)・観測情報をまとめて返す。
    最初に使うツール。vuln_id は CVE-2021-44228 のような ID(GHSA なども可)。"""
    vid = check_id(vuln_id)
    rec_t = circl("GET", f"/vulnerability/{seg(vid, 'vuln_id')}", allow_404=True)
    epss_t = circl("GET", f"/epss/{seg(vid, 'vuln_id')}", allow_404=True)
    kev_t = circl("GET", "/kev/", {"vuln_id": vid, "per_page": 10, "exploited": "all"}, allow_404=True)
    sig_t = circl("GET", "/sighting/", {"vuln_id": vid, "per_page": 100}, allow_404=True)
    rec, epss_raw, kev_raw, sig_raw = await asyncio.gather(rec_t, epss_t, kev_t, sig_t, return_exceptions=True)
    if isinstance(rec, Exception):
        raise rec
    if rec is None:
        return {"id": vid, "found": False,
                "hint": "CIRCL に記録がありません。ID の綴りを確かめるか、search_vulnerabilities で検索してください"}
    s = summarize(rec)
    epss = None if isinstance(epss_raw, Exception) or epss_raw is None else _epss_item(epss_raw)
    kev_items = [] if isinstance(kev_raw, Exception) or kev_raw is None else _list_of(kev_raw)[0]
    kev_entries = [_kev_item(k) for k in kev_items if isinstance(k, dict)]
    sig_items, sig_meta = ([], {}) if isinstance(sig_raw, Exception) or sig_raw is None else _list_of(sig_raw)
    counts: dict[str, int] = {}
    latest: dict[str, str] = {}
    for it in sig_items:
        if isinstance(it, dict) and it.get("type"):
            counts[it["type"]] = counts.get(it["type"], 0) + 1
            d = it.get("creation_timestamp") or ""
            latest[it["type"]] = max(latest.get(it["type"], ""), d)
    sightings = {"counts_in_latest_100": counts, "latest_by_type": latest,
                 "total": sig_meta.get("count", len(sig_items))}
    out = {"found": True, **s,
           "epss": epss or "記録なし",
           "kev_records": kev_entries or "記録なし",
           "sightings": sightings if sig_items else "記録なし",
           "priority": _priority(s if isinstance(s, dict) else {}, epss, kev_entries, counts),
           "circl_url": f"https://vulnerability.circl.lu/vuln/{vid.lower()}"}
    errors = [n for n, v in (("epss", epss_raw), ("kev", kev_raw), ("sightings", sig_raw)) if isinstance(v, Exception)]
    if errors:
        out["partial_errors"] = errors
    return out


@mcp.tool()
async def get_vulnerability(vuln_id: str, full: bool = False, with_sightings: bool = False,
                            with_comments: bool = False, with_linked: bool = False) -> dict:
    """1件の脆弱性の詳細。CVE / GHSA / PYSEC / EUVD などのIDに対応。
    full=True で CIRCL の記録をそのまま(大きいことがある)返す。
    with_linked=True で、同じ脆弱性を指す別のID(GHSAなど)の記録も付ける。"""
    vid = check_id(vuln_id)
    params = {"with_sightings": str(with_sightings).lower(), "with_comments": str(with_comments).lower(),
              "with_linked": str(with_linked).lower()}
    rec = await circl("GET", f"/vulnerability/{seg(vid, 'vuln_id')}", params, allow_404=True)
    if rec is None:
        return {"id": vid, "found": False, "hint": "CIRCL に記録がありません"}
    if full:
        return {"found": True, "record": shrink(rec)}
    out = summarize(rec)
    out = out if isinstance(out, dict) else {"record": out}
    for extra in ("sightings", "comments", "linked", "bundles"):
        if isinstance(rec, dict) and rec.get(extra):
            val = rec[extra]
            out[extra] = [summarize(x) if extra == "linked" else shrink(x) for x in val[:20]] \
                if isinstance(val, list) else shrink(val)
    return {"found": True, **out, "circl_url": f"https://vulnerability.circl.lu/vuln/{vid.lower()}"}


@mcp.tool()
async def get_epss(vuln_ids: list[str]) -> dict:
    """EPSS(今後30日以内に悪用される確率の推定、0〜1)と、全体の中での位置(percentile)。最大30件。"""
    ids = [check_id(v) for v in vuln_ids][:30]
    if not ids:
        raise ValueError("vuln_ids が空です")
    res = await asyncio.gather(*[circl("GET", f"/epss/{seg(v, 'vuln_id')}", allow_404=True) for v in ids],
                               return_exceptions=True)
    out = {}
    for v, r in zip(ids, res):
        if isinstance(r, Exception):
            out[v] = {"error": str(r)}
        else:
            out[v] = (_epss_item(r) if r is not None else None) or "記録なし"
    return {"epss": out, "about": "EPSS は FIRST.org の推定値。0.1 以上なら悪用の可能性が高めとされる"}


@mcp.tool()
async def get_kev(vuln_id: Optional[str] = None, exploited: str = "true", status_reason: Optional[str] = None,
                  date_from: Optional[str] = None, date_to: Optional[str] = None,
                  page: int = 1, per_page: int = 20) -> dict:
    """悪用が確認された(または疑われる)脆弱性の記録(KEV)。CISA KEV やハニーポットの観測などから集めたもの。
    vuln_id を省くと最近の記録の一覧。exploited は true / false / all。
    status_reason は confirmed / suspected / disputed / historical / unknown / withdrawn。
    date_from, date_to は YYYY-MM-DD。"""
    if exploited not in ("true", "false", "all"):
        raise ValueError("exploited は true / false / all のどれか")
    params = {"vuln_id": check_id(vuln_id) if vuln_id else None, "exploited": exploited,
              "status_reason": status_reason, "date_from": date_or_none(date_from, "date_from"),
              "date_to": date_or_none(date_to, "date_to"), "page": clamp(page, 1, 1000),
              "per_page": clamp(per_page, 1, 100)}
    data = await circl("GET", "/kev/", params)
    items, meta = _list_of(data)
    return {"metadata": meta, "items": [_kev_item(i) for i in items if isinstance(i, dict)]}


@mcp.tool()
async def get_sightings(vuln_id: Optional[str] = None, type: Optional[str] = None,
                        date_from: Optional[str] = None, date_to: Optional[str] = None,
                        page: int = 1, per_page: int = 30) -> dict:
    """観測情報(sighting)。ある脆弱性が、悪用された・PoCが公開された・SNSなどで話題になった、といった記録。
    type は seen / exploited / published-proof-of-concept / not-exploited / confirmed / not-confirmed /
    patched / not-patched。date_from, date_to は YYYY-MM-DD。"""
    if type and type not in SIGHTING_TYPES:
        raise ValueError("type は " + " / ".join(SIGHTING_TYPES) + " のどれか")
    params = {"vuln_id": check_id(vuln_id) if vuln_id else None, "type": type,
              "date_from": date_or_none(date_from, "date_from"), "date_to": date_or_none(date_to, "date_to"),
              "page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 100)}
    data = await circl("GET", "/sighting/", params)
    items, meta = _list_of(data)
    return {"metadata": meta, "items": [_sighting_item(i) for i in items if isinstance(i, dict)]}


@mcp.tool()
async def search_vulnerabilities(query: str, sources: str = "cvelistv5", page: int = 1,
                                 per_page: int = 10) -> dict:
    """キーワードで脆弱性を全文検索する(説明文・製品名など)。例: "log4j", "fortinet ssl vpn"。
    sources はカンマ区切り(既定 cvelistv5。github, pysec, nvd, euvd なども指定できる)。"""
    q = (query or "").strip()
    if len(q) < 2 or len(q) > 200:
        raise ValueError("query は2〜200文字で指定してください")
    if not re.fullmatch(r"[a-z0-9_,]{1,200}", sources):
        raise ValueError("sources の形式が違います(例: cvelistv5,github)")
    data = await circl("GET", "/vulnerability/fulltext",
                       {"q": q, "sources": sources, "page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 50)})
    items, meta = _list_of(data)
    return {"metadata": meta, "items": [brief(i) for i in items]}


@mcp.tool()
async def search_by_product(vendor: str, product: str, since: Optional[str] = None,
                            page: int = 1, per_page: int = 20) -> dict:
    """ベンダー名と製品名で脆弱性を探す(新しいものから)。名前は CIRCL での表記(小文字が多い)に合わせる。
    分からないときは list_vendors / list_products で確かめる。since は YYYY-MM-DD(それ以降に更新されたもの)。"""
    params = {"page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 50),
              "since": date_or_none(since, "since")}
    data = await circl("GET", f"/vulnerability/search/{seg(vendor, 'vendor')}/{seg(product, 'product')}",
                       params, allow_404=True)
    if data is None:
        return {"items": [], "hint": "見つかりません。list_vendors / list_products で正しい名前を確かめてください"}
    merged: dict[str, dict] = {}
    results = (data.get("results") if isinstance(data, dict) else None) or {}
    if isinstance(results, dict):
        for source, rows in results.items():
            for row in rows if isinstance(rows, list) else []:
                rec = row[1] if isinstance(row, list) and len(row) == 2 else row
                b = brief(rec)
                key = str((b or {}).get("id") or (row[0] if isinstance(row, list) else "")).upper()
                if key in merged:
                    merged[key]["sources"].append(source)
                elif isinstance(b, dict):
                    merged[key] = {**b, "sources": [source]}
    else:
        for rec in _list_of(data)[0]:
            b = brief(rec)
            if isinstance(b, dict):
                merged[str(b.get("id"))] = b
    meta = {k: data.get(k) for k in ("total_count", "page", "page_size") if isinstance(data, dict) and k in data}
    return {"metadata": meta, "items": list(merged.values())}


@mcp.tool()
async def list_vendors(q: Optional[str] = None, page: int = 1, per_page: int = 50) -> dict:
    """ベンダー名の一覧(最近脆弱性が更新された順)。q で名前の一部を検索できる(例: "fortinet")。"""
    data = await circl("GET", "/browse/vendors",
                       {"q": q, "page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 200)})
    items, meta = _list_of(data)
    return {"metadata": meta, "items": shrink(items)}


@mcp.tool()
async def list_products(vendor: str, q: Optional[str] = None, page: int = 1, per_page: int = 50) -> dict:
    """ベンダーの製品名の一覧(最近脆弱性が更新された順)。q で名前の一部を検索できる。"""
    data = await circl("GET", f"/browse/vendors/{seg(vendor, 'vendor')}/products",
                       {"q": q, "page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 200)},
                       allow_404=True)
    if data is None:
        return {"items": [], "hint": "ベンダーが見つかりません。list_vendors で確かめてください"}
    items, meta = _list_of(data)
    return {"metadata": meta, "items": shrink(items)}


@mcp.tool()
async def recent_vulnerabilities(source: str = "cvelistv5", since: Optional[str] = None,
                                 product: Optional[str] = None, cwe: Optional[str] = None,
                                 date_sort: str = "updated", page: int = 1, per_page: int = 20) -> dict:
    """最近の脆弱性の一覧(新しい順)。date_sort は updated(更新順)か published(公開順)。
    source は cvelistv5(既定)、github、pysec、nvd、euvd など。
    since は YYYY-MM-DD。product で製品名、cwe で弱点の種類(例: CWE-79)を絞り込める。"""
    if date_sort not in ("updated", "published"):
        raise ValueError("date_sort は updated か published")
    if not re.fullmatch(r"[a-z0-9_]{1,40}", source):
        raise ValueError("source の形式が違います")
    params = {"source": source, "since": date_or_none(since, "since"), "product": product, "cwe": cwe,
              "date_sort": date_sort, "sort_order": "desc",
              "page": clamp(page, 1, 1000), "per_page": clamp(per_page, 1, 50)}
    data = await circl("GET", "/vulnerability/", params)
    items, meta = _list_of(data)
    return {"metadata": meta, "items": [brief(i) for i in items]}


@mcp.tool()
async def most_sighted(date_from: Optional[str] = None, date_to: Optional[str] = None,
                       sighting_type: Optional[str] = None, limit: int = 15) -> dict:
    """期間内によく観測された脆弱性のランキング(いま話題・攻撃されている脆弱性を知るのに使う)。
    date_from, date_to は YYYY-MM-DD(省くと CIRCL の既定の期間)。
    sighting_type は seen / exploited / published-proof-of-concept など。"""
    if sighting_type and sighting_type not in SIGHTING_TYPES:
        raise ValueError("sighting_type は " + " / ".join(SIGHTING_TYPES) + " のどれか")
    data = await circl("GET", "/stats/vulnerability/most_sighted",
                       {"date_from": date_or_none(date_from, "date_from"),
                        "date_to": date_or_none(date_to, "date_to"),
                        "sighting_type": sighting_type, "limit": clamp(limit, 1, 100), "output": "json"})
    return {"ranking": shrink(data)}


@mcp.tool()
async def get_cwe(cwe_id: str) -> dict:
    """CWE(弱点の種類)の説明。cwe_id は "CWE-79" か "79"。"""
    m = re.fullmatch(r"(?i)(?:cwe-)?(\d{1,5})", (cwe_id or "").strip())
    if not m:
        raise ValueError("cwe_id は CWE-79 か 79 の形で指定してください")
    data = await circl("GET", f"/cwe/{m.group(1)}", allow_404=True)
    if data is None:
        data = await circl("GET", f"/cwe/CWE-{m.group(1)}", allow_404=True)
    if data is None:
        return {"id": f"CWE-{m.group(1)}", "found": False}
    return {"found": True, "cwe": shrink(data),
            "url": f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"}


# ---------------------------------------------------------------- 起動

app = mcp.streamable_http_app()


async def health(_: Request):
    return JSONResponse({"mcp": "ok"})


async def root(_: Request):
    return PlainTextResponse("ok")


app.add_route("/healthz", health)
app.add_route("/", root)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info", access_log=False)
