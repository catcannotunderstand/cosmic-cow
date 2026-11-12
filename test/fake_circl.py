"""動作確認用の偽の CIRCL API。本物の応答の形(2026年11月時点)をまねて、決まった値を返す。"""
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

LOG4J = {
    "dataType": "CVE_RECORD", "dataVersion": "5.1",
    "cveMetadata": {"state": "PUBLISHED", "cveId": "CVE-2021-44228", "assignerShortName": "apache",
                    "datePublished": "2021-12-10T00:00:00.000Z", "dateUpdated": "2025-10-21T23:25:23.121Z"},
    "containers": {
        "cna": {
            "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
            "providerMetadata": {"shortName": "apache"},
            "descriptions": [{"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.15.0 ... " * 60}],
            "affected": [{"vendor": "Apache Software Foundation", "product": "Apache Log4j2",
                          "versions": [{"version": "2.0-beta9", "status": "affected", "lessThan": "2.3.1",
                                        "versionType": "custom"}]}],
            "references": [{"url": f"https://example.org/ref{i}", "tags": ["x_transferred"]} for i in range(30)],
            "metrics": [{"other": {"type": "unknown", "content": {"other": "critical"}}}],
            "problemTypes": [{"descriptions": [{"type": "CWE", "lang": "en", "cweId": "CWE-502",
                                                "description": "CWE-502 Deserialization of Untrusted Data"}]}],
        },
        "adp": [
            {"title": "CVE Program Container", "providerMetadata": {"shortName": "CVE"},
             "references": [{"url": "https://example.org/ref1"}]},
            {"title": "CISA ADP Vulnrichment", "providerMetadata": {"shortName": "CISA-ADP"},
             "metrics": [
                 {"cvssV3_1": {"version": "3.1", "baseScore": 10, "baseSeverity": "CRITICAL",
                               "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                 {"other": {"type": "ssvc", "content": {"role": "CISA Coordinator", "timestamp": "2025-02-04",
                                                        "options": [{"Exploitation": "active"},
                                                                    {"Automatable": "yes"},
                                                                    {"Technical Impact": "total"}]}}},
                 {"other": {"type": "kev", "content": {"dateAdded": "2021-12-10",
                                                       "reference": "https://www.cisa.gov/kev"}}},
             ]},
        ],
    },
}

GHSA = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j",
        "details": "details", "published": "2021-12-10T00:00:00Z", "modified": "2024-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]}],
        "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"}],
        "database_specific": {"cwe_ids": ["CWE-502"]}}

calls: list[str] = []


async def vuln(req: Request):
    vid = req.path_params["vid"]
    calls.append(f"vuln {vid} {dict(req.query_params)}")
    if vid.upper() == "CVE-2021-44228":
        rec = dict(LOG4J)
        if req.query_params.get("with_linked") == "true":
            rec["linked"] = [GHSA]
        return JSONResponse(rec)
    if vid == "GHSA-jfh8-c2jp-5v3q":
        return JSONResponse(GHSA)
    return JSONResponse({"message": "Not found"}, status_code=404)


async def epss(req: Request):
    vid = req.path_params["vid"]
    if vid.upper() != "CVE-2021-44228":
        return JSONResponse({"status": "OK", "data": []})
    return JSONResponse({"status": "OK", "status-code": 200, "total": 1,
                         "data": [{"cve": vid, "epss": "0.99999", "percentile": "1.0", "date": "2026-11-12"}]})


async def kev(req: Request):
    calls.append(f"kev {dict(req.query_params)}")
    return JSONResponse({"metadata": {"count": 1, "page": 1, "per_page": 10}, "data": [{
        "uuid": "u1", "vulnerability": {"vulnId": "CVE-2021-44228", "altId": []},
        "status": {"exploited": True, "status_reason": "confirmed", "status_updated_at": "2026-11-07T13:23:10+00:00"},
        "timestamps": {"first_seen_at": "2026-08-19T21:34:01+00:00", "last_seen_at": "2026-08-19T21:34:01+00:00"},
        "scope": {"notes": "long notes", "asset_exposure": ["internet-facing"]},
        "evidence": [{"type": "honeypot", "source": "SiberKapan", "signal": "in_the_wild_attempts",
                      "confidence": 0.8, "details": {"x": 1}}],
        "references": [{"id": "CVE-2021-44228", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}]}]})


async def sighting(req: Request):
    calls.append(f"sighting {dict(req.query_params)}")
    items = [{"uuid": f"s{i}", "creation_timestamp": f"2026-11-{10 + i % 3:02d}T00:00:00Z",
              "type": ["seen", "exploited", "published-proof-of-concept"][i % 3],
              "source": "https://mastodon.example/post", "content": "", "vulnerability": "CVE-2021-44228",
              "author": {"login": "automation"}} for i in range(9)]
    return JSONResponse({"metadata": {"count": 1992, "page": 1, "per_page": 100}, "data": items})


async def fulltext(req: Request):
    calls.append(f"fulltext {dict(req.query_params)}")
    rec = {"containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "Log4j 1.2 SocketServer deserialization"}],
        "affected": [{"vendor": "Apache Software Foundation", "product": "Log4j"}],
        "providerMetadata": {"shortName": "apache"},
        "x_legacyV4Record": {"CVE_data_meta": {"ID": "CVE-2019-17571"}},
        "x_gcve": [{"vulnId": "cve-2019-17571", "recordType": "advisory"}]}, "adp": []}}
    return JSONResponse({"metadata": {"count": 118, "page": 1, "per_page": 3}, "data": [rec]})


async def search(req: Request):
    calls.append(f"search {req.path_params['vendor']}/{req.path_params['product']} {dict(req.query_params)}")
    if req.path_params["vendor"] != "apache":
        return JSONResponse({"message": "Not found"}, status_code=404)
    return JSONResponse({"results": {"nvd": [["cve-2021-44228", LOG4J]], "cvelistv5": [["cve-2021-44228", LOG4J]]},
                         "total_count": 40, "page_size": 3, "page": 1})


async def vendors(req: Request):
    calls.append(f"vendors {dict(req.query_params)}")
    return JSONResponse({"metadata": {"count": 1}, "data": [{"vendor": "fortinet", "last_change": "2026-11-11"}]})


async def products(req: Request):
    calls.append(f"products {req.path_params['vendor']} {dict(req.query_params)}")
    return JSONResponse({"metadata": {"count": 1}, "data": [{"product": "fortios", "last_change": "2026-11-11"}]})


async def vuln_list(req: Request):
    calls.append(f"list {dict(req.query_params)}")
    return JSONResponse({"metadata": {"count": 1, "page": 1, "per_page": 20}, "data": [LOG4J]})


async def most_sighted(req: Request):
    calls.append(f"most_sighted {dict(req.query_params)}")
    return JSONResponse([{"vulnerability": "CVE-2021-44228", "count": 42}])


async def cwe(req: Request):
    if req.path_params["cid"] == "79":
        return JSONResponse({"id": "79", "name": "Improper Neutralization of Input During Web Page Generation"})
    return JSONResponse({"message": "Not found"}, status_code=404)


async def get_calls(_: Request):
    return JSONResponse(calls)


app = Starlette(routes=[
    Route("/api/vulnerability/", vuln_list),
    Route("/api/vulnerability/fulltext", fulltext),
    Route("/api/vulnerability/search/{vendor}/{product}", search),
    Route("/api/vulnerability/{vid}", vuln),
    Route("/api/epss/{vid}", epss),
    Route("/api/kev/", kev),
    Route("/api/sighting/", sighting),
    Route("/api/browse/vendors", vendors),
    Route("/api/browse/vendors/{vendor}/products", products),
    Route("/api/stats/vulnerability/most_sighted", most_sighted),
    Route("/api/cwe/{cid}", cwe),
    Route("/_calls", get_calls),
])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning")
