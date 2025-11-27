"""
CVE Database Integration Service
Provides CVE matching and vulnerability database lookup
"""

import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import httpx

from models.database import get_db_connection
from logger import get_logger

logger = get_logger(__name__)

# NVD API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Optional but recommended for higher rate limits
CVE_CACHE_HOURS = int(os.getenv("CVE_CACHE_HOURS", "24"))


class CVEDatabase:
    """CVE database management and querying"""

    # Known Android/iOS CVE patterns by category
    CVE_PATTERNS = {
        "webview": {
            "keywords": ["webview", "webengine", "chromium", "webkit"],
            "android_cpe": "cpe:2.3:a:google:android",
            "ios_cpe": "cpe:2.3:o:apple:iphone_os"
        },
        "ssl_tls": {
            "keywords": ["ssl", "tls", "certificate", "x509", "https"],
            "android_cpe": "cpe:2.3:a:google:android",
            "ios_cpe": "cpe:2.3:o:apple:iphone_os"
        },
        "crypto": {
            "keywords": ["cryptography", "encryption", "cipher", "aes", "rsa", "md5", "sha1"],
            "android_cpe": "cpe:2.3:a:google:android"
        },
        "intent": {
            "keywords": ["intent", "deeplink", "url scheme", "broadcast"],
            "android_cpe": "cpe:2.3:a:google:android"
        },
        "permission": {
            "keywords": ["permission", "privilege", "sandbox"],
            "android_cpe": "cpe:2.3:a:google:android"
        },
        "sql_injection": {
            "keywords": ["sql injection", "sqlite", "database injection"],
            "android_cpe": "cpe:2.3:a:google:android"
        },
        "memory": {
            "keywords": ["buffer overflow", "memory corruption", "use after free", "heap"],
            "android_cpe": "cpe:2.3:a:google:android"
        }
    }

    # Known mobile library CVEs (static database)
    KNOWN_LIBRARY_CVES = {
        "okhttp": [
            {
                "cve_id": "CVE-2021-0341",
                "description": "OkHttp before 4.9.0 allows credential exposure via HttpURLConnection",
                "severity": "high",
                "affected_versions": "<4.9.0",
                "recommendation": "Update OkHttp to version 4.9.0 or later"
            },
            {
                "cve_id": "CVE-2023-0833",
                "description": "OkHttp vulnerable to improper certificate validation",
                "severity": "medium",
                "affected_versions": "<4.10.0",
                "recommendation": "Update OkHttp to version 4.10.0 or later"
            }
        ],
        "retrofit": [
            {
                "cve_id": "CVE-2018-1000850",
                "description": "Retrofit before 2.5.0 vulnerable to unsafe deserialization",
                "severity": "high",
                "affected_versions": "<2.5.0",
                "recommendation": "Update Retrofit to version 2.5.0 or later"
            }
        ],
        "gson": [
            {
                "cve_id": "CVE-2022-25647",
                "description": "Denial of service via crafted JSON in Gson",
                "severity": "high",
                "affected_versions": "<2.8.9",
                "recommendation": "Update Gson to version 2.8.9 or later"
            }
        ],
        "jackson": [
            {
                "cve_id": "CVE-2020-36518",
                "description": "Jackson Databind before 2.13.2.1 allows resource exhaustion",
                "severity": "high",
                "affected_versions": "<2.13.2.1",
                "recommendation": "Update Jackson to version 2.13.2.1 or later"
            }
        ],
        "log4j": [
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4j2 JNDI injection vulnerability (Log4Shell)",
                "severity": "critical",
                "affected_versions": "<2.17.0",
                "recommendation": "Update Log4j to version 2.17.0 or later immediately"
            }
        ],
        "commons-collections": [
            {
                "cve_id": "CVE-2015-7501",
                "description": "Apache Commons Collections deserialization vulnerability",
                "severity": "critical",
                "affected_versions": "<4.0",
                "recommendation": "Update to Commons Collections 4.0 or later"
            }
        ],
        "bouncy_castle": [
            {
                "cve_id": "CVE-2020-28052",
                "description": "Bouncy Castle BC Java before 1.67 vulnerable to OpenBSDBcrypt issue",
                "severity": "high",
                "affected_versions": "<1.67",
                "recommendation": "Update Bouncy Castle to version 1.67 or later"
            }
        ],
        "fresco": [
            {
                "cve_id": "CVE-2019-16370",
                "description": "Facebook Fresco image library allows data exfiltration",
                "severity": "medium",
                "affected_versions": "<2.0.0",
                "recommendation": "Update Fresco to latest version"
            }
        ],
        "alamofire": [
            {
                "cve_id": "CVE-2020-11988",
                "description": "Alamofire vulnerable to certificate validation bypass",
                "severity": "high",
                "affected_versions": "<5.4.0",
                "recommendation": "Update Alamofire to version 5.4.0 or later"
            }
        ]
    }

    @staticmethod
    async def init_table():
        """Initialize CVE cache table"""
        async with get_db_connection() as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    affected_products TEXT,
                    references_json TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_cache(cve_id)
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS report_cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    match_type TEXT,
                    match_confidence TEXT,
                    finding_id INTEGER,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
                )
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_report_cves_report ON report_cves(report_id)
            """)

            await db.commit()

    @staticmethod
    async def search_nvd(keyword: str, results_per_page: int = 20) -> List[Dict]:
        """Search NVD for CVEs matching keyword"""
        try:
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": results_per_page
                }

                response = await client.get(NVD_API_BASE, params=params, headers=headers)
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                results = []
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Get CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    cvss_vector = None
                    severity = "unknown"

                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        severity = cvss_data.get("baseSeverity", "").lower()
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")

                    # Get description
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    results.append({
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "published": cve.get("published"),
                        "lastModified": cve.get("lastModified")
                    })

                return results

        except httpx.HTTPError as e:
            logger.error(f"NVD API request failed: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"CVE search failed: {str(e)}")
            return []

    @staticmethod
    async def match_findings_to_cves(
        findings: List[Dict],
        platform: str = "android"
    ) -> List[Dict]:
        """Match findings to potential CVEs"""
        matches = []

        for finding in findings:
            finding_type = finding.get("type", "").lower()
            title = finding.get("title", "").lower()
            description = finding.get("description", "").lower()
            code_snippet = finding.get("code_snippet", "").lower() if finding.get("code_snippet") else ""

            # Check for known library CVEs
            for library, cves in CVEDatabase.KNOWN_LIBRARY_CVES.items():
                if library in title or library in description or library in code_snippet:
                    for cve in cves:
                        matches.append({
                            "finding_id": finding.get("id"),
                            "finding_title": finding.get("title"),
                            "cve_id": cve["cve_id"],
                            "cve_description": cve["description"],
                            "severity": cve["severity"],
                            "match_type": "library",
                            "match_confidence": "high",
                            "affected_versions": cve.get("affected_versions"),
                            "recommendation": cve.get("recommendation")
                        })

            # Check pattern-based matches
            for category, patterns in CVEDatabase.CVE_PATTERNS.items():
                keywords = patterns.get("keywords", [])
                for keyword in keywords:
                    if keyword in finding_type or keyword in title or keyword in description:
                        matches.append({
                            "finding_id": finding.get("id"),
                            "finding_title": finding.get("title"),
                            "cve_category": category,
                            "match_type": "pattern",
                            "match_confidence": "medium",
                            "search_keywords": keywords,
                            "note": f"Finding may be related to {category} vulnerabilities. Consider searching NVD for '{keyword}' CVEs."
                        })
                        break

        # Deduplicate
        seen = set()
        unique_matches = []
        for match in matches:
            key = (match.get("finding_id"), match.get("cve_id") or match.get("cve_category"))
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)

        return unique_matches

    @staticmethod
    async def get_cve_details(cve_id: str) -> Optional[Dict]:
        """Get detailed CVE information"""
        # Check cache first
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM cve_cache WHERE cve_id = ?",
                (cve_id,)
            )
            cached = await cursor.fetchone()

            if cached:
                cached_at = datetime.fromisoformat(cached["cached_at"])
                if datetime.utcnow() - cached_at < timedelta(hours=CVE_CACHE_HOURS):
                    return dict(cached)

        # Fetch from NVD
        try:
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {"cveId": cve_id}
                response = await client.get(NVD_API_BASE, params=params, headers=headers)
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    return None

                cve = vulnerabilities[0].get("cve", {})

                # Parse CVE data
                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                severity = "unknown"

                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = cvss_data.get("baseSeverity", "").lower()

                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                references = cve.get("references", [])
                affected = cve.get("configurations", [])

                cve_data = {
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "affected_products": json.dumps(affected),
                    "references_json": json.dumps(references),
                    "published_date": cve.get("published"),
                    "last_modified": cve.get("lastModified")
                }

                # Cache the result
                async with get_db_connection() as db:
                    await db.execute("""
                        INSERT OR REPLACE INTO cve_cache
                        (cve_id, description, severity, cvss_score, cvss_vector,
                         affected_products, references_json, published_date, last_modified, cached_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        cve_data["cve_id"],
                        cve_data["description"],
                        cve_data["severity"],
                        cve_data["cvss_score"],
                        cve_data["cvss_vector"],
                        cve_data["affected_products"],
                        cve_data["references_json"],
                        cve_data["published_date"],
                        cve_data["last_modified"]
                    ))
                    await db.commit()

                return cve_data

        except Exception as e:
            logger.error(f"Failed to fetch CVE details: {str(e)}")
            return None

    @staticmethod
    async def save_report_cves(report_id: int, cve_matches: List[Dict]):
        """Save CVE matches for a report"""
        async with get_db_connection() as db:
            # Clear existing matches
            await db.execute("DELETE FROM report_cves WHERE report_id = ?", (report_id,))

            # Insert new matches
            for match in cve_matches:
                if match.get("cve_id"):
                    await db.execute("""
                        INSERT INTO report_cves (report_id, cve_id, match_type, match_confidence, finding_id, notes)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        report_id,
                        match["cve_id"],
                        match.get("match_type", "unknown"),
                        match.get("match_confidence", "low"),
                        match.get("finding_id"),
                        match.get("recommendation") or match.get("note")
                    ))

            await db.commit()

    @staticmethod
    async def get_report_cves(report_id: int) -> List[Dict]:
        """Get CVE matches for a report"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                SELECT rc.*, cc.description, cc.severity, cc.cvss_score
                FROM report_cves rc
                LEFT JOIN cve_cache cc ON rc.cve_id = cc.cve_id
                WHERE rc.report_id = ?
                ORDER BY cc.cvss_score DESC NULLS LAST
            """, (report_id,))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
