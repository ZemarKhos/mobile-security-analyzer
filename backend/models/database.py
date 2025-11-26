"""
Database Models and Connection Management
SQLite with SQLAlchemy async support
"""

import os
import json
import aiosqlite
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

# Database path
DATABASE_PATH = os.getenv("DATABASE_PATH", "/app/data/mobile_analyzer.db")


async def init_database():
    """Initialize the database with required tables"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Reports table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version_name TEXT,
                version_code INTEGER,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                md5_hash TEXT NOT NULL,
                sha1_hash TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                platform TEXT DEFAULT 'android',
                status TEXT DEFAULT 'pending',
                risk_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                
                -- Analysis results stored as JSON
                manifest_analysis TEXT,
                certificate_analysis TEXT,
                binary_analysis TEXT,
                code_analysis TEXT,
                findings_summary TEXT
            )
        """)
        
        # Add platform column if not exists (for migration)
        try:
            await db.execute("ALTER TABLE reports ADD COLUMN platform TEXT DEFAULT 'android'")
        except:
            pass  # Column already exists
        
        # Findings table - for large finding sets
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                line_number INTEGER,
                code_snippet TEXT,
                recommendation TEXT,
                cwe_id TEXT,
                owasp_category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for performance
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_report_id ON findings(report_id)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)
        """)
        
        # Security Rules table - for custom root/SSL detection patterns
        await db.execute("""
            CREATE TABLE IF NOT EXISTS security_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                category TEXT NOT NULL,
                pattern TEXT NOT NULL,
                is_regex INTEGER DEFAULT 1,
                case_sensitive INTEGER DEFAULT 0,
                description TEXT,
                severity TEXT DEFAULT 'info',
                bypass_difficulty TEXT DEFAULT 'medium',
                platform TEXT DEFAULT 'android',
                is_enabled INTEGER DEFAULT 1,
                is_builtin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_type ON security_rules(type)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_enabled ON security_rules(is_enabled)
        """)
        
        await db.commit()
        print("Database initialized successfully")


@asynccontextmanager
async def get_db_connection():
    """Get database connection as async context manager"""
    db = await aiosqlite.connect(DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


class ReportRepository:
    """Repository for report operations"""
    
    @staticmethod
    async def create(report_data: Dict[str, Any]) -> int:
        """Create a new report and return its ID"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                INSERT INTO reports (
                    app_name, package_name, version_name, version_code,
                    file_name, file_size, md5_hash, sha1_hash, sha256_hash,
                    platform, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_data["app_name"],
                report_data["package_name"],
                report_data.get("version_name"),
                report_data.get("version_code"),
                report_data["file_name"],
                report_data["file_size"],
                report_data["md5_hash"],
                report_data["sha1_hash"],
                report_data["sha256_hash"],
                report_data.get("platform", "android"),
                "pending"
            ))
            await db.commit()
            return cursor.lastrowid
    
    @staticmethod
    async def get_by_id(report_id: int) -> Optional[Dict[str, Any]]:
        """Get report by ID"""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM reports WHERE id = ?", 
                (report_id,)
            )
            row = await cursor.fetchone()
            if row:
                report = dict(row)
                # Parse JSON fields
                for field in ["manifest_analysis", "certificate_analysis", 
                              "binary_analysis", "code_analysis", "findings_summary"]:
                    if report.get(field):
                        try:
                            report[field] = json.loads(report[field])
                        except json.JSONDecodeError:
                            report[field] = None
                return report
            return None
    
    @staticmethod
    async def get_all(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get all reports with pagination"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                SELECT id, app_name, package_name, version_name, file_name,
                       platform, status, risk_score, created_at, completed_at, findings_summary
                FROM reports
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = await cursor.fetchall()
            reports = []
            for row in rows:
                report = dict(row)
                if report.get("findings_summary"):
                    try:
                        report["findings_summary"] = json.loads(report["findings_summary"])
                    except json.JSONDecodeError:
                        report["findings_summary"] = {}
                reports.append(report)
            return reports
    
    @staticmethod
    async def update_status(report_id: int, status: str, 
                           completed_at: Optional[datetime] = None):
        """Update report status"""
        async with get_db_connection() as db:
            if completed_at:
                await db.execute("""
                    UPDATE reports SET status = ?, completed_at = ? WHERE id = ?
                """, (status, completed_at.isoformat(), report_id))
            else:
                await db.execute("""
                    UPDATE reports SET status = ? WHERE id = ?
                """, (status, report_id))
            await db.commit()
    
    @staticmethod
    async def update_analysis(report_id: int, analysis_type: str, 
                             analysis_data: Dict[str, Any]):
        """Update specific analysis result"""
        async with get_db_connection() as db:
            await db.execute(f"""
                UPDATE reports SET {analysis_type} = ? WHERE id = ?
            """, (json.dumps(analysis_data), report_id))
            await db.commit()
    
    @staticmethod
    async def update_findings_summary(report_id: int, summary: Dict[str, Any]):
        """Update findings summary"""
        async with get_db_connection() as db:
            await db.execute("""
                UPDATE reports SET findings_summary = ? WHERE id = ?
            """, (json.dumps(summary), report_id))
            await db.commit()
    
    @staticmethod
    async def update_risk_score(report_id: int, risk_score: int):
        """Update risk score"""
        async with get_db_connection() as db:
            await db.execute("""
                UPDATE reports SET risk_score = ? WHERE id = ?
            """, (risk_score, report_id))
            await db.commit()
    
    @staticmethod
    async def delete(report_id: int):
        """Delete a report and its findings"""
        async with get_db_connection() as db:
            await db.execute("DELETE FROM findings WHERE report_id = ?", (report_id,))
            await db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            await db.commit()


class FindingRepository:
    """Repository for finding operations"""
    
    @staticmethod
    async def bulk_insert(report_id: int, findings: List[Dict[str, Any]]):
        """Insert multiple findings at once"""
        async with get_db_connection() as db:
            await db.executemany("""
                INSERT INTO findings (
                    report_id, type, severity, title, description,
                    file_path, line_number, code_snippet, recommendation,
                    cwe_id, owasp_category
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    report_id,
                    f.get("type", "unknown"),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("file_path"),
                    f.get("line_number"),
                    f.get("code_snippet"),
                    f.get("recommendation"),
                    f.get("cwe_id"),
                    f.get("owasp_category")
                )
                for f in findings
            ])
            await db.commit()
    
    @staticmethod
    async def get_paginated(report_id: int, page: int = 1, 
                           page_size: int = 100,
                           severity: Optional[str] = None,
                           finding_type: Optional[str] = None) -> Dict[str, Any]:
        """Get paginated findings for a report"""
        async with get_db_connection() as db:
            # Build query conditions
            conditions = ["report_id = ?"]
            params = [report_id]
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            if finding_type:
                conditions.append("type = ?")
                params.append(finding_type)
            
            where_clause = " AND ".join(conditions)
            
            # Get total count
            cursor = await db.execute(
                f"SELECT COUNT(*) as count FROM findings WHERE {where_clause}",
                params
            )
            row = await cursor.fetchone()
            total = row["count"]
            
            # Calculate pagination
            total_pages = (total + page_size - 1) // page_size
            offset = (page - 1) * page_size
            
            # Get findings
            cursor = await db.execute(f"""
                SELECT * FROM findings 
                WHERE {where_clause}
                ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    id
                LIMIT ? OFFSET ?
            """, params + [page_size, offset])
            
            rows = await cursor.fetchall()
            findings = [dict(row) for row in rows]
            
            return {
                "findings": findings,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages
            }
    
    @staticmethod
    async def get_summary(report_id: int) -> Dict[str, Any]:
        """Get findings summary for a report"""
        async with get_db_connection() as db:
            # Count by severity
            cursor = await db.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE report_id = ?
                GROUP BY severity
            """, (report_id,))
            severity_rows = await cursor.fetchall()
            
            # Count by type
            cursor = await db.execute("""
                SELECT type, COUNT(*) as count
                FROM findings
                WHERE report_id = ?
                GROUP BY type
            """, (report_id,))
            type_rows = await cursor.fetchall()
            
            summary = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "by_type": {}
            }
            
            for row in severity_rows:
                severity = row["severity"]
                count = row["count"]
                summary["total"] += count
                if severity in summary:
                    summary[severity] = count
            
            for row in type_rows:
                summary["by_type"][row["type"]] = row["count"]
            
            return summary
    
    @staticmethod
    async def delete_by_report(report_id: int):
        """Delete all findings for a report"""
        async with get_db_connection() as db:
            await db.execute(
                "DELETE FROM findings WHERE report_id = ?", 
                (report_id,)
            )
            await db.commit()


class SecurityRulesRepository:
    """Repository for security rule operations"""
    
    @staticmethod
    async def get_all(
        rule_type: Optional[str] = None,
        platform: Optional[str] = None,
        enabled_only: bool = True
    ) -> List[Dict[str, Any]]:
        """Get all security rules with optional filters"""
        async with get_db_connection() as db:
            conditions = []
            params = []
            
            if enabled_only:
                conditions.append("is_enabled = 1")
            
            if rule_type:
                conditions.append("type = ?")
                params.append(rule_type)
            
            if platform:
                conditions.append("(platform = ? OR platform = 'all')")
                params.append(platform)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            cursor = await db.execute(f"""
                SELECT * FROM security_rules 
                WHERE {where_clause}
                ORDER BY type, category, name
            """, params)
            
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    @staticmethod
    async def get_by_id(rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a single rule by ID"""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM security_rules WHERE id = ?",
                (rule_id,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    @staticmethod
    async def create(rule_data: Dict[str, Any]) -> int:
        """Create a new security rule"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                INSERT INTO security_rules (
                    name, type, category, pattern, is_regex, case_sensitive,
                    description, severity, bypass_difficulty, platform, 
                    is_enabled, is_builtin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_data["name"],
                rule_data["type"],
                rule_data["category"],
                rule_data["pattern"],
                rule_data.get("is_regex", True),
                rule_data.get("case_sensitive", False),
                rule_data.get("description", ""),
                rule_data.get("severity", "info"),
                rule_data.get("bypass_difficulty", "medium"),
                rule_data.get("platform", "android"),
                rule_data.get("is_enabled", True),
                rule_data.get("is_builtin", False)
            ))
            await db.commit()
            return cursor.lastrowid
    
    @staticmethod
    async def update(rule_id: int, rule_data: Dict[str, Any]) -> bool:
        """Update an existing security rule"""
        async with get_db_connection() as db:
            # Build SET clause dynamically
            allowed_fields = [
                "name", "type", "category", "pattern", "is_regex", 
                "case_sensitive", "description", "severity", 
                "bypass_difficulty", "platform", "is_enabled"
            ]
            
            set_parts = []
            params = []
            
            for field in allowed_fields:
                if field in rule_data:
                    set_parts.append(f"{field} = ?")
                    params.append(rule_data[field])
            
            if not set_parts:
                return False
            
            set_parts.append("updated_at = CURRENT_TIMESTAMP")
            params.append(rule_id)
            
            await db.execute(f"""
                UPDATE security_rules 
                SET {', '.join(set_parts)}
                WHERE id = ?
            """, params)
            await db.commit()
            return True
    
    @staticmethod
    async def delete(rule_id: int) -> bool:
        """Delete a security rule (only non-builtin rules)"""
        async with get_db_connection() as db:
            # Check if it's a builtin rule
            cursor = await db.execute(
                "SELECT is_builtin FROM security_rules WHERE id = ?",
                (rule_id,)
            )
            row = await cursor.fetchone()
            
            if not row:
                return False
            
            if row["is_builtin"]:
                # For builtin rules, just disable instead of delete
                await db.execute(
                    "UPDATE security_rules SET is_enabled = 0 WHERE id = ?",
                    (rule_id,)
                )
            else:
                await db.execute(
                    "DELETE FROM security_rules WHERE id = ?",
                    (rule_id,)
                )
            
            await db.commit()
            return True
    
    @staticmethod
    async def toggle_enabled(rule_id: int) -> Optional[bool]:
        """Toggle rule enabled status, returns new status"""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT is_enabled FROM security_rules WHERE id = ?",
                (rule_id,)
            )
            row = await cursor.fetchone()
            
            if not row:
                return None
            
            new_status = not row["is_enabled"]
            await db.execute(
                "UPDATE security_rules SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_status, rule_id)
            )
            await db.commit()
            return new_status
    
    @staticmethod
    async def bulk_insert(rules: List[Dict[str, Any]]) -> int:
        """Insert multiple rules at once (for seeding)"""
        async with get_db_connection() as db:
            count = 0
            for rule in rules:
                try:
                    await db.execute("""
                        INSERT OR IGNORE INTO security_rules (
                            name, type, category, pattern, is_regex, case_sensitive,
                            description, severity, bypass_difficulty, platform, 
                            is_enabled, is_builtin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        rule["name"],
                        rule["type"],
                        rule["category"],
                        rule["pattern"],
                        rule.get("is_regex", True),
                        rule.get("case_sensitive", False),
                        rule.get("description", ""),
                        rule.get("severity", "info"),
                        rule.get("bypass_difficulty", "medium"),
                        rule.get("platform", "android"),
                        rule.get("is_enabled", True),
                        rule.get("is_builtin", True)
                    ))
                    count += 1
                except Exception as e:
                    print(f"Failed to insert rule {rule.get('name')}: {e}")
            
            await db.commit()
            return count
    
    @staticmethod
    async def get_count() -> int:
        """Get total count of rules"""
        async with get_db_connection() as db:
            cursor = await db.execute("SELECT COUNT(*) as count FROM security_rules")
            row = await cursor.fetchone()
            return row["count"] if row else 0