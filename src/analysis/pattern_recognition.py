"""
Ghost Identity Hunter - Pattern Recognition Module

PURPOSE:
--------
Identify and analyze patterns across multiple investigations to detect
recurring artifacts, behaviors, and threat indicators.

FUNCTIONALITY:
--------------
- Cross-investigation artifact correlation
- Pattern detection in findings
- Recurring threat indicator identification
- Historical pattern analysis
- Pattern similarity scoring

USAGE EXAMPLES:
--------------
# Analyze patterns across all investigations
from src.analysis.pattern_recognition import PatternRecognizer

recognizer = PatternRecognizer()
patterns = recognizer.analyze_all_investigations()

# Find similar investigations
similar = recognizer.find_similar_investigations(investigation_id)

# Detect recurring artifacts
recurring = recognizer.find_recurring_artifacts()

DEPENDENCIES:
-------------
- sqlite3: Database operations
- collections: Data structures for pattern analysis
- typing: Type hints
- logging: Logging

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
1.0 - Initial implementation
"""

import logging
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from src.storage.database import get_connection

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """Represents a detected pattern."""
    pattern_type: str  # artifact_type, platform, risk_indicator, etc.
    pattern_value: str
    frequency: int
    investigations: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass
class PatternAnalysis:
    """Results of pattern recognition analysis."""
    total_investigations: int
    common_artifacts: List[Pattern]
    common_platforms: List[Pattern]
    common_risks: List[Pattern]
    recurring_usernames: List[Pattern]
    recurring_emails: List[Pattern]
    similar_investigations: List[Tuple[str, str, float]]  # (id1, id2, similarity)


class PatternRecognizer:
    """Analyze patterns across investigations."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize pattern recognizer."""
        self.db_path = db_path
    
    def analyze_all_investigations(self) -> PatternAnalysis:
        """
        Analyze patterns across all investigations.
        
        Returns:
            PatternAnalysis with detected patterns
        """
        conn = get_connection(self.db_path)
        try:
            # Get all investigations
            investigations = self._get_all_investigations(conn)
            
            if not investigations:
                logger.warning("No investigations found for pattern analysis")
                return PatternAnalysis(
                    total_investigations=0,
                    common_artifacts=[],
                    common_platforms=[],
                    common_risks=[],
                    recurring_usernames=[],
                    recurring_emails=[],
                    similar_investigations=[]
                )
            
            logger.info(f"Analyzing patterns across {len(investigations)} investigations")
            
            # Analyze different pattern types
            common_artifacts = self._find_common_artifacts(conn, investigations)
            common_platforms = self._find_common_platforms(conn, investigations)
            common_risks = self._find_common_risks(conn, investigations)
            recurring_usernames = self._find_recurring_artifacts(conn, investigations, "username")
            recurring_emails = self._find_recurring_artifacts(conn, investigations, "email")
            similar_investigations = self._find_similar_investigations(conn, investigations)
            
            return PatternAnalysis(
                total_investigations=len(investigations),
                common_artifacts=common_artifacts,
                common_platforms=common_platforms,
                common_risks=common_risks,
                recurring_usernames=recurring_usernames,
                recurring_emails=recurring_emails,
                similar_investigations=similar_investigations
            )
            
        finally:
            conn.close()
    
    def _get_all_investigations(self, conn: sqlite3.Connection) -> List[Dict]:
        """Get all investigations from database."""
        cursor = conn.execute("""
            SELECT investigation_id, title, created_at
            FROM investigations
            ORDER BY created_at DESC
        """)
        
        return [
            {
                "id": row[0],
                "title": row[1],
                "created_at": row[2]
            }
            for row in cursor.fetchall()
        ]
    
    def _find_common_artifacts(self, conn: sqlite3.Connection, investigations: List[Dict]) -> List[Pattern]:
        """Find artifacts that appear across multiple investigations."""
        artifact_counter = defaultdict(lambda: {"count": 0, "investigations": []})
        
        for inv in investigations:
            cursor = conn.execute("""
                SELECT artifact_type, value
                FROM artifacts
                WHERE investigation_id = ?
            """, (inv["id"],))
            
            for artifact_type, value in cursor.fetchall():
                key = f"{artifact_type}:{value}"
                artifact_counter[key]["count"] += 1
                artifact_counter[key]["investigations"].append(inv["id"])
        
        # Filter to artifacts appearing in multiple investigations
        patterns = []
        for key, data in artifact_counter.items():
            if data["count"] > 1:
                artifact_type, value = key.split(":", 1)
                patterns.append(Pattern(
                    pattern_type=artifact_type,
                    pattern_value=value,
                    frequency=data["count"],
                    investigations=data["investigations"]
                ))
        
        # Sort by frequency
        patterns.sort(key=lambda p: p.frequency, reverse=True)
        return patterns[:20]  # Top 20
    
    def _find_common_platforms(self, conn: sqlite3.Connection, investigations: List[Dict]) -> List[Pattern]:
        """Find platforms that appear across multiple investigations."""
        platform_counter = defaultdict(lambda: {"count": 0, "investigations": []})
        
        for inv in investigations:
            cursor = conn.execute("""
                SELECT platform
                FROM platform_presences
                WHERE investigation_id = ?
            """, (inv["id"],))
            
            for (platform,) in cursor.fetchall():
                if platform:
                    platform_counter[platform]["count"] += 1
                    platform_counter[platform]["investigations"].append(inv["id"])
        
        patterns = []
        for platform, data in platform_counter.items():
            if data["count"] > 1:
                patterns.append(Pattern(
                    pattern_type="platform",
                    pattern_value=platform,
                    frequency=data["count"],
                    investigations=data["investigations"]
                ))
        
        patterns.sort(key=lambda p: p.frequency, reverse=True)
        return patterns[:20]
    
    def _find_common_risks(self, conn: sqlite3.Connection, investigations: List[Dict]) -> List[Pattern]:
        """Find risk indicators that appear across multiple investigations."""
        risk_counter = defaultdict(lambda: {"count": 0, "investigations": []})
        
        for inv in investigations:
            cursor = conn.execute("""
                SELECT DISTINCT risk_indicator
                FROM risk_indicators
                WHERE investigation_id = ?
            """, (inv["id"],))
            
            for (risk,) in cursor.fetchall():
                if risk:
                    risk_counter[risk]["count"] += 1
                    risk_counter[risk]["investigations"].append(inv["id"])
        
        patterns = []
        for risk, data in risk_counter.items():
            if data["count"] > 1:
                patterns.append(Pattern(
                    pattern_type="risk_indicator",
                    pattern_value=risk,
                    frequency=data["count"],
                    investigations=data["investigations"]
                ))
        
        patterns.sort(key=lambda p: p.frequency, reverse=True)
        return patterns[:20]
    
    def _find_recurring_artifacts(self, conn: sqlite3.Connection, investigations: List[Dict], artifact_type: str) -> List[Pattern]:
        """Find specific artifact types that recur across investigations."""
        artifact_counter = defaultdict(lambda: {"count": 0, "investigations": []})
        
        for inv in investigations:
            cursor = conn.execute("""
                SELECT value
                FROM artifacts
                WHERE investigation_id = ? AND artifact_type = ?
            """, (inv["id"], artifact_type))
            
            for (value,) in cursor.fetchall():
                artifact_counter[value]["count"] += 1
                artifact_counter[value]["investigations"].append(inv["id"])
        
        patterns = []
        for value, data in artifact_counter.items():
            if data["count"] > 1:
                patterns.append(Pattern(
                    pattern_type=artifact_type,
                    pattern_value=value,
                    frequency=data["count"],
                    investigations=data["investigations"]
                ))
        
        patterns.sort(key=lambda p: p.frequency, reverse=True)
        return patterns[:15]
    
    def _find_similar_investigations(self, conn: sqlite3.Connection, investigations: List[Dict]) -> List[Tuple[str, str, float]]:
        """Find investigations with similar artifact patterns."""
        similarities = []
        
        # Build artifact sets for each investigation
        inv_artifacts = {}
        for inv in investigations:
            cursor = conn.execute("""
                SELECT artifact_type, value
                FROM artifacts
                WHERE investigation_id = ?
            """, (inv["id"],))
            
            artifacts = set(f"{row[0]}:{row[1]}" for row in cursor.fetchall())
            inv_artifacts[inv["id"]] = artifacts
        
        # Calculate Jaccard similarity between all pairs
        for i, inv1 in enumerate(investigations):
            for inv2 in investigations[i+1:]:
                set1 = inv_artifacts[inv1["id"]]
                set2 = inv_artifacts[inv2["id"]]
                
                if not set1 or not set2:
                    continue
                
                intersection = len(set1 & set2)
                union = len(set1 | set2)
                similarity = intersection / union if union > 0 else 0
                
                if similarity > 0.1:  # Only include if >10% similarity
                    similarities.append((inv1["id"], inv2["id"], similarity))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[2], reverse=True)
        return similarities[:15]
    
    def find_recurring_artifacts(self, min_frequency: int = 2) -> List[Pattern]:
        """
        Find artifacts that recur across multiple investigations.
        
        Args:
            min_frequency: Minimum number of investigations to consider recurring
            
        Returns:
            List of recurring artifact patterns
        """
        analysis = self.analyze_all_investigations()
        
        # Filter by minimum frequency
        recurring = [
            pattern for pattern in analysis.common_artifacts
            if pattern.frequency >= min_frequency
        ]
        
        return recurring
    
    def get_investigation_patterns(self, investigation_id: str) -> Dict:
        """
        Get patterns specific to a single investigation.
        
        Args:
            investigation_id: ID of the investigation
            
        Returns:
            Dictionary with investigation-specific patterns
        """
        conn = get_connection(self.db_path)
        try:
            # Get investigation artifacts
            cursor = conn.execute("""
                SELECT artifact_type, value
                FROM artifacts
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            artifacts = list(cursor.fetchall())
            
            # Get platform presences
            cursor = conn.execute("""
                SELECT platform
                FROM platform_presences
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            platforms = [row[0] for row in cursor.fetchall() if row[0]]
            
            # Get risk indicators
            cursor = conn.execute("""
                SELECT DISTINCT risk_indicator
                FROM risk_indicators
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            risks = [row[0] for row in cursor.fetchall() if row[0]]
            
            return {
                "investigation_id": investigation_id,
                "artifact_count": len(artifacts),
                "artifacts_by_type": Counter([a[0] for a in artifacts]),
                "platforms": platforms,
                "risk_indicators": risks,
                "unique_artifacts": len(set(a[1] for a in artifacts))
            }
            
        finally:
            conn.close()
