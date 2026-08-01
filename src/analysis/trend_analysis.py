"""
Ghost Identity Hunter - Trend Analysis Module

PURPOSE:
--------
Analyze trends in OSINT investigation data against historical baselines
to identify emerging threats, changing patterns, and statistical anomalies.

FUNCTIONALITY:
--------------
- Historical baseline calculation
- Trend detection and analysis
- Statistical comparison against baselines
- Emerging threat identification
- Time-series analysis of investigation metrics

USAGE EXAMPLES:
--------------
# Analyze trends
from src.analysis.trend_analysis import TrendAnalyzer

analyzer = TrendAnalyzer()
trends = analyzer.analyze_trends()

# Compare against baseline
comparison = analyzer.compare_to_baseline(investigation_id)

DEPENDENCIES:
-------------
- sqlite3: Database operations
- statistics: Statistical calculations
- datetime: Date/time handling
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
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from src.storage.database import get_connection

logger = logging.getLogger(__name__)


@dataclass
class Trend:
    """Represents a detected trend."""
    metric: str
    baseline_value: float
    current_value: float
    change_percent: float
    direction: str  # "increasing", "decreasing", "stable"
    significance: str  # "high", "medium", "low"
    timeframe: str


@dataclass
class TrendAnalysis:
    """Results of trend analysis."""
    analysis_period: str
    baseline_period: str
    total_investigations: int
    trends: List[Trend]
    emerging_threats: List[str]
    statistical_summary: Dict[str, float]


class TrendAnalyzer:
    """Analyze trends in investigation data."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize trend analyzer."""
        self.db_path = db_path
    
    def analyze_trends(self, baseline_days: int = 30, analysis_days: int = 7) -> TrendAnalysis:
        """
        Analyze trends comparing recent period to historical baseline.
        
        Args:
            baseline_days: Number of days for baseline calculation
            analysis_days: Number of days for trend analysis
            
        Returns:
            TrendAnalysis with detected trends
        """
        conn = get_connection(self.db_path)
        try:
            # Calculate date ranges
            end_date = datetime.now()
            analysis_start = end_date - timedelta(days=analysis_days)
            baseline_start = end_date - timedelta(days=baseline_days)
            
            logger.info(f"Analyzing trends: baseline {baseline_days} days, analysis {analysis_days} days")
            
            # Get metrics for both periods
            baseline_metrics = self._calculate_period_metrics(conn, baseline_start, analysis_start)
            current_metrics = self._calculate_period_metrics(conn, analysis_start, end_date)
            
            # Calculate trends
            trends = self._calculate_trends(baseline_metrics, current_metrics)
            
            # Identify emerging threats
            emerging_threats = self._identify_emerging_threats(conn, analysis_start, end_date)
            
            # Statistical summary
            total_investigations = self._count_investigations(conn, baseline_start, end_date)
            
            return TrendAnalysis(
                analysis_period=f"{analysis_start.date()} to {end_date.date()}",
                baseline_period=f"{baseline_start.date()} to {analysis_start.date()}",
                total_investigations=total_investigations,
                trends=trends,
                emerging_threats=emerging_threats,
                statistical_summary=current_metrics
            )
            
        finally:
            conn.close()
    
    def _calculate_period_metrics(self, conn: sqlite3.Connection, start: datetime, end: datetime) -> Dict[str, float]:
        """Calculate metrics for a specific time period."""
        metrics = {}
        
        # Total investigations
        cursor = conn.execute("""
            SELECT COUNT(*)
            FROM investigations
            WHERE created_at BETWEEN ? AND ?
        """, (start.isoformat(), end.isoformat()))
        
        metrics["total_investigations"] = cursor.fetchone()[0]
        
        # Average artifacts per investigation
        cursor = conn.execute("""
            SELECT AVG(artifact_count)
            FROM (
                SELECT COUNT(*) as artifact_count
                FROM artifacts
                WHERE investigation_id IN (
                    SELECT investigation_id
                    FROM investigations
                    WHERE created_at BETWEEN ? AND ?
                )
                GROUP BY investigation_id
            )
        """, (start.isoformat(), end.isoformat()))
        
        result = cursor.fetchone()
        metrics["avg_artifacts_per_investigation"] = result[0] if result[0] else 0
        
        # Average risk indicators per investigation
        cursor = conn.execute("""
            SELECT AVG(risk_count)
            FROM (
                SELECT COUNT(*) as risk_count
                FROM risk_indicators
                WHERE investigation_id IN (
                    SELECT investigation_id
                    FROM investigations
                    WHERE created_at BETWEEN ? AND ?
                )
                GROUP BY investigation_id
            )
        """, (start.isoformat(), end.isoformat()))
        
        result = cursor.fetchone()
        metrics["avg_risk_indicators_per_investigation"] = result[0] if result[0] else 0
        
        # Platform diversity
        cursor = conn.execute("""
            SELECT COUNT(DISTINCT platform)
            FROM platform_presences
            WHERE investigation_id IN (
                SELECT investigation_id
                FROM investigations
                WHERE created_at BETWEEN ? AND ?
            )
        """, (start.isoformat(), end.isoformat()))
        
        metrics["platform_diversity"] = cursor.fetchone()[0]
        
        # High-risk investigation percentage
        cursor = conn.execute("""
            SELECT 
                COUNT(CASE WHEN risk_count >= 5 THEN 1 END) * 100.0 / COUNT(*)
            FROM (
                SELECT COUNT(*) as risk_count
                FROM risk_indicators
                WHERE investigation_id IN (
                    SELECT investigation_id
                    FROM investigations
                    WHERE created_at BETWEEN ? AND ?
                )
                GROUP BY investigation_id
            )
        """, (start.isoformat(), end.isoformat()))
        
        result = cursor.fetchone()
        metrics["high_risk_percentage"] = result[0] if result[0] else 0
        
        return metrics
    
    def _calculate_trends(self, baseline: Dict[str, float], current: Dict[str, float]) -> List[Trend]:
        """Calculate trends by comparing current to baseline."""
        trends = []
        
        for metric in baseline:
            if metric in current:
                baseline_val = baseline[metric]
                current_val = current[metric]
                
                if baseline_val == 0:
                    change_percent = 0
                else:
                    change_percent = ((current_val - baseline_val) / baseline_val) * 100
                
                # Determine direction
                if abs(change_percent) < 5:
                    direction = "stable"
                    significance = "low"
                elif change_percent > 0:
                    direction = "increasing"
                    significance = "high" if change_percent > 20 else "medium"
                else:
                    direction = "decreasing"
                    significance = "high" if change_percent < -20 else "medium"
                
                trends.append(Trend(
                    metric=metric,
                    baseline_value=baseline_val,
                    current_value=current_val,
                    change_percent=change_percent,
                    direction=direction,
                    significance=significance,
                    timeframe="recent"
                ))
        
        return trends
    
    def _identify_emerging_threats(self, conn: sqlite3.Connection, start: datetime, end: datetime) -> List[str]:
        """Identify emerging threat indicators."""
        threats = []
        
        # Get risk indicators from recent period
        cursor = conn.execute("""
            SELECT risk_indicator, COUNT(*) as count
            FROM risk_indicators
            WHERE investigation_id IN (
                SELECT investigation_id
                FROM investigations
                WHERE created_at BETWEEN ? AND ?
            )
            GROUP BY risk_indicator
            ORDER BY count DESC
            LIMIT 10
        """, (start.isoformat(), end.isoformat()))
        
        for (risk, count) in cursor.fetchall():
            if count >= 2:  # Appearing in multiple investigations
                threats.append(f"{risk} (frequency: {count})")
        
        return threats
    
    def _count_investigations(self, conn: sqlite3.Connection, start: datetime, end: datetime) -> int:
        """Count investigations in a time period."""
        cursor = conn.execute("""
            SELECT COUNT(*)
            FROM investigations
            WHERE created_at BETWEEN ? AND ?
        """, (start.isoformat(), end.isoformat()))
        
        return cursor.fetchone()[0]
    
    def compare_to_baseline(self, investigation_id: str) -> Dict:
        """
        Compare a specific investigation to historical baseline.
        
        Args:
            investigation_id: ID of the investigation to compare
            
        Returns:
            Dictionary with comparison results
        """
        conn = get_connection(self.db_path)
        try:
            # Get investigation details
            cursor = conn.execute("""
                SELECT created_at, title
                FROM investigations
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            inv = cursor.fetchone()
            if not inv:
                return {"error": "Investigation not found"}
            
            # Calculate baseline (30 days before investigation)
            inv_date = datetime.fromisoformat(inv[0])
            baseline_start = inv_date - timedelta(days=30)
            baseline_end = inv_date - timedelta(days=7)
            
            baseline_metrics = self._calculate_period_metrics(conn, baseline_start, baseline_end)
            
            # Get current investigation metrics
            current_metrics = {}
            
            cursor = conn.execute("""
                SELECT COUNT(*)
                FROM artifacts
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            current_metrics["total_artifacts"] = cursor.fetchone()[0]
            
            cursor = conn.execute("""
                SELECT COUNT(*)
                FROM risk_indicators
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            current_metrics["total_risk_indicators"] = cursor.fetchone()[0]
            
            cursor = conn.execute("""
                SELECT COUNT(DISTINCT platform)
                FROM platform_presences
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            current_metrics["platform_diversity"] = cursor.fetchone()[0]
            
            # Calculate comparison
            comparison = {
                "investigation_id": investigation_id,
                "investigation_title": inv[1],
                "baseline_period": f"{baseline_start.date()} to {baseline_end.date()}",
                "baseline": baseline_metrics,
                "current": current_metrics,
                "assessment": self._assess_investigation(baseline_metrics, current_metrics)
            }
            
            return comparison
            
        finally:
            conn.close()
    
    def _assess_investigation(self, baseline: Dict[str, float], current: Dict[str, float]) -> str:
        """Assess how current investigation compares to baseline."""
        if not baseline or not current:
            return "insufficient_data"
        
        # Simple assessment based on risk indicators
        baseline_risks = baseline.get("avg_risk_indicators_per_investigation", 0)
        current_risks = current.get("total_risk_indicators", 0)
        
        if current_risks > baseline_risks * 2:
            return "high_risk_above_baseline"
        elif current_risks > baseline_risks * 1.5:
            return "elevated_risk_above_baseline"
        elif current_risks < baseline_risks * 0.5:
            return "low_risk_below_baseline"
        else:
            return "normal"
