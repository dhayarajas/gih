"""
Ghost Identity Hunter - Statistical Analysis Module

PURPOSE:
--------
Provide statistical analysis capabilities for OSINT investigation data,
including confidence intervals, hypothesis testing, and statistical significance.

FUNCTIONALITY:
--------------
- Confidence interval calculation
- Statistical significance testing
- Sample size estimation
- Mean and variance analysis
- Probability distribution analysis

USAGE EXAMPLES:
--------------
# Calculate confidence intervals
from src.analysis.statistical_analysis import StatisticalAnalyzer

analyzer = StatisticalAnalyzer()
ci = analyzer.calculate_confidence_interval([1, 2, 3, 4, 5], confidence=0.95)

# Test statistical significance
result = analyzer.test_significance(sample1, sample2)

DEPENDENCIES:
-------------
- statistics: Statistical calculations
- math: Mathematical functions
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
import math
import statistics
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceInterval:
    """Represents a confidence interval."""
    lower_bound: float
    upper_bound: float
    mean: float
    std_error: float
    confidence_level: float
    sample_size: int
    
    def __str__(self) -> str:
        return f"{self.confidence_level*100:.0f}% CI: [{self.lower_bound:.2f}, {self.upper_bound:.2f}] (mean: {self.mean:.2f})"


@dataclass
class SignificanceTest:
    """Results of a significance test."""
    test_statistic: float
    p_value: float
    is_significant: bool
    alpha: float
    test_type: str  # "t_test", "z_test", etc.


class StatisticalAnalyzer:
    """Perform statistical analysis on investigation data."""
    
    def __init__(self):
        """Initialize statistical analyzer."""
        pass
    
    def calculate_confidence_interval(
        self, 
        data: List[float], 
        confidence: float = 0.95
    ) -> Optional[ConfidenceInterval]:
        """
        Calculate confidence interval for a sample.
        
        Args:
            data: List of numeric values
            confidence: Confidence level (0.0 to 1.0)
            
        Returns:
            ConfidenceInterval object or None if insufficient data
        """
        if len(data) < 2:
            logger.warning("Insufficient data for confidence interval (need at least 2 samples)")
            return None
        
        n = len(data)
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data)
        std_error = std_dev / math.sqrt(n)
        
        # Calculate t-score for given confidence level
        t_score = self._get_t_score(n - 1, confidence)
        
        # Calculate margin of error
        margin_of_error = t_score * std_error
        
        return ConfidenceInterval(
            lower_bound=mean - margin_of_error,
            upper_bound=mean + margin_of_error,
            mean=mean,
            std_error=std_error,
            confidence_level=confidence,
            sample_size=n
        )
    
    def _get_t_score(self, degrees_of_freedom: int, confidence: float) -> float:
        """
        Get t-score for given degrees of freedom and confidence level.
        
        Uses approximation for common confidence levels.
        """
        # Common t-scores for 95% confidence
        if confidence == 0.95:
            if degrees_of_freedom >= 30:
                return 1.96  # Approximate with z-score
            elif degrees_of_freedom >= 20:
                return 2.086
            elif degrees_of_freedom >= 10:
                return 2.228
            elif degrees_of_freedom >= 5:
                return 2.571
            else:
                return 3.182  # For small samples
        elif confidence == 0.99:
            if degrees_of_freedom >= 30:
                return 2.576
            elif degrees_of_freedom >= 20:
                return 2.845
            elif degrees_of_freedom >= 10:
                return 3.169
            elif degrees_of_freedom >= 5:
                return 4.032
            else:
                return 5.841
        elif confidence == 0.90:
            if degrees_of_freedom >= 30:
                return 1.645
            elif degrees_of_freedom >= 20:
                return 1.725
            elif degrees_of_freedom >= 10:
                return 1.812
            elif degrees_of_freedom >= 5:
                return 2.015
            else:
                return 2.920
        else:
            # Default to 95% approximation
            logger.warning(f"Using 95% confidence approximation for {confidence}")
            return self._get_t_score(degrees_of_freedom, 0.95)
    
    def test_significance(
        self, 
        sample1: List[float], 
        sample2: List[float],
        alpha: float = 0.05
    ) -> Optional[SignificanceTest]:
        """
        Perform two-sample t-test for significance.
        
        Args:
            sample1: First sample data
            sample2: Second sample data
            alpha: Significance level (default 0.05)
            
        Returns:
            SignificanceTest object or None if insufficient data
        """
        if len(sample1) < 2 or len(sample2) < 2:
            logger.warning("Insufficient data for significance test (need at least 2 samples each)")
            return None
        
        n1 = len(sample1)
        n2 = len(sample2)
        
        mean1 = statistics.mean(sample1)
        mean2 = statistics.mean(sample2)
        
        var1 = statistics.variance(sample1)
        var2 = statistics.variance(sample2)
        
        # Pooled variance
        pooled_var = ((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2)
        
        # Standard error
        std_error = math.sqrt(pooled_var * (1/n1 + 1/n2))
        
        # t-statistic
        t_statistic = (mean1 - mean2) / std_error
        
        # Degrees of freedom
        df = n1 + n2 - 2
        
        # Approximate p-value (simplified)
        p_value = self._approximate_p_value(abs(t_statistic), df)
        
        is_significant = p_value < alpha
        
        return SignificanceTest(
            test_statistic=t_statistic,
            p_value=p_value,
            is_significant=is_significant,
            alpha=alpha,
            test_type="t_test"
        )
    
    def _approximate_p_value(self, t_statistic: float, df: int) -> float:
        """
        Approximate p-value from t-statistic.
        
        This is a simplified approximation. For production use,
        consider using scipy.stats for exact calculations.
        """
        # Simplified approximation for common t-values
        if t_statistic > 3:
            return 0.001
        elif t_statistic > 2.5:
            return 0.01
        elif t_statistic > 2:
            return 0.05
        elif t_statistic > 1.5:
            return 0.1
        else:
            return 0.2
    
    def calculate_sample_size(
        self, 
        margin_of_error: float, 
        confidence: float = 0.95,
        population_std_dev: Optional[float] = None,
        population_size: Optional[int] = None
    ) -> int:
        """
        Calculate required sample size for desired margin of error.
        
        Args:
            margin_of_error: Desired margin of error
            confidence: Confidence level
            population_std_dev: Population standard deviation (if known)
            population_size: Total population size (for finite population correction)
            
        Returns:
            Required sample size
        """
        # Get z-score for confidence level
        z_score = self._get_z_score(confidence)
        
        # If population std dev not provided, use conservative estimate
        if population_std_dev is None:
            population_std_dev = 0.5  # Assumes binary proportion with max variance
        
        # Calculate sample size
        if population_size is None:
            # Infinite population
            sample_size = int((z_score * population_std_dev / margin_of_error) ** 2)
        else:
            # Finite population correction
            sample_size = int(
                (z_score ** 2 * population_std_dev ** 2 * population_size) /
                ((margin_of_error ** 2 * (population_size - 1)) + (z_score ** 2 * population_std_dev ** 2))
            )
        
        # Ensure minimum sample size
        return max(sample_size, 30)
    
    def _get_z_score(self, confidence: float) -> float:
        """Get z-score for given confidence level."""
        if confidence == 0.90:
            return 1.645
        elif confidence == 0.95:
            return 1.96
        elif confidence == 0.99:
            return 2.576
        else:
            logger.warning(f"Using 95% confidence approximation for {confidence}")
            return 1.96
    
    def analyze_distribution(self, data: List[float]) -> dict:
        """
        Analyze the distribution of data.
        
        Args:
            data: List of numeric values
            
        Returns:
            Dictionary with distribution statistics
        """
        if not data:
            return {"error": "No data provided"}
        
        n = len(data)
        
        return {
            "count": n,
            "mean": statistics.mean(data),
            "median": statistics.median(data),
            "mode": statistics.mode(data) if n > 0 else None,
            "std_dev": statistics.stdev(data) if n > 1 else 0,
            "variance": statistics.variance(data) if n > 1 else 0,
            "min": min(data),
            "max": max(data),
            "range": max(data) - min(data),
            "q1": statistics.quantiles(data)[0] if n >= 4 else None,
            "q3": statistics.quantiles(data)[2] if n >= 4 else None,
            "iqr": statistics.quantiles(data)[2] - statistics.quantiles(data)[0] if n >= 4 else None,
            "skewness": self._calculate_skewness(data) if n >= 3 else None,
            "kurtosis": self._calculate_kurtosis(data) if n >= 4 else None
        }
    
    def _calculate_skewness(self, data: List[float]) -> float:
        """Calculate skewness of data."""
        n = len(data)
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data)
        
        if std_dev == 0:
            return 0
        
        skew = sum((x - mean) ** 3 for x in data) / (n * std_dev ** 3)
        return skew
    
    def _calculate_kurtosis(self, data: List[float]) -> float:
        """Calculate kurtosis of data."""
        n = len(data)
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data)
        
        if std_dev == 0:
            return 0
        
        kurt = sum((x - mean) ** 4 for x in data) / (n * std_dev ** 4) - 3
        return kurt
    
    def compare_means(
        self, 
        sample1: List[float], 
        sample2: List[float],
        confidence: float = 0.95
    ) -> dict:
        """
        Compare means of two samples with confidence interval.
        
        Args:
            sample1: First sample data
            sample2: Second sample data
            confidence: Confidence level for interval
            
        Returns:
            Dictionary with comparison results
        """
        if len(sample1) < 2 or len(sample2) < 2:
            return {"error": "Insufficient data"}
        
        mean1 = statistics.mean(sample1)
        mean2 = statistics.mean(sample2)
        diff = mean1 - mean2
        
        # Calculate confidence interval for the difference
        n1 = len(sample1)
        n2 = len(sample2)
        
        var1 = statistics.variance(sample1)
        var2 = statistics.variance(sample2)
        
        # Standard error of the difference
        std_error = math.sqrt(var1/n1 + var2/n2)
        
        # Degrees of freedom (Welch-Satterthwaite approximation)
        df = int((var1/n1 + var2/n2) ** 2 / ((var1/n1)**2/(n1-1) + (var2/n2)**2/(n2-1)))
        
        t_score = self._get_t_score(df, confidence)
        margin_of_error = t_score * std_error
        
        return {
            "mean1": mean1,
            "mean2": mean2,
            "difference": diff,
            "ci_lower": diff - margin_of_error,
            "ci_upper": diff + margin_of_error,
            "confidence_level": confidence,
            "std_error": std_error,
            "degrees_of_freedom": df
        }
