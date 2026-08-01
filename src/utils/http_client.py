"""
Ghost Identity Hunter - HTTP Client with Connection Pooling

PURPOSE:
--------
Provides a centralized HTTP client with connection pooling, compression,
and optimized settings for high-performance OSINT operations.

FUNCTIONALITY:
--------------
- Reusable connection pool to reduce TCP handshake overhead
- HTTP compression (gzip, brotli) enabled by default
- Configurable timeouts and retry logic (excluding rate limits)
- User-Agent rotation for reduced fingerprinting
- Session reuse across requests
- Rate limiting to prevent API throttling

USAGE EXAMPLES:
--------------
# Get global HTTP client session
from src.utils.http_client import get_http_session

session = get_http_session()
response = session.get("https://api.example.com")

DEPENDENCIES:
-------------
- requests: HTTP client library
- requests.adapters: Connection pooling configuration

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
1.2 - All configurations moved to config.yaml
"""

import logging
import random
import time
from threading import Lock
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.config.loader import get_config

logger = logging.getLogger(__name__)

# Global session instance
_http_session: Optional[requests.Session] = None
_rate_limit_lock = Lock()
_last_request_time = 0
_response_times = []  # Track recent response times for adaptive timeout


def _get_http_config() -> dict:
    """Get HTTP client configuration from config.yaml."""
    config = get_config()
    return config.get("http_client", {
        "timeout": 10,
        "min_timeout": 5,
        "max_timeout": 30,
        "adaptive_timeout": True,
        "connection_pool_size": 100,
        "connect_timeout": 5,
        "read_timeout": 15,
        "retry_total": 2,
        "retry_backoff_factor": 1.0,
        "retry_status_codes": [500, 502, 503, 504],
        "min_request_interval": 0.1,
        "user_agents": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]
    })


def _get_adaptive_timeout() -> float:
    """Calculate adaptive timeout based on recent response times."""
    global _response_times
    
    config = _get_http_config()
    if not config.get("adaptive_timeout", True):
        return config.get("timeout", 10)
    
    if not _response_times:
        return config.get("timeout", 10)
    
    # Calculate average of recent response times
    avg_response_time = sum(_response_times) / len(_response_times)
    
    # Adaptive timeout: 2x average response time, bounded by min/max
    adaptive_timeout = avg_response_time * 2
    adaptive_timeout = max(config.get("min_timeout", 5), adaptive_timeout)
    adaptive_timeout = min(config.get("max_timeout", 30), adaptive_timeout)
    
    logger.debug("Adaptive timeout: %.2fs (based on avg response time: %.2fs)", 
                 adaptive_timeout, avg_response_time)
    
    return adaptive_timeout


def _record_response_time(response_time: float):
    """Record response time for adaptive timeout calculation."""
    global _response_times
    
    # Keep only last 10 response times
    _response_times.append(response_time)
    if len(_response_times) > 10:
        _response_times.pop(0)


def _create_optimized_session() -> requests.Session:
    """
    Create an optimized HTTP session with connection pooling and retry logic.
    
    Returns:
        Configured requests.Session object
    """
    config = _get_http_config()
    session = requests.Session()
    
    # Configure retry strategy - DO NOT retry on rate limits (429)
    # Only retry on actual server errors
    retry_strategy = Retry(
        total=config["retry_total"],
        backoff_factor=config["retry_backoff_factor"],
        status_forcelist=config["retry_status_codes"],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        raise_on_status=False  # Don't raise exception on retries
    )
    
    # Configure connection pool
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=config["connection_pool_size"],
        pool_maxsize=config["connection_pool_size"],
        pool_block=False
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default headers with compression and random user agent
    user_agents = config["user_agents"]
    session.headers.update({
        "Accept": "application/json, text/html, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": random.choice(user_agents),
        "Connection": "keep-alive",
    })
    
    # Set default timeouts
    session.timeout = (config["connect_timeout"], config["read_timeout"])
    
    return session


def _apply_rate_limit():
    """Apply rate limiting before making a request."""
    global _last_request_time
    
    config = _get_http_config()
    min_interval = config["min_request_interval"]
    
    with _rate_limit_lock:
        current_time = time.time()
        time_since_last = current_time - _last_request_time
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            logger.debug("Rate limiting: sleeping for %.2f seconds", sleep_time)
            time.sleep(sleep_time)
        
        _last_request_time = time.time()


def get_http_session() -> requests.Session:
    """
    Get or create a global HTTP session with connection pooling.
    
    Returns:
        Configured requests.Session object with connection pooling
    """
    global _http_session
    
    if _http_session is None:
        _http_session = _create_optimized_session()
        logger.debug("Created new HTTP session with connection pooling")
    
    return _http_session


def get_adaptive_timeout() -> float:
    """
    Get the current adaptive timeout value.
    
    Returns:
        Timeout in seconds based on recent response times
    """
    return _get_adaptive_timeout()


def make_request_with_timing(method: str, url: str, **kwargs) -> requests.Response:
    """
    Make an HTTP request with timing for adaptive timeout calculation.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        **kwargs: Additional arguments for requests
        
    Returns:
        requests.Response object
    """
    _apply_rate_limit()
    
    # Use adaptive timeout if not specified
    if 'timeout' not in kwargs:
        kwargs['timeout'] = _get_adaptive_timeout()
    
    session = get_http_session()
    start_time = time.time()
    
    try:
        response = session.request(method, url, **kwargs)
        response_time = time.time() - start_time
        _record_response_time(response_time)
        
        logger.debug("Request to %s completed in %.2fs", url, response_time)
        return response
        
    except requests.Timeout as e:
        response_time = time.time() - start_time
        _record_response_time(response_time)
        logger.warning("Request to %s timed out after %.2fs", url, response_time)
        raise


def reset_http_session():
    """Reset the global HTTP session (useful for testing or reconfiguration)."""
    global _http_session
    if _http_session:
        _http_session.close()
        _http_session = None
    logger.debug("Reset HTTP session")


def rotate_user_agent():
    """Rotate the User-Agent header in the global session."""
    config = _get_http_config()
    session = get_http_session()
    user_agents = config["user_agents"]
    session.headers["User-Agent"] = random.choice(user_agents)
