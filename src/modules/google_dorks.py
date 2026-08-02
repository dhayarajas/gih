"""
Ghost Identity Hunter - Google Dorks Module

PURPOSE:
--------
This module provides Google Dorks integration for advanced username discovery
and OSINT gathering using Google search operators and patterns.

FUNCTIONALITY:
--------------
- Pre-defined Google Dork patterns for username discovery
- Google Custom Search API integration
- Web scraping fallback for searches
- Result parsing and artifact extraction
- Rate limiting and caching
- Platform-specific dork patterns
- Combined dork queries for comprehensive results

DORK PATTERNS:
-------------
- Site-specific searches (Twitter, LinkedIn, GitHub, etc.)
- Social platform searches
- Profile page searches
- Document searches
- Forum mentions
- Email pattern searches
- Combined searches with multiple operators

ALGORITHM:
---------
1. Build Google Dork queries from username
2. Execute searches via API or web scraping
3. Parse search results for username mentions
4. Extract artifacts (platforms, profiles, emails, etc.)
5. Return discovered artifacts with confidence scores

DEPENDENCIES:
-------------
- requests: HTTP requests for Google searches
- beautifulsoup4: HTML parsing for web scraping
- google-api-python-client: Google Custom Search API (optional)
- logging: Debug and error reporting
- time: Rate limiting

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
3.0 - Google Dorks Integration
"""

import json
import logging
import random
import re
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from bs4 import BeautifulSoup

from src.config.loader import get_config

logger = logging.getLogger(__name__)

# Process-global rate-limit state shared across ALL GoogleDorksSearch instances.
# An investigation creates a fresh instance per username artifact, and many run
# concurrently across BFS workers, so a per-instance limiter never actually
# spaces out the outbound search traffic -- dozens of requests fire at once and
# the search engine responds with 429s. One shared clock throttles every search
# request in the process regardless of which instance/thread issues it.
_global_rate_limit_lock = threading.Lock()
_global_last_request_time = 0.0


# Path segments that are never real usernames; extracting them from result URLs
# just spawns junk username searches (e.g. login.php, login?service=mail) that
# balloon the BFS frontier and waste rate-limited search calls.
_GENERIC_PATH_SEGMENTS = frozenset({
    "login", "signin", "sign-in", "signup", "sign-up", "register", "logout",
    "home", "index", "about", "about-us", "contact", "help", "support",
    "search", "settings", "account", "accounts", "profile", "profiles",
    "user", "users", "page", "pages", "post", "posts", "tag", "tags",
    "category", "categories", "wiki", "news", "blog", "faq", "terms",
    "privacy", "en", "www", "auth", "oauth", "sso", "dashboard", "explore",
})

# File extensions that indicate a page/asset path rather than a username.
_FILE_EXTENSIONS = (
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi", ".xml",
    ".json", ".pdf", ".doc", ".docx", ".png", ".jpg", ".jpeg", ".gif",
    ".css", ".js", ".txt",
)


def _is_valid_username(value: str) -> bool:
    """Reject URL path segments that are clearly not usernames.

    The dork extractor takes the last path segment of every result URL as a
    candidate username; without this filter, values like ``login.php`` or
    ``login?service=mail`` become artifacts and trigger their own searches.
    """
    if not value:
        return False
    value = value.strip()
    # Query strings / fragments / encoded chars are never usernames.
    if any(ch in value for ch in "?=&%#@ \t"):
        return False
    if not (3 <= len(value) <= 40):
        return False
    lowered = value.lower()
    if lowered in _GENERIC_PATH_SEGMENTS:
        return False
    if lowered.endswith(_FILE_EXTENSIONS):
        return False
    # Must contain at least one letter and only username-safe characters.
    if not re.search(r"[a-z]", lowered):
        return False
    return bool(re.fullmatch(r"[a-z0-9._-]+", lowered))


def _get_google_dorks_config() -> dict:
    """Get Google Dorks configuration from config.yaml."""
    config = get_config()
    return config.get("google_dorks", {
        "max_patterns": 3,
        "rate_limit_seconds": 1.0,
        "max_results_per_search": 10,
        "max_parallel_workers": 10,
        "max_retries": 1,
        "initial_backoff": 0.5,
        "backoff_multiplier": 2.0,
        "jitter_max": 0.3,
        "max_alternative_links": 50,
        "request_timeout": 15,
    })


@dataclass
class DorkPattern:
    """Google Dork pattern template."""
    
    name: str
    template: str
    description: str
    platforms: List[str] = field(default_factory=list)
    confidence: float = 0.7


@dataclass
class DorkResult:
    """Result from Google Dork search."""
    
    pattern_name: str
    query: str
    results: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    artifacts_discovered: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class GoogleDorksSearch:
    """Google Dorks search engine for username discovery."""
    
    # Pre-defined dork patterns for username discovery
    DORK_PATTERNS = [
        DorkPattern(
            name="simple_search",
            template='{username}',
            description="Simple search for username",
            platforms=["generic"],
            confidence=0.5
        ),
        DorkPattern(
            name="social_platforms",
            template='site:twitter.com "{username}" OR site:linkedin.com "{username}" OR site:github.com "{username}" OR site:instagram.com "{username}"',
            description="Search major social platforms",
            platforms=["twitter", "linkedin", "github", "instagram"],
            confidence=0.9
        ),
        DorkPattern(
            name="profile_pages",
            template='intitle:"profile" "{username}" OR intitle:"user" "{username}"',
            description="Search for profile pages",
            platforms=["generic"],
            confidence=0.7
        ),
        DorkPattern(
            name="documents",
            template='filetype:pdf "{username}" OR filetype:doc "{username}" OR filetype:docx "{username}"',
            description="Search for documents containing username",
            platforms=["documents"],
            confidence=0.6
        ),
        DorkPattern(
            name="forum_mentions",
            template='site:reddit.com "{username}" OR site:stackoverflow.com "{username}" OR site:quora.com "{username}"',
            description="Search forum mentions",
            platforms=["reddit", "stackoverflow", "quora"],
            confidence=0.8
        ),
        # Removed email_pattern - too broad and causes false positives
        DorkPattern(
            name="combined_search",
            template='"{username}" (profile OR account OR user OR bio)',
            description="Combined search with keywords",
            platforms=["generic"],
            confidence=0.6
        ),
        DorkPattern(
            name="developer_platforms",
            template='site:github.com "{username}" OR site:gitlab.com "{username}" OR site:bitbucket.org "{username}"',
            description="Search developer platforms",
            platforms=["github", "gitlab", "bitbucket"],
            confidence=0.9
        ),
        DorkPattern(
            name="professional_networks",
            template='site:linkedin.com "{username}" OR site:xing.com "{username}" OR site:about.me "{username}"',
            description="Search professional networks",
            platforms=["linkedin", "xing", "about.me"],
            confidence=0.9
        ),
    ]
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cx: Optional[str] = None,
        use_api: bool = False,
        rate_limit: Optional[float] = None,
        search_engine: str = "auto",
        cache_dir: Optional[str] = None,
        max_patterns: Optional[int] = None
    ):
        """
        Initialize Google Dorks search engine.
        
        Args:
            api_key: Google Custom Search API key (optional)
            cx: Google Custom Search Engine ID (optional)
            use_api: Use Google API instead of web scraping
            rate_limit: Minimum seconds between requests (rate limiting)
            search_engine: Search engine to use (auto, duckduckgo, google, bing)
            cache_dir: Directory for caching results (optional)
            max_patterns: Maximum number of patterns to execute (to avoid rate limiting)
        """
        config = _get_google_dorks_config()
        
        self.api_key = api_key
        self.cx = cx
        self.use_api = use_api and api_key and cx
        self.rate_limit = rate_limit if rate_limit is not None else config["rate_limit_seconds"]
        self.search_engine = search_engine
        self.max_patterns = max_patterns if max_patterns is not None else config["max_patterns"]
        self.max_results_per_search = config["max_results_per_search"]
        self.max_parallel_workers = config["max_parallel_workers"]
        # Explicit per-request timeout so a hung HTTP call cannot stall the run.
        self.request_timeout = config.get("request_timeout", 15)
        self.last_request_time = 0
        self._rate_limit_lock = threading.Lock()
        
        # Reuse the pooled HTTP session (keep-alive + tuned retry adapter) so
        # scraping requests don't open a fresh TCP+TLS connection every call.
        from src.utils.http_client import get_http_session
        self._session = get_http_session()
        http_config = get_config().get("http_client", {})
        user_agents = http_config.get("user_agents", [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ])
        self.headers = {
            'User-Agent': random.choice(user_agents)
        }
        
        # Cache setup
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / '.ghosthunter' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _rate_limit(self):
        """Apply rate limiting between requests (thread-safe, process-global).

        Reserve this request's slot against a shared clock under the lock, then
        sleep *outside* it so concurrent callers don't serialize on a thread
        that is merely sleeping. The clock is process-global so that all
        instances spawned across BFS workers space their requests together
        rather than each throttling only against its own last call.
        """
        global _global_last_request_time
        now = time.time()
        with _global_rate_limit_lock:
            scheduled = max(now, _global_last_request_time + self.rate_limit)
            _global_last_request_time = scheduled

        sleep_time = scheduled - now
        if sleep_time > 0:
            logger.debug("Rate limiting: sleeping for %.2f seconds", sleep_time)
            time.sleep(sleep_time)
    
    def _get_cache_key(self, query: str, engine: str) -> str:
        """Generate cache key for query."""
        cache_string = f"{engine}:{query}"
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _get_cached_result(self, query: str, engine: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available."""
        cache_key = self._get_cache_key(query, engine)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                    # Check if cache is less than 24 hours old
                    cache_age = time.time() - cached_data.get('timestamp', 0)
                    if cache_age < 86400:  # 24 hours
                        logger.debug(f"Using cached result for {query}")
                        return cached_data.get('result')
            except Exception as e:
                logger.debug(f"Cache read error: {e}")
        
        return None
    
    def _cache_result(self, query: str, engine: str, result: Dict[str, Any]):
        """Cache search result."""
        cache_key = self._get_cache_key(query, engine)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            cache_data = {
                'timestamp': time.time(),
                'query': query,
                'engine': engine,
                'result': result
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
            logger.debug(f"Cached result for {query}")
        except Exception as e:
            logger.debug(f"Cache write error: {e}")
    
    def _retry_with_backoff(self, func, *args, **kwargs) -> Any:
        """Execute function with exponential backoff retry logic."""
        config = _get_google_dorks_config()
        enable_retry = config.get("enable_retry", True)
        
        if not enable_retry:
            # If retry is disabled, execute once without retry
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.debug(f"Retry disabled, failing immediately: {e}")
                raise
        
        max_retries = config.get("max_retries", 3)
        initial_backoff = config.get("initial_backoff", 1.0)
        backoff_multiplier = config.get("backoff_multiplier", 2.0)
        jitter_max = config.get("jitter_max", 0.5)
        
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                
                # Calculate backoff with jitter
                backoff = initial_backoff * (backoff_multiplier ** attempt)
                jitter = random.uniform(0, jitter_max)
                total_wait = backoff + jitter
                
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {total_wait:.1f}s...")
                time.sleep(total_wait)
        
        return None
    
    def search_username(self, username: str, patterns: Optional[List[str]] = None) -> List[DorkResult]:
        """
        Search for username using Google Dorks patterns.
        
        Args:
            username: Username to search for
            patterns: Specific pattern names to use (None for all)
            
        Returns:
            List of DorkResult objects
        """
        results = []
        
        # Filter patterns if specified
        if patterns:
            dork_patterns = [p for p in self.DORK_PATTERNS if p.name in patterns]
        else:
            dork_patterns = self.DORK_PATTERNS
        
        # Limit patterns to avoid rate limiting
        if self.max_patterns and len(dork_patterns) > self.max_patterns:
            logger.info(f"Limiting patterns from {len(dork_patterns)} to {self.max_patterns} to avoid rate limiting")
            dork_patterns = dork_patterns[:self.max_patterns]
        
        logger.info(f"Searching for username '{username}' with {len(dork_patterns)} dork patterns")
        
        # Execute dork patterns in parallel
        with ThreadPoolExecutor(max_workers=self.max_parallel_workers) as executor:
            futures = {
                executor.submit(self._execute_dork_search, username, pattern): pattern
                for pattern in dork_patterns
            }
            
            for future in as_completed(futures):
                pattern = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"Pattern '{pattern.name}' found {len(result.results)} results")
                    else:
                        logger.warning(f"Pattern '{pattern.name}' failed: {result.error}")
                    
                except Exception as e:
                    logger.error(f"Error executing dork pattern '{pattern.name}': {e}")
                    results.append(DorkResult(
                        pattern_name=pattern.name,
                        query=pattern.template.format(username=username),
                        success=False,
                        error=str(e)
                    ))
        
        # Limit total results to prevent exponential artifact growth
        total_urls = []
        for result in results:
            total_urls.extend(result.results)
        
        if len(total_urls) > self.max_results_per_search:
            logger.warning(f"Limiting Google Dorks results from {len(total_urls)} to {self.max_results_per_search} to prevent exponential growth")
            # Take first N URLs and redistribute across results
            limited_urls = total_urls[:self.max_results_per_search]
            url_index = 0
            for result in results:
                if url_index >= len(limited_urls):
                    result.results = []
                else:
                    result.results = limited_urls[url_index:url_index + len(result.results)]
                    url_index += len(result.results)
        
        return results
    
    def _execute_dork_search(self, username: str, pattern: DorkPattern) -> DorkResult:
        """Execute a single dork pattern search."""
        query = pattern.template.format(username=username)
        
        # Determine which search engine to use
        engine = self._determine_search_engine()
        
        # Check cache first
        cached = self._get_cached_result(query, engine)
        if cached:
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                results=cached.get('results', []),
                success=True,
                artifacts_discovered=cached.get('artifacts', [])
            )
        
        # Execute search based on engine
        if engine == "duckduckgo":
            result = self._search_via_duckduckgo(query, pattern)
        elif self.use_api:
            result = self._search_via_api(query, pattern)
        else:
            result = self._retry_with_backoff(self._search_via_scraping, query, pattern)
        
        # Cache successful results
        if result.success:
            self._cache_result(query, engine, {
                'results': result.results,
                'artifacts': result.artifacts_discovered
            })
        
        return result
    
    def _determine_search_engine(self) -> str:
        """Determine which search engine to use."""
        if self.search_engine == "auto":
            # Prefer Google web scraping (more reliable for dorks), fallback to DuckDuckGo
            return "google"
        return self.search_engine
    
    def _search_via_api(self, query: str, pattern: DorkPattern) -> DorkResult:
        """Search using Google Custom Search API."""
        self._rate_limit()
        
        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                'key': self.api_key,
                'cx': self.cx,
                'q': query,
                'num': 10
            }
            
            response = self._session.get(url, params=params, headers=self.headers, timeout=self.request_timeout)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            
            results = []
            artifacts = []
            
            for item in items:
                result = {
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'snippet': item.get('snippet', ''),
                    'pattern': pattern.name
                }
                results.append(result)
                
                # Extract artifacts from result
                extracted = self._extract_artifacts_from_result(result, pattern)
                artifacts.extend(extracted)
            
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                results=results,
                success=True,
                artifacts_discovered=artifacts
            )
            
        except Exception as e:
            logger.error(f"Google API search failed: {e}")
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                success=False,
                error=str(e)
            )
    
    def _search_via_duckduckgo(self, query: str, pattern: DorkPattern) -> DorkResult:
        """Search using DuckDuckGo HTML search (free, no rate limits)."""
        # DuckDuckGo doesn't require rate limiting - skip for true parallelism
        
        try:
            # DuckDuckGo HTML search (more reliable than API for dorks)
            url = "https://html.duckduckgo.com/html/"
            params = {
                'q': query,
                'kl': 'us-en'
            }
            
            response = self._session.post(url, data=params, headers=self.headers, timeout=self.request_timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            results = []
            artifacts = []
            
            # Debug: Log the HTML structure
            logger.debug(f"DuckDuckGo response length: {len(response.text)}")
            
            # Try multiple parsing strategies
            # Strategy 1: Look for result divs with class 'result'
            result_divs = soup.find_all('div', class_='result')
            logger.debug(f"Found {len(result_divs)} divs with class 'result'")
            
            # Strategy 2: Look for any divs with 'result' in class name
            if not result_divs:
                result_divs = soup.find_all('div', class_=lambda x: x and 'result' in x.lower())
                logger.debug(f"Found {len(result_divs)} divs with 'result' in class name")
            
            # Strategy 3: Look for all links that might be results
            if not result_divs:
                all_links = soup.find_all('a', href=True)
                logger.debug(f"Found {len(all_links)} total links")
                # Filter for likely result links
                result_links = [a for a in all_links if a.get('href') and not a.get('href').startswith('#')]
                logger.debug(f"Found {len(result_links)} non-anchor links")
            
            # Parse DuckDuckGo search results
            for result_div in result_divs:
                try:
                    # Extract title and URL using multiple selectors
                    title_tag = result_div.find('a', class_='result__a')
                    if not title_tag:
                        title_tag = result_div.find('a', class_=lambda x: x and 'result__a' in str(x))
                    if not title_tag:
                        title_tag = result_div.find('a')
                    
                    snippet_tag = result_div.find('a', class_='result__snippet')
                    if not snippet_tag:
                        snippet_tag = result_div.find('div', class_=lambda x: x and 'snippet' in str(x).lower())
                    
                    if title_tag:
                        title = title_tag.get_text().strip()
                        url = title_tag.get('href', '')
                        snippet = snippet_tag.get_text().strip() if snippet_tag else ''
                        
                        # Clean DuckDuckGo redirect URLs
                        if url.startswith('/l/?uddg='):
                            # Extract actual URL from DuckDuckGo redirect
                            import urllib.parse
                            parsed = urllib.parse.urlparse(url)
                            params = urllib.parse.parse_qs(parsed.query)
                            if 'uddg' in params:
                                url = urllib.parse.unquote(params['uddg'][0])
                        
                        # Only add if we have a valid URL
                        if url and url.startswith('http'):
                            results.append({
                                'title': title,
                                'url': url,
                                'snippet': snippet,
                                'pattern': pattern.name
                            })
                            
                            # Extract artifacts from result
                            extracted = self._extract_artifacts_from_result(results[-1], pattern)
                            artifacts.extend(extracted)
                
                except Exception as e:
                    logger.debug(f"Error parsing DuckDuckGo result: {e}")
                    continue
            
            # If still no results, try a different approach
            if not results:
                logger.debug("Trying alternative DuckDuckGo parsing approach")
                # Look for all links with text content
                all_links = soup.find_all('a', href=True)
                logger.debug(f"Found {len(all_links)} total links for alternative parsing")
                
                config = _get_google_dorks_config()
                processed_count = 0
                max_alternative_links = config.get("max_alternative_links", 50)
                
                for link in all_links:
                    if processed_count >= max_alternative_links:
                        logger.debug(f"Reached limit of {max_alternative_links} alternative links")
                        break
                        
                    href = link.get('href', '')
                    text = link.get_text().strip()
                    # Skip navigation links and empty text
                    if href and text and len(text) > 3 and not href.startswith('#'):
                        # Clean redirect URLs
                        if href.startswith('/l/?uddg='):
                            import urllib.parse
                            parsed = urllib.parse.urlparse(href)
                            params = urllib.parse.parse_qs(parsed.query)
                            if 'uddg' in params:
                                href = urllib.parse.unquote(params['uddg'][0])
                        
                        if href.startswith('http'):
                            results.append({
                                'title': text,
                                'url': href,
                                'snippet': '',
                                'pattern': pattern.name
                            })
                            
                            # Extract artifacts from result
                            extracted = self._extract_artifacts_from_result(results[-1], pattern)
                            artifacts.extend(extracted)
                            
                            processed_count += 1
                            
                            # Limit to prevent too many results
                            if len(results) >= 10:
                                break
            
            logger.info(f"DuckDuckGo search found {len(results)} results for pattern '{pattern.name}'")
            
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                results=results,
                success=len(results) > 0,
                artifacts_discovered=artifacts
            )
            
        except Exception as e:
            logger.error(f"DuckDuckGo search failed: {e}")
            # Fallback to Google web scraping
            logger.info("Falling back to Google web scraping")
            return self._retry_with_backoff(self._search_via_scraping, query, pattern)
    
    def _search_via_scraping(self, query: str, pattern: DorkPattern) -> DorkResult:
        """Search using web scraping (fallback)."""
        self._rate_limit()
        
        # Rotate user agent for each request from config
        http_config = get_config().get("http_client", {})
        user_agents = http_config.get("user_agents", [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ])
        self.headers['User-Agent'] = random.choice(user_agents)
        
        try:
            url = f"https://www.google.com/search?q={quote_plus(query)}&num=10"
            response = self._session.get(url, headers=self.headers, timeout=self.request_timeout)
            
            # Handle 429 rate limiting specifically
            if response.status_code == 429:
                logger.warning(f"Google rate limited (429) for query: {query}")
                # Return empty result instead of error to allow other patterns to continue
                return DorkResult(
                    pattern_name=pattern.name,
                    query=query,
                    results=[],
                    success=False,
                    error="Rate limited by Google (429)"
                )
            
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            results = []
            artifacts = []
            
            # Debug: Log response length
            logger.debug(f"Google response length: {len(response.text)}")
            
            # Parse search results - try multiple selectors
            # Strategy 1: Standard Google result divs
            for div in soup.find_all('div', class_='g'):
                try:
                    title_div = div.find('h3')
                    link_div = div.find('a')
                    snippet_div = div.find('div', class_='VwiC3b')
                    
                    if title_div and link_div:
                        result = {
                            'title': title_div.get_text(),
                            'url': link_div.get('href', ''),
                            'snippet': snippet_div.get_text() if snippet_div else '',
                            'pattern': pattern.name
                        }
                        results.append(result)
                        
                        # Extract artifacts from result
                        extracted = self._extract_artifacts_from_result(result, pattern)
                        artifacts.extend(extracted)
                
                except Exception as e:
                    logger.debug(f"Error parsing search result: {e}")
                    continue
            
            # Strategy 2: If no results, try alternative parsing
            if not results:
                logger.debug("Trying alternative Google parsing approach")
                all_links = soup.find_all('a', href=True)
                logger.debug(f"Found {len(all_links)} total links for alternative parsing")
                
                config = _get_google_dorks_config()
                processed_count = 0
                max_alternative_links = config.get("max_alternative_links", 50)
                
                for link in all_links:
                    if processed_count >= max_alternative_links:
                        logger.debug(f"Reached limit of {max_alternative_links} alternative links")
                        break
                        
                    href = link.get('href', '')
                    if href.startswith('http') and not href.startswith('https://www.google.'):
                        # Get text from parent or link
                        text = link.get_text().strip()
                        if text and len(text) > 3:
                            results.append({
                                'title': text,
                                'url': href,
                                'snippet': '',
                                'pattern': pattern.name
                            })
                            
                            # Extract artifacts from result
                            extracted = self._extract_artifacts_from_result(results[-1], pattern)
                            artifacts.extend(extracted)
                            
                            processed_count += 1
                            
                            # Limit results
                            if len(results) >= 10:
                                break
            
            logger.info(f"Google search found {len(results)} results for pattern '{pattern.name}'")
            
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                results=results,
                success=True,
                artifacts_discovered=artifacts
            )
            
        except Exception as e:
            logger.error(f"Web scraping search failed: {e}")
            return DorkResult(
                pattern_name=pattern.name,
                query=query,
                success=False,
                error=str(e)
            )
    
    def _extract_artifacts_from_result(
        self,
        result: Dict[str, Any],
        pattern: DorkPattern
    ) -> List[Dict[str, Any]]:
        """Extract artifacts from search result."""
        artifacts = []
        url = result.get('url', '')
        title = result.get('title', '')
        snippet = result.get('snippet', '')

        config = _get_google_dorks_config()
        max_emails_per_result = int(config.get("max_emails_per_result", 3))
        
        # Extract platform from URL
        platform = self._extract_platform_from_url(url)
        
        # Extract username from URL (skip non-username path segments so junk
        # like login.php or index.html doesn't spawn its own search).
        username_match = re.search(r'/([^/]+)/?$', url)
        if username_match and _is_valid_username(username_match.group(1)):
            username = username_match.group(1)
            artifacts.append({
                'type': 'username',
                'value': username,
                'source': f'google_dorks_{pattern.name}',
                'confidence': pattern.confidence,
                'platform': platform,
                'url': url,
                'metadata': {
                    'pattern': pattern.name,
                    'title': title,
                    'snippet': snippet
                }
            })
        
        # Extract email from snippet (de-duplicated and capped to bound growth).
        seen_emails: set = set()
        for email in re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', snippet):
            if email in seen_emails:
                continue
            seen_emails.add(email)
            if len(seen_emails) > max_emails_per_result:
                break
            artifacts.append({
                'type': 'email',
                'value': email,
                'source': f'google_dorks_{pattern.name}',
                'confidence': pattern.confidence * 0.8,
                'url': url,
                'metadata': {
                    'pattern': pattern.name,
                    'title': title
                }
            })
        
        # Extract domain from URL
        domain_match = re.search(r'https?://(?:www\.)?([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            artifacts.append({
                'type': 'domain',
                'value': domain,
                'source': f'google_dorks_{pattern.name}',
                'confidence': pattern.confidence * 0.7,
                'url': url,
                'metadata': {
                    'pattern': pattern.name
                }
            })
        
        return artifacts
    
    def _extract_platform_from_url(self, url: str) -> str:
        """Extract platform name from URL."""
        domain_match = re.search(r'https?://(?:www\.)?([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            # Map common domains to platform patterns
            platform_map = {
                'twitter.com': 'twitter',
                'linkedin.com': 'linkedin',
                'github.com': 'github',
                'instagram.com': 'instagram',
                'reddit.com': 'reddit',
                'stackoverflow.com': 'stackoverflow',
                'gitlab.com': 'gitlab',
                'bitbucket.org': 'bitbucket',
                'xing.com': 'xing',
                'about.me': 'about.me',
                'quora.com': 'quora'
            }
            return platform_map.get(domain, 'generic')
        return 'generic'


def run_google_dorks_search(
    username: str,
    api_key: Optional[str] = None,
    cx: Optional[str] = None,
    use_api: bool = False,
    patterns: Optional[List[str]] = None,
    search_engine: str = "auto",
    cache_dir: Optional[str] = None,
    max_patterns: int = 3
) -> List[Dict[str, Any]]:
    """
    Run Google Dorks search for username discovery.
    
    Args:
        username: Username to search for
        api_key: Google Custom Search API key (optional)
        cx: Google Custom Search Engine ID (optional)
        use_api: Use Google API instead of web scraping
        patterns: Specific pattern names to use (None for all)
        search_engine: Search engine to use (auto, duckduckgo, google, bing)
        cache_dir: Directory for caching results (optional)
        max_patterns: Maximum number of patterns to execute (to avoid rate limiting)
        
    Returns:
        List of discovered artifacts
    """
    searcher = GoogleDorksSearch(
        api_key=api_key,
        cx=cx,
        use_api=use_api,
        search_engine=search_engine,
        cache_dir=cache_dir,
        max_patterns=max_patterns
    )
    
    results = searcher.search_username(username, patterns)
    
    # Collect all discovered artifacts
    all_artifacts = []
    for result in results:
        all_artifacts.extend(result.artifacts_discovered)
    
    logger.info(f"Google Dorks search discovered {len(all_artifacts)} artifacts")
    
    return all_artifacts


def check_google_dorks_availability(api_key: Optional[str] = None) -> bool:
    """Check if Google Dorks search is available."""
    if api_key:
        return True
    # Web scraping is always available (though less reliable)
    return True
