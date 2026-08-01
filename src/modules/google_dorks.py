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

import logging
import random
import re
import time
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Rotate through realistic User-Agent strings to reduce fingerprinting
_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
]

# Retry / backoff settings for web scraping
_MAX_RETRIES = 3
_INITIAL_BACKOFF = 8.0   # seconds — first retry wait
_BACKOFF_MULTIPLIER = 2.0
_JITTER_MAX = 3.0        # random extra seconds added to each wait


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
        DorkPattern(
            name="email_pattern",
            template='site:*.* "{username}" @gmail.com OR "{username}" @yahoo.com OR "{username}" @hotmail.com',
            description="Search for email patterns",
            platforms=["email"],
            confidence=0.7
        ),
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
        rate_limit: float = 1.0,
        search_engine: str = "auto",
        cache_dir: Optional[str] = None,
        max_patterns: int = 3
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
        self.api_key = api_key
        self.cx = cx
        self.use_api = use_api and api_key and cx
        self.rate_limit = rate_limit
        self.search_engine = search_engine
        self.max_patterns = max_patterns
        self.last_request_time = 0
        
        # User agent rotation
        self.headers = {
            'User-Agent': random.choice(_USER_AGENTS)
        }
        
        # Cache setup
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / '.ghosthunter' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
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
        for attempt in range(_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == _MAX_RETRIES - 1:
                    raise
                
                # Calculate backoff with jitter
                backoff = _INITIAL_BACKOFF * (_BACKOFF_MULTIPLIER ** attempt)
                jitter = random.uniform(0, _JITTER_MAX)
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
        
        for pattern in dork_patterns:
            try:
                result = self._execute_dork_search(username, pattern)
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
            
            response = requests.get(url, params=params, headers=self.headers)
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
        self._rate_limit()
        
        try:
            # DuckDuckGo HTML search (more reliable than API for dorks)
            url = "https://html.duckduckgo.com/html/"
            params = {
                'q': query,
                'kl': 'us-en'
            }
            
            response = requests.post(url, data=params, headers=self.headers)
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
                for link in all_links:
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
        
        # Rotate user agent for each request
        self.headers['User-Agent'] = random.choice(_USER_AGENTS)
        
        try:
            url = f"https://www.google.com/search?q={quote_plus(query)}&num=10"
            response = requests.get(url, headers=self.headers)
            
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
                for link in soup.find_all('a', href=True):
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
        
        # Extract platform from URL
        platform = self._extract_platform_from_url(url)
        
        # Extract username from URL
        username_match = re.search(r'/([^/]+)/?$', url)
        if username_match:
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
        
        # Extract email from snippet
        email_matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', snippet)
        for email in email_matches:
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
