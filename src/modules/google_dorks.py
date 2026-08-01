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
        rate_limit: float = 1.0
    ):
        """
        Initialize Google Dorks search engine.
        
        Args:
            api_key: Google Custom Search API key (optional)
            cx: Google Custom Search Engine ID (optional)
            use_api: Use Google API instead of web scraping
            rate_limit: Minimum seconds between requests (rate limiting)
        """
        self.api_key = api_key
        self.cx = cx
        self.use_api = use_api and api_key and cx
        self.rate_limit = rate_limit
        self.last_request_time = 0
        
        # User agent for web scraping
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
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
        
        if self.use_api:
            return self._search_via_api(query, pattern)
        else:
            return self._search_via_scraping(query, pattern)
    
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
    
    def _search_via_scraping(self, query: str, pattern: DorkPattern) -> DorkResult:
        """Search using web scraping (fallback)."""
        self._rate_limit()
        
        try:
            url = f"https://www.google.com/search?q={quote_plus(query)}&num=10"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            results = []
            artifacts = []
            
            # Parse search results
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
    patterns: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Run Google Dorks search for username discovery.
    
    Args:
        username: Username to search for
        api_key: Google Custom Search API key (optional)
        cx: Google Custom Search Engine ID (optional)
        use_api: Use Google API instead of web scraping
        patterns: Specific pattern names to use (None for all)
        
    Returns:
        List of discovered artifacts
    """
    searcher = GoogleDorksSearch(
        api_key=api_key,
        cx=cx,
        use_api=use_api
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
