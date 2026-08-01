"""
Ghost Identity Hunter - Profile Image Extraction Plugin

PURPOSE:
--------
Plugin to extract profile images from platform presence URLs.
Fetches profile pages from discovered social media accounts and
extracts profile/avatar image URLs to create image artifacts.

FUNCTIONALITY:
--------------
- Processes platform_presence artifacts (URLs)
- Fetches profile page HTML using HTTP client
- Extracts profile image URLs from common selectors and meta tags
- Downloads image metadata and creates image artifacts
- Links profile images to identity profiles via correlation

SUPPORTED PLATFORMS:
--------------------
- Instagram, Pinterest, Steam, Medium, Mastodon, GitHub
- LinkedIn, GitLab, Reddit, Twitter/X, Keybase
- Generic OpenGraph/meta tag fallback

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project
"""

import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from src.plugins.base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.utils.http_client import get_http_session

logger = logging.getLogger(__name__)


class ProfileImagePlugin(OSINTPlugin):
    """Plugin for extracting profile images from platform presence URLs."""
    
    name = "profile_image"
    version = "1.0.0"
    description = "Extracts profile/avatar images from social platform URLs"
    
    def __init__(self, config: Optional[PluginConfig] = None):
        super().__init__(config)
        self.supported_artifact_types = ["platform_presence"]
        self.timeout = self.config.timeout if self.config else 10
    
    def get_name(self) -> str:
        """Get the plugin name."""
        return self.name
    
    def get_version(self) -> str:
        """Get the plugin version."""
        return self.version
    
    def get_description(self) -> str:
        """Get the plugin description."""
        return self.description
    
    def get_supported_artifact_types(self) -> list[str]:
        """Get the artifact types this plugin can process."""
        return self.supported_artifact_types
    
    def is_available(self) -> bool:
        """Check if the plugin is available."""
        try:
            import bs4
            return True
        except ImportError:
            logger.warning("beautifulsoup4 not available, profile image plugin disabled")
            return False
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute profile image extraction from platform presence URL.
        
        Args:
            artifact: platform_presence artifact with URL value
            
        Returns:
            PluginResult with discovered image artifacts
        """
        try:
            url = artifact.value
            if not url or not url.startswith("http"):
                logger.debug("Invalid platform presence URL: %s", url)
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SKIPPED,
                    error="Invalid URL"
                )
            
            logger.info("Extracting profile image from: %s", url)
            
            # Fetch the profile page with strict timeout to avoid hanging
            session = get_http_session()
            try:
                resp = session.get(
                    url, 
                    timeout=(max(self.timeout - 2, 3), self.timeout),
                    allow_redirects=True,
                    headers={"Accept": "text/html,application/xhtml+xml"},
                    stream=False
                )
                resp.raise_for_status()
            except Exception as e:
                logger.debug("Failed to fetch %s: %s", url, e)
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.PARTIAL,
                    error=f"Failed to fetch profile page: {e}"
                )
            
            # Extract image URL
            image_url = self._extract_profile_image(url, resp.text)
            
            if not image_url:
                logger.debug("No profile image found for %s", url)
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.PARTIAL,
                    error="No profile image found"
                )
            
            # Validate image URL
            image_url = urljoin(url, image_url)
            
            # Verify image is accessible and get metadata
            image_type, image_size = self._get_image_info(image_url)
            
            if not image_type:
                logger.debug("Image not accessible: %s", image_url)
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.PARTIAL,
                    error="Profile image not accessible"
                )
            
            logger.info("Found profile image for %s: %s", url, image_url)
            
            # Create image artifact
            platform_name = self._extract_platform(url)
            discovered = [Artifact(
                type="image",
                value=image_url,
                source=self.name,
                confidence=0.85,
                metadata={
                    "platform": platform_name,
                    "profile_url": url,
                    "image_type": image_type,
                    "image_size": image_size,
                    "is_profile_image": True
                }
            )]
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered,
                metadata={
                    "platform": platform_name,
                    "profile_url": url,
                    "image_url": image_url,
                    "image_type": image_type
                }
            )
            
        except Exception as e:
            logger.error("Profile image extraction failed for %s: %s", artifact.value, e)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )
    
    def _extract_platform(self, url: str) -> str:
        """Extract platform name from URL."""
        domain = urlparse(url).netloc.lower()
        platform_map = {
            "instagram.com": "Instagram",
            "pinterest.com": "Pinterest",
            "steamcommunity.com": "Steam",
            "medium.com": "Medium",
            "mastodon.social": "Mastodon",
            "github.com": "GitHub",
            "gitlab.com": "GitLab",
            "linkedin.com": "LinkedIn",
            "reddit.com": "Reddit",
            "twitter.com": "Twitter",
            "x.com": "Twitter",
            "keybase.io": "Keybase",
            "news.ycombinator.com": "HackerNews",
        }
        
        for key, value in platform_map.items():
            if key in domain:
                return value
        
        return "unknown"
    
    def _extract_profile_image(self, url: str, html: str) -> Optional[str]:
        """
        Extract profile image URL from profile page HTML.
        
        Uses platform-specific selectors and falls back to OpenGraph meta tags.
        """
        soup = BeautifulSoup(html, "html.parser")
        platform = self._extract_platform(url)
        
        # Platform-specific extraction
        selectors = self._get_platform_selectors(platform)
        
        for selector, attr in selectors:
            element = soup.select_one(selector)
            if element:
                image_url = element.get(attr)
                if image_url:
                    image_url = self._clean_image_url(image_url)
                    if image_url:
                        return image_url
        
        # Fallback: OpenGraph image meta tag
        og_image = soup.find("meta", property="og:image") or soup.find("meta", attrs={"name": "og:image"})
        if og_image and og_image.get("content"):
            image_url = self._clean_image_url(og_image.get("content"))
            if image_url:
                return image_url
        
        # Fallback: Twitter card image
        twitter_image = soup.find("meta", attrs={"name": "twitter:image"}) or soup.find("meta", property="twitter:image")
        if twitter_image and twitter_image.get("content"):
            image_url = self._clean_image_url(twitter_image.get("content"))
            if image_url:
                return image_url
        
        # Fallback: profile/avatar image with common class names
        for keyword in ["avatar", "profile-photo", "profile-image", "user-photo", "profile-pic"]:
            element = soup.find(attrs={"class": re.compile(keyword, re.I)})
            if element and element.get("src"):
                return self._clean_image_url(element.get("src"))
            if element:
                img = element.find("img")
                if img and img.get("src"):
                    return self._clean_image_url(img.get("src"))
        
        return None
    
    def _get_platform_selectors(self, platform: str) -> list[tuple[str, str]]:
        """Get CSS selectors for profile images by platform."""
        selectors = {
            "Instagram": [
                ("img[src*=\"profile\"]", "src"),
                ("header img", "src"),
                ("article img", "src"),
            ],
            "Pinterest": [
                ("img[alt*=\"profile\"]", "src"),
                ("[data-test-id=\"profile-image\"] img", "src"),
            ],
            "Steam": [
                (".playerAvatar img", "src"),
                (".player_avatar img", "src"),
            ],
            "Medium": [
                ("img[width=\"128\"]", "src"),
                ("img[width=\"64\"]", "src"),
            ],
            "GitHub": [
                ("img.avatar", "src"),
                ("[itemprop=\"image\"]", "src"),
            ],
            "GitLab": [
                (".avatar, .user-avatar", "src"),
                ("[src*=\"avatar\"]", "src"),
            ],
            "Mastodon": [
                ("img.account__avatar", "src"),
                (".account__header__bar img", "src"),
            ],
            "Reddit": [
                ("img[alt=\"User avatar\"]", "src"),
                ("[data-testid=\"profile-icon\"] img", "src"),
            ],
            "LinkedIn": [
                ("img[alt*=\"profile\"]", "src"),
                (".pv-top-card-profile-picture__image", "src"),
            ],
        }
        
        return selectors.get(platform, [])
    
    def _clean_image_url(self, url: str) -> Optional[str]:
        """Clean and validate image URL."""
        if not url:
            return None
        
        # Remove URL parameters that might be tracking
        url = url.strip()
        
        # Handle protocol-relative URLs
        if url.startswith("//"):
            url = "https:" + url
        
        # Handle data URIs (skip them - too large)
        if url.startswith("data:"):
            return None
        
        # Only accept http/https URLs
        if not url.startswith("http://") and not url.startswith("https://"):
            return None
        
        return url
    
    def _get_image_info(self, image_url: str) -> tuple[Optional[str], Optional[int]]:
        """Get image content type and size with strict timeout to avoid hanging."""
        timeout = (max(self.timeout - 2, 2), self.timeout)
        try:
            session = get_http_session()
            resp = session.head(
                image_url, 
                timeout=timeout,
                allow_redirects=True,
                headers={"Accept": "image/*,*/*;q=0.8"}
            )
            content_type = resp.headers.get("content-type", "").lower()
            content_length = resp.headers.get("content-length")
            
            if "image" in content_type:
                size = int(content_length) if content_length else None
                return content_type, size
            
            # If HEAD fails, try GET with stream and small timeout
            resp = session.get(
                image_url, 
                timeout=timeout,
                stream=True,
                headers={"Accept": "image/*,*/*;q=0.8"}
            )
            content_type = resp.headers.get("content-type", "").lower()
            
            if "image" in content_type:
                size = resp.headers.get("content-length")
                size = int(size) if size else None
                return content_type, size
            
            return None, None
            
        except Exception as e:
            logger.debug("Could not verify image %s: %s", image_url, e)
            return None, None
