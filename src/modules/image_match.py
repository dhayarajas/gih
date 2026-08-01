"""
Ghost Identity Hunter - Image Search and Face Matching Module

PURPOSE:
--------
This module provides comprehensive image search and face matching capabilities
to identify and verify individuals based on their full name and collated
data from multiple sources.

FUNCTIONALITY:
--------------
- Image search across multiple platforms (Google Images, Bing, social media)
- Face detection and feature extraction using face_recognition library
- Face matching with probability scoring
- Multi-source image aggregation
- Confidence scoring based on cross-platform consistency
- Metadata extraction (profile pictures, avatars, etc.)

DATA SOURCES:
-------------
- Google Images Search API
- Bing Images Search API
- Social media profile pictures (LinkedIn, GitHub, Twitter, etc.)
- Professional networking sites
- Public profile databases

MATCHING ALGORITHM:
-------------------
- Face encoding using 128-dimensional face descriptors
- Euclidean distance calculation for face similarity
- Probability scoring based on distance thresholds
- Cross-platform consistency verification
- Metadata correlation (name, location, etc.)

RISK ASSESSMENT:
---------------
- High confidence: Multiple matching faces across platforms
- Medium confidence: Single high-quality match with metadata
- Low confidence: Low-quality images or inconsistent metadata
- Critical: Exact match with verified identity sources

USAGE EXAMPLES:
--------------
# Search for images by full name
results = search_images_by_name("John Doe")

# Match faces across multiple images
matches = match_faces(image_list, reference_image)

# Get probability score
probability = calculate_match_probability(face1, face2, metadata)

DEPENDENCIES:
-------------
- face_recognition: Face detection and recognition
- PIL/Pillow: Image processing
- requests: HTTP client for API calls
- numpy: Numerical operations for face encodings

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
1.0 - Initial Implementation
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from urllib.parse import quote_plus

import requests
from PIL import Image
import numpy as np

from src.utils.http_client import get_http_session

logger = logging.getLogger(__name__)


@dataclass
class ImageResult:
    """Result from image search."""
    
    url: str
    source: str
    confidence: float = 0.0
    face_encoding: Optional[np.ndarray] = None
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class FaceMatchResult:
    """Result from face matching."""
    
    image_url: str
    match_probability: float
    distance: float
    source: str
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "image_url": self.image_url,
            "match_probability": self.match_probability,
            "distance": self.distance,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class IdentityMatchResult:
    """Aggregated identity matching results."""
    
    full_name: str
    images: List[ImageResult] = field(default_factory=list)
    face_matches: List[FaceMatchResult] = field(default_factory=list)
    overall_probability: float = 0.0
    confidence_sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "full_name": self.full_name,
            "images": [img.to_dict() for img in self.images],
            "face_matches": [match.to_dict() for match in self.face_matches],
            "overall_probability": self.overall_probability,
            "confidence_sources": self.confidence_sources,
        }


def search_images_by_name(full_name: str, max_results: int = 20) -> List[ImageResult]:
    """
    Search for images of a person by their full name across multiple sources.
    
    Args:
        full_name: The person's full name to search for
        max_results: Maximum number of results to return
    
    Returns:
        List of ImageResult objects
    """
    results = []
    
    # Search Google Images
    google_results = _search_google_images(full_name, max_results)
    results.extend(google_results)
    
    # Search Bing Images
    bing_results = _search_bing_images(full_name, max_results)
    results.extend(bing_results)
    
    # Search social media profile pictures
    social_results = _search_social_media_images(full_name)
    results.extend(social_results)
    
    logger.info("Found %d images for %s", len(results), full_name)
    return results[:max_results]


def _search_google_images(query: str, max_results: int = 10) -> List[ImageResult]:
    """Search Google Images for the given query."""
    results = []
    
    try:
        session = get_http_session()
        
        # Use Google Custom Search API if available, otherwise use scraping
        # For now, use a simple approach with Google Images URL pattern
        search_url = f"https://www.google.com/search?q={quote_plus(query)}&tbm=isch"
        
        resp = session.get(search_url, timeout=10)
        
        if resp.status_code == 200:
            # Parse HTML to extract image URLs
            # This is a simplified version - production would use proper API
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Extract image URLs from img tags
            img_tags = soup.find_all('img')
            for img in img_tags[:max_results]:
                src = img.get('src', '')
                if src and src.startswith('http'):
                    results.append(ImageResult(
                        url=src,
                        source="Google Images",
                        confidence=0.7,
                        metadata={"query": query}
                    ))
    
    except Exception as e:
        logger.warning("Google Images search failed: %s", e)
    
    return results


def _search_bing_images(query: str, max_results: int = 10) -> List[ImageResult]:
    """Search Bing Images for the given query."""
    results = []
    
    try:
        session = get_http_session()
        search_url = f"https://www.bing.com/images/search?q={quote_plus(query)}"
        
        resp = session.get(search_url, timeout=10)
        
        if resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            img_tags = soup.find_all('img')
            for img in img_tags[:max_results]:
                src = img.get('src', '')
                if src and src.startswith('http'):
                    results.append(ImageResult(
                        url=src,
                        source="Bing Images",
                        confidence=0.7,
                        metadata={"query": query}
                    ))
    
    except Exception as e:
        logger.warning("Bing Images search failed: %s", e)
    
    return results


def _search_social_media_images(full_name: str) -> List[ImageResult]:
    """Search social media platforms for profile pictures."""
    results = []
    
    # Extract potential username from full name
    username = full_name.lower().replace(' ', '').replace('.', '')
    
    # Common social media platforms
    platforms = [
        ("GitHub", f"https://github.com/{username}"),
        ("LinkedIn", f"https://www.linkedin.com/in/{username}"),
        ("Twitter", f"https://twitter.com/{username}"),
        ("Instagram", f"https://www.instagram.com/{username}/"),
    ]
    
    session = get_http_session()
    
    for platform_name, profile_url in platforms:
        try:
            resp = session.get(profile_url, timeout=10)
            
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Look for profile picture
                img_tags = soup.find_all('img')
                for img in img_tags:
                    src = img.get('src', '') or img.get('data-src', '')
                    if src and ('avatar' in src.lower() or 'profile' in src.lower()):
                        results.append(ImageResult(
                            url=src,
                            source=f"{platform_name} Profile",
                            confidence=0.9,  # Higher confidence for profile pictures
                            metadata={"profile_url": profile_url, "platform": platform_name}
                        ))
                        break  # Take first profile picture found
        
        except Exception as e:
            logger.debug("Failed to fetch %s profile: %s", platform_name, e)
    
    return results


def extract_profile_image_from_url(profile_url: str) -> Optional[str]:
    """
    Extract a single profile/avatar image URL from a platform profile page.

    Reuses the same scraping heuristics as ``_search_social_media_images`` but
    operates on an already-known profile URL (e.g. a ``platform_presence``
    record's ``profile_url``) instead of guessing platform URLs from a name.

    Args:
        profile_url: URL of the social/web profile page to scrape.

    Returns:
        Absolute image URL if a profile picture is found, otherwise None.
    """
    if not profile_url or not profile_url.startswith("http"):
        return None

    try:
        session = get_http_session()
        resp = session.get(profile_url, timeout=10)

        if resp.status_code != 200:
            return None

        from bs4 import BeautifulSoup
        from urllib.parse import urljoin

        soup = BeautifulSoup(resp.text, "html.parser")

        # Primary heuristic: an <img> whose src/data-src references an avatar
        # or profile picture (mirrors _search_social_media_images).
        for img in soup.find_all("img"):
            src = img.get("src", "") or img.get("data-src", "")
            if src and ("avatar" in src.lower() or "profile" in src.lower()):
                return urljoin(profile_url, src)

        # Fallback: OpenGraph / Twitter card image meta tags.
        for finder in (
            lambda: soup.find("meta", property="og:image"),
            lambda: soup.find("meta", attrs={"name": "twitter:image"}),
        ):
            meta = finder()
            if meta and meta.get("content"):
                return urljoin(profile_url, meta["content"])

    except Exception as e:
        logger.debug("Failed to extract profile image from %s: %s", profile_url, e)

    return None


def extract_face_encoding(image_url: str) -> Optional[np.ndarray]:
    """
    Extract face encoding from an image URL.
    
    Args:
        image_url: URL of the image
    
    Returns:
        Face encoding as numpy array, or None if no face detected
    """
    try:
        import face_recognition
        
        session = get_http_session()
        resp = session.get(image_url, timeout=10)
        
        if resp.status_code == 200:
            # Load image from response
            from io import BytesIO
            image = Image.open(BytesIO(resp.content))
            image_array = np.array(image)
            
            # Detect faces and get encodings
            face_encodings = face_recognition.face_encodings(image_array)
            
            if face_encodings:
                return face_encodings[0]  # Return first face encoding
    
    except ImportError:
        logger.warning("face_recognition library not installed")
    except Exception as e:
        logger.debug("Failed to extract face encoding: %s", e)
    
    return None


def match_faces(images: List[ImageResult], reference_encoding: Optional[np.ndarray] = None) -> List[FaceMatchResult]:
    """
    Match faces across multiple images with probability scoring.
    
    Args:
        images: List of ImageResult objects
        reference_encoding: Optional reference face encoding to match against
    
    Returns:
        List of FaceMatchResult objects with probability scores
    """
    matches = []
    
    # Extract face encodings for all images
    with ThreadPoolExecutor(max_workers=10) as executor:
        encoding_futures = {
            executor.submit(extract_face_encoding, img.url): img
            for img in images
        }
        
        for future in as_completed(encoding_futures):
            image = encoding_futures[future]
            try:
                encoding = future.result()
                
                if encoding is not None:
                    image.face_encoding = encoding
            except Exception as e:
                logger.debug("Failed to extract encoding for %s: %s", image.url, e)
    
    # If no reference encoding provided, use first image with face
    if reference_encoding is None:
        for img in images:
            if img.face_encoding is not None:
                reference_encoding = img.face_encoding
                break
    
    if reference_encoding is None:
        logger.warning("No reference face encoding found")
        return matches
    
    # Calculate match probabilities
    for image in images:
        if image.face_encoding is not None:
            distance = np.linalg.norm(reference_encoding - image.face_encoding)
            
            # Convert distance to probability (closer = higher probability)
            # Typical distance threshold is 0.6
            if distance < 0.6:
                probability = (0.6 - distance) / 0.6
            else:
                probability = 0.0
            
            matches.append(FaceMatchResult(
                image_url=image.url,
                match_probability=probability,
                distance=distance,
                source=image.source,
                metadata=image.metadata
            ))
    
    # Sort by probability
    matches.sort(key=lambda x: x.match_probability, reverse=True)
    
    return matches


def calculate_identity_probability(full_name: str, images: List[ImageResult], face_matches: List[FaceMatchResult]) -> float:
    """
    Calculate overall identity probability based on multiple factors.
    
    Args:
        full_name: The person's full name
        images: List of image results
        face_matches: List of face match results
    
    Returns:
        Overall probability score (0.0 to 1.0)
    """
    if not images:
        return 0.0
    
    factors = []
    
    # Factor 1: Number of images found
    image_count_factor = min(len(images) / 10.0, 1.0)
    factors.append(("image_count", image_count_factor))
    
    # Factor 2: Face match consistency
    if face_matches:
        avg_face_probability = sum(m.match_probability for m in face_matches) / len(face_matches)
        factors.append(("face_match", avg_face_probability))
    else:
        factors.append(("face_match", 0.0))
    
    # Factor 3: Source diversity
    sources = set(img.source for img in images)
    source_diversity = min(len(sources) / 5.0, 1.0)
    factors.append(("source_diversity", source_diversity))
    
    # Factor 4: Profile picture presence (higher confidence)
    profile_pictures = sum(1 for img in images if "profile" in img.source.lower())
    profile_factor = min(profile_pictures / 3.0, 1.0)
    factors.append(("profile_pictures", profile_factor))
    
    # Calculate weighted average
    weights = {
        "image_count": 0.2,
        "face_match": 0.4,
        "source_diversity": 0.2,
        "profile_pictures": 0.2
    }
    
    overall_probability = sum(weights[name] * value for name, value in factors)
    
    logger.debug("Identity probability factors for %s: %s", full_name, factors)
    
    return overall_probability


def search_and_match_identity(full_name: str, max_results: int = 20) -> IdentityMatchResult:
    """
    Complete identity search and matching workflow.
    
    Args:
        full_name: The person's full name to search for
        max_results: Maximum number of results to return
    
    Returns:
        IdentityMatchResult with images, face matches, and probability
    """
    logger.info("Starting identity search for: %s", full_name)
    
    # Search for images
    images = search_images_by_name(full_name, max_results)
    
    # Match faces
    face_matches = match_faces(images)
    
    # Calculate overall probability
    overall_probability = calculate_identity_probability(full_name, images, face_matches)
    
    # Identify confidence sources
    confidence_sources = list(set(img.source for img in images if img.confidence > 0.7))
    
    result = IdentityMatchResult(
        full_name=full_name,
        images=images,
        face_matches=face_matches,
        overall_probability=overall_probability,
        confidence_sources=confidence_sources
    )
    
    logger.info(
        "Identity search complete for %s: %d images, %d face matches, probability=%.2f",
        full_name, len(images), len(face_matches), overall_probability
    )
    
    return result


def get_discovered_artifacts(match_result: IdentityMatchResult) -> list[dict]:
    """Extract artifacts from identity match results."""
    artifacts = []
    
    # Add image URLs as artifacts
    for image in match_result.images:
        artifacts.append({
            "type": "image_url",
            "value": image.url,
            "source": f"image_search_{image.source.lower().replace(' ', '_')}",
            "confidence": image.confidence,
            "metadata": json.dumps(image.to_dict()),
        })
    
    # Add high-confidence face matches
    for match in match_result.face_matches:
        if match.match_probability > 0.7:
            artifacts.append({
                "type": "face_match",
                "value": match.image_url,
                "source": f"face_match_{match.source.lower().replace(' ', '_')}",
                "confidence": match.match_probability,
                "metadata": json.dumps(match.to_dict()),
            })
    
    return artifacts
