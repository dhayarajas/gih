"""
Ghost Identity Hunter - Image Search Module

PURPOSE:
--------
This module provides comprehensive image intelligence capabilities including EXIF metadata
extraction, GPS coordinate analysis, file hashing, reverse image search URL generation,
and stock photo detection to assess the authenticity and origin of image artifacts.

FUNCTIONALITY:
--------------
- EXIF metadata extraction (camera info, timestamps, GPS coordinates)
- GPS coordinate conversion and location analysis
- File hashing (MD5, SHA-256) for duplicate detection
- Reverse image search URL generation for multiple services
- Image dimension and format analysis
- Stock photo detection indicators
- Camera fingerprinting for device identification

DATA SOURCES:
-------------
- PIL/Pillow: EXIF metadata extraction and image processing
- Built-in GPS coordinate conversion utilities
- Reverse image search engines (Google Images, TinEye, Yandex, Lens)
- File system for image file access and hashing

RISK ASSESSMENT:
---------------
- GPS coordinates reveal physical location data
- Camera EXIF data can identify specific devices
- Stock photos indicate potential identity deception
- File hashes help detect image reuse across platforms
- Missing EXIF data may indicate privacy-conscious usage

USAGE EXAMPLES:
--------------
# Analyze an image file
analysis = analyze_image("/path/to/image.jpg")

# Check for GPS coordinates
if analysis.exif.has_gps():
    print(f"Location: {analysis.exif.gps_latitude}, {analysis.exif.gps_longitude}")

# Generate reverse search URLs
search_urls = generate_reverse_search_urls("/path/to/image.jpg")

# Extract discovered artifacts
artifacts = get_discovered_artifacts(analysis)

DEPENDENCIES:
-------------
- PIL/Pillow: Image processing and EXIF extraction
- hashlib: File hashing for duplicate detection
- pathlib: Cross-platform file path handling
- dataclasses: Structured result objects
- logging: Debug and error reporting

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

logger = logging.getLogger(__name__)


@dataclass
class ExifData:
    """Extracted EXIF metadata from an image."""

    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    software: Optional[str] = None
    date_taken: Optional[str] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    gps_altitude: Optional[float] = None
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    orientation: Optional[int] = None
    all_tags: dict = field(default_factory=dict)

    def has_gps(self) -> bool:
        return self.gps_latitude is not None and self.gps_longitude is not None

    def to_dict(self) -> dict:
        return {
            "camera_make": self.camera_make,
            "camera_model": self.camera_model,
            "software": self.software,
            "date_taken": self.date_taken,
            "gps_latitude": self.gps_latitude,
            "gps_longitude": self.gps_longitude,
            "gps_altitude": self.gps_altitude,
            "image_width": self.image_width,
            "image_height": self.image_height,
            "orientation": self.orientation,
        }


@dataclass
class ImageAnalysis:
    """Results from image OSINT analysis."""

    file_path: str
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    file_size_bytes: int = 0
    image_format: str = ""
    dimensions: tuple[int, int] = (0, 0)
    exif: Optional[ExifData] = None
    has_exif: bool = False
    is_stock_photo: bool = False
    risk_indicators: list[str] = field(default_factory=list)
    reverse_search_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_hash_md5": self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size_bytes": self.file_size_bytes,
            "image_format": self.image_format,
            "dimensions": list(self.dimensions),
            "exif": self.exif.to_dict() if self.exif else None,
            "has_exif": self.has_exif,
            "is_stock_photo": self.is_stock_photo,
            "risk_indicators": self.risk_indicators,
            "reverse_search_urls": self.reverse_search_urls,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _convert_gps_to_decimal(gps_coords, gps_ref: str) -> Optional[float]:
    """Convert GPS coordinates from DMS (degrees, minutes, seconds) to decimal."""
    try:
        degrees = float(gps_coords[0])
        minutes = float(gps_coords[1])
        seconds = float(gps_coords[2])
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if gps_ref in ("S", "W"):
            decimal = -decimal
        return decimal
    except (TypeError, ValueError, IndexError):
        return None


def extract_exif(image_path: str) -> Optional[ExifData]:
    """Extract EXIF metadata from an image file."""
    try:
        img = Image.open(image_path)
        exif_data = img._getexif()

        if not exif_data:
            return None

        exif = ExifData()
        gps_info = {}

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, str(tag_id))

            # Store safely (some values aren't JSON-serializable)
            try:
                json.dumps(value)
                exif.all_tags[tag_name] = value
            except (TypeError, ValueError):
                exif.all_tags[tag_name] = str(value)

            if tag_name == "Make":
                exif.camera_make = str(value).strip()
            elif tag_name == "Model":
                exif.camera_model = str(value).strip()
            elif tag_name == "Software":
                exif.software = str(value).strip()
            elif tag_name == "DateTimeOriginal":
                exif.date_taken = str(value)
            elif tag_name == "DateTime":
                if not exif.date_taken:
                    exif.date_taken = str(value)
            elif tag_name == "ImageWidth":
                exif.image_width = int(value)
            elif tag_name == "ImageLength":
                exif.image_height = int(value)
            elif tag_name == "Orientation":
                exif.orientation = int(value)
            elif tag_name == "GPSInfo":
                for gps_tag_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                    gps_info[gps_tag_name] = gps_value

        # Process GPS data
        if "GPSLatitude" in gps_info and "GPSLatitudeRef" in gps_info:
            exif.gps_latitude = _convert_gps_to_decimal(
                gps_info["GPSLatitude"], gps_info["GPSLatitudeRef"]
            )
        if "GPSLongitude" in gps_info and "GPSLongitudeRef" in gps_info:
            exif.gps_longitude = _convert_gps_to_decimal(
                gps_info["GPSLongitude"], gps_info["GPSLongitudeRef"]
            )
        if "GPSAltitude" in gps_info:
            try:
                exif.gps_altitude = float(gps_info["GPSAltitude"])
            except (TypeError, ValueError):
                pass

        return exif

    except Exception as e:
        logger.warning("Failed to extract EXIF from %s: %s", image_path, e)
        return None


def compute_file_hashes(file_path: str) -> tuple[str, str]:
    """Compute MD5 and SHA-256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def generate_reverse_search_urls(image_path: str) -> list[str]:
    """
    Generate URLs for reverse image search services.
    Note: These require manual browser upload — returned as helper links.
    """
    return [
        "https://www.google.com/imghp?hl=en (Google Images - upload)",
        "https://tineye.com/ (TinEye - upload)",
        "https://yandex.com/images/ (Yandex Images - upload)",
        "https://lens.google.com/ (Google Lens - upload)",
    ]


def analyze_image(image_path: str) -> ImageAnalysis:
    """
    Perform image OSINT analysis.

    Extracts:
    - File hashes (MD5, SHA-256)
    - EXIF metadata (camera, GPS, date)
    - Image dimensions and format
    - Reverse image search links
    """
    path = Path(image_path)
    result = ImageAnalysis(file_path=str(path.resolve()))

    if not path.exists():
        result.risk_indicators.append("file_not_found")
        return result

    # File hashes
    result.file_hash_md5, result.file_hash_sha256 = compute_file_hashes(image_path)
    result.file_size_bytes = path.stat().st_size

    # Image properties
    try:
        img = Image.open(image_path)
        result.image_format = img.format or "unknown"
        result.dimensions = img.size
    except Exception as e:
        result.risk_indicators.append(f"image_open_failed: {e}")
        return result

    # EXIF extraction
    exif = extract_exif(image_path)
    if exif:
        result.has_exif = True
        result.exif = exif

        if exif.has_gps():
            result.risk_indicators.append("contains_gps_coordinates")

        # Check for common stock photo camera models
        stock_indicators = ["shutterstock", "getty", "istock", "adobe stock"]
        if exif.software:
            for indicator in stock_indicators:
                if indicator in exif.software.lower():
                    result.is_stock_photo = True
                    result.risk_indicators.append("possible_stock_photo")
                    break
    else:
        # Stripped EXIF might indicate intentional privacy
        result.risk_indicators.append("no_exif_metadata")

    # Reverse search URLs
    result.reverse_search_urls = generate_reverse_search_urls(image_path)

    logger.info(
        "Image analysis complete: %s → format=%s, dims=%s, has_exif=%s, has_gps=%s",
        image_path, result.image_format, result.dimensions,
        result.has_exif, result.exif.has_gps() if result.exif else False
    )
    return result


def get_discovered_artifacts(analysis: ImageAnalysis) -> list[dict]:
    """Extract new artifacts from image analysis."""
    artifacts = []
    if analysis.exif and analysis.exif.has_gps():
        artifacts.append({
            "type": "location",
            "value": f"{analysis.exif.gps_latitude},{analysis.exif.gps_longitude}",
            "source": "image_exif_gps",
            "confidence": 0.8,
        })
    return artifacts
