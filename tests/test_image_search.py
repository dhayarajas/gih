"""Tests for image OSINT module."""


import pytest
from PIL import Image

from src.modules.image_search import (
    analyze_image,
    compute_file_hashes,
    ImageAnalysis,
)


@pytest.fixture
def sample_image(tmp_path):
    """Create a sample test image."""
    img_path = tmp_path / "test_image.png"
    img = Image.new("RGB", (100, 100), color="red")
    img.save(str(img_path))
    return str(img_path)


@pytest.fixture
def sample_jpeg(tmp_path):
    """Create a sample JPEG image (EXIF-capable format)."""
    img_path = tmp_path / "test_image.jpg"
    img = Image.new("RGB", (200, 200), color="blue")
    img.save(str(img_path), "JPEG")
    return str(img_path)


class TestImageAnalysis:
    """Test image analysis functionality."""

    def test_basic_image_analysis(self, sample_image):
        """Should extract basic image properties."""
        result = analyze_image(sample_image)
        assert result.file_hash_md5 != ""
        assert result.file_hash_sha256 != ""
        assert result.dimensions == (100, 100)
        assert result.image_format == "PNG"
        assert result.file_size_bytes > 0

    def test_nonexistent_file(self):
        """Should handle missing files gracefully."""
        result = analyze_image("/nonexistent/path/image.png")
        assert "file_not_found" in result.risk_indicators

    def test_jpeg_analysis(self, sample_jpeg):
        """Should analyze JPEG format."""
        result = analyze_image(sample_jpeg)
        assert result.image_format == "JPEG"
        assert result.dimensions == (200, 200)

    def test_no_exif_flagged(self, sample_image):
        """PNG without EXIF should be flagged."""
        result = analyze_image(sample_image)
        assert "no_exif_metadata" in result.risk_indicators

    def test_returns_image_analysis(self, sample_image):
        """Should return ImageAnalysis type."""
        result = analyze_image(sample_image)
        assert isinstance(result, ImageAnalysis)

    def test_to_dict(self, sample_image):
        """to_dict should include all fields."""
        result = analyze_image(sample_image)
        d = result.to_dict()
        assert "file_hash_md5" in d
        assert "file_hash_sha256" in d
        assert "dimensions" in d
        assert "risk_indicators" in d

    def test_reverse_search_urls_generated(self, sample_image):
        """Should generate reverse search helper URLs."""
        result = analyze_image(sample_image)
        assert len(result.reverse_search_urls) > 0


class TestFileHashes:
    """Test file hash computation."""

    def test_consistent_hashes(self, sample_image):
        """Same file should always produce same hashes."""
        md5_1, sha256_1 = compute_file_hashes(sample_image)
        md5_2, sha256_2 = compute_file_hashes(sample_image)
        assert md5_1 == md5_2
        assert sha256_1 == sha256_2

    def test_hash_format(self, sample_image):
        """Hashes should be hex strings of correct length."""
        md5, sha256 = compute_file_hashes(sample_image)
        assert len(md5) == 32
        assert len(sha256) == 64
        assert all(c in "0123456789abcdef" for c in md5)
