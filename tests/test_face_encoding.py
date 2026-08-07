"""Tests for how the face encoder hands an image to dlib.

dlib is native code: given the wrong buffer, or called from two threads at
once, it aborts the whole investigation instead of raising.
"""

import io
import sys
import threading
import time
import types

import numpy as np
import pytest
from PIL import Image

from src.modules import image_match


class _Response:
    def __init__(self, content):
        self.status_code = 200
        self.content = content


def _png(mode, colour):
    buffer = io.BytesIO()
    Image.new(mode, (8, 8), color=colour).save(buffer, "PNG")
    return buffer.getvalue()


@pytest.fixture
def fake_dlib(monkeypatch):
    """Stand in for face_recognition, recording what it is handed."""
    seen = {"arrays": [], "concurrent": False}
    running = threading.Event()

    def face_encodings(array):
        if running.is_set():
            seen["concurrent"] = True
        running.set()
        seen["arrays"].append(array)
        time.sleep(0.02)  # widen the window a second caller would land in
        running.clear()
        return [np.zeros(128)]

    module = types.ModuleType("face_recognition")
    module.face_encodings = face_encodings
    monkeypatch.setitem(sys.modules, "face_recognition", module)
    return seen


@pytest.fixture
def serve(monkeypatch):
    """Serve the given bytes for any image URL."""
    def _serve(content):
        session = types.SimpleNamespace(get=lambda url, timeout=10: _Response(content))
        monkeypatch.setattr(image_match, "get_http_session", lambda: session)
    return _serve


class TestBufferHandedToDlib:

    @pytest.mark.parametrize("mode,colour", [
        ("P", 3), ("L", 128), ("RGBA", (1, 2, 3, 4)), ("I;16", 300),
    ])
    def test_any_image_arrives_as_8_bit_rgb(self, mode, colour, fake_dlib, serve):
        """dlib reads the buffer as RGB whatever the array actually is."""
        serve(_png(mode, colour))

        assert image_match.extract_face_encoding("https://example.com/a.png") is not None

        array = fake_dlib["arrays"][0]
        assert array.dtype == np.uint8
        assert array.shape == (8, 8, 3)
        assert array.flags["C_CONTIGUOUS"]


class TestConcurrency:

    def test_threads_do_not_reach_dlib_together(self, fake_dlib, serve):
        """A run matches several images per artifact, across artifacts."""
        serve(_png("RGB", (10, 20, 30)))

        threads = [
            threading.Thread(
                target=image_match.extract_face_encoding,
                args=(f"https://example.com/{n}.png",),
            )
            for n in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(fake_dlib["arrays"]) == 8
        assert not fake_dlib["concurrent"]
