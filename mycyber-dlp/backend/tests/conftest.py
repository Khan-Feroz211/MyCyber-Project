"""
Pytest configuration for MyCyber DLP backend tests.

Sets HuggingFace offline mode so tests never make real network requests
to huggingface.co. All NER model calls are mocked at the _hf_pipeline level.
"""
import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def hf_offline_mode():
    """Force HuggingFace hub into offline mode for all tests."""
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
