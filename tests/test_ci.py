"""Basic CI health-check tests – no heavy dependencies required."""
import importlib.metadata
import sys


def test_python_version():
    """Ensure the runtime is Python 3.8 or newer."""
    assert sys.version_info >= (3, 8), (
        f"Python 3.8+ required, got {sys.version}"
    )


def test_flask_importable():
    """Ensure Flask>=2.0.0 is installed (listed in requirements.txt)."""
    version = importlib.metadata.version("flask")
    assert version
    major = int(version.split(".")[0])
    assert major >= 2, f"Flask 2.0+ required, got {version}"
