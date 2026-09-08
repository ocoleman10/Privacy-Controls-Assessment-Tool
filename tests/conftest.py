import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def sample_target() -> Path:
    """The synthetic fixture tree under sample_target/ — see its README.md."""
    return REPO_ROOT / "sample_target"
