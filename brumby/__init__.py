try:
    from ._version import __version__
except ImportError:  # pragma: no cover
    __version__ = "dev"

from .analyze import check_package, get_artifacts
from .compare import DiffCallback, compare_releases
from .finding import Finding
from .registry import get_finders, register

__all__ = [
    "__version__",
    "check_package",
    "compare_releases",
    "get_artifacts",
    "get_finders",
    "register",
    "DiffCallback",
    "Finding",
]
