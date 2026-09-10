try:
    from ._version import __version__
except ImportError:  # pragma: no cover
    __version__ = "dev"

from . import api
from .analyze import check_package, get_artifacts
from .compare import DiffCallback, compare_releases
from .finding import Finding
from .registry import get_finders, register

# The direct imports above remain available to old callers, but brumby.api is the
# supported library interface.
