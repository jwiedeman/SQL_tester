"""Detection modules for the scanner."""

from . import error_based
from . import union_based
from . import boolean_based

__all__ = ["error_based", "union_based", "boolean_based"]
