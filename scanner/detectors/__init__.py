"""Detection modules for the scanner."""

from . import error_based
from . import union_based
from . import boolean_based
from . import time_based
from . import oob_based

__all__ = [
    "error_based",
    "union_based",
    "boolean_based",
    "time_based",
    "oob_based",
]
