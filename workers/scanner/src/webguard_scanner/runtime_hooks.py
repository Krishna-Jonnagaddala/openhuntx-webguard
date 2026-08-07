"""Generic pre/post request hooks used by higher-level runtime safety policy."""

from __future__ import annotations

from typing import Callable

from .safe_http import SafeHttpResponse
from .scope_validator import ValidatedTarget

BeforeRequestHook = Callable[[ValidatedTarget, str], None]
AfterRequestHook = Callable[[ValidatedTarget, str, SafeHttpResponse | None, str | None], None]

__all__ = ["AfterRequestHook", "BeforeRequestHook"]
