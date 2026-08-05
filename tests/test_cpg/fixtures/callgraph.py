"""Sample Python file for call-graph testing.

Exercises: simple calls, method calls, chains, recursion, unresolved calls,
nested functions, lambdas, and decorated functions.
"""

import os
from typing import Optional

# ── Module-level functions ─────────────────────────────────────────────


def helper(x: int) -> int:
    """A utility called by several functions."""
    return x * 2


def compute(a: int, b: int) -> int:
    """Calls helper then a built-in."""
    result = helper(a)
    print(f"debug: {result}")  # print is unresolved
    return helper(b) + result


def recursive_fib(n: int) -> int:
    """Recursive call to self — should create a self-loop edge."""
    if n <= 1:
        return n
    return recursive_fib(n - 1) + recursive_fib(n - 2)


def calls_external() -> None:
    """Calls to builtins and external functions — all unresolved."""
    data = os.path.join("/tmp", "file.txt")  # os.path.join → 'join'
    print(len(data))  # print, len → both unresolved


def no_calls(x: int) -> int:
    """A leaf function — produces zero call edges."""
    return x + 1


# ── Class with method calls ────────────────────────────────────────────


class DataService:
    """Service class exercising intra-class method calls."""

    def __init__(self, db_url: str) -> None:
        self.db_url = db_url

    def connect(self) -> bool:
        """Simulate connecting — called by query()."""
        return self.db_url != ""

    def query(self, sql: str) -> Optional[str]:
        """Calls self.connect() and external db.execute()."""
        if not self.connect():  # resolved: self.connect → connect
            return None
        return self.db.execute(sql)  # unresolved: self.db.execute → execute

    def batch_query(self, sqls: list[str]) -> list[str]:
        """Calls self.query() in a loop — chain: batch_query→query→connect."""
        results: list[str] = []
        for sql in sqls:
            result = self.query(sql)  # resolved: self.query → query
            if result is not None:
                results.append(result)
        return results

    def fallback(self) -> str:
        """Calls an external function only."""
        return fetch_from_cache("users")  # unresolved: bare call


# ── Decorated functions ────────────────────────────────────────────────


def with_decorator(fn):
    """A decorator that wraps a function."""
    return fn


@with_decorator
def decorated_func(value: str) -> str:
    """Calls helper from within a decorated function."""
    doubled = helper(len(value))  # resolved
    return str(doubled)


# ── Nested functions ───────────────────────────────────────────────────


def outer(x: int) -> int:
    """Contains a nested function that makes calls."""

    def inner(y: int) -> int:
        """Calls helper and built-ins — should be attributed to 'inner'."""
        val = helper(y)  # resolved
        print(val)  # unresolved
        return val + 1

    # outer itself calls helper AND the nested inner
    base = helper(x)  # resolved: outer → helper
    return inner(base)  # call to inner — should we resolve this?


# ── Lambda ─────────────────────────────────────────────────────────────


def uses_lambda(items: list[int]) -> list[int]:
    """Calls inside a lambda should be attributed to the enclosing function."""
    transform = lambda n: helper(n) + 1  # noqa: E731 — call in lambda → 'uses_lambda'
    return [transform(i) for i in items]


# ── Edge case: function that shadows a builtin ─────────────────────────


def max_value(x: int, y: int) -> int:
    """Function named 'max_value' — ensure it doesn't match 'max' builtin."""
    return compute(x, y)  # resolved: max_value → compute
