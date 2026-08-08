"""Minimal control-flow patterns for CFG builder tests.

Each function is deliberately kept small so that block boundaries and
edge counts are easy to assert against in the test suite.
"""


def straight_line():
    """A single basic-block function: no branches, no loops."""
    a = 1
    b = 2
    c = a + b
    return c


def if_else(x):
    """If / else — three blocks: condition, then, else."""
    if x > 0:
        a = "positive"
        return a
    else:
        b = "non-positive"
        return b


def if_without_else(x):
    """If without else — fallthrough to after-if code."""
    result = 0
    if x > 0:
        result = 1
    return result


def while_loop(n):
    """While loop — loop header, body, exit."""
    total = 0
    i = 0
    while i < n:
        total += i
        i += 1
    return total


def for_loop(items):
    """For loop — header, body, exit."""
    result = []
    for item in items:
        result.append(item)
    return result


def break_in_loop(items):
    """Break inside a loop."""
    found = None
    for item in items:
        if item > 10:
            found = item
            break
    return found


def continue_in_loop(items):
    """Continue inside a loop."""
    total = 0
    for item in items:
        if item < 0:
            continue
        total += item
    return total


def nested_if(a, b):
    """Nested if — branches within branches."""
    if a > 0:
        if b > 0:
            return "both positive"
        else:
            return "a positive, b non-positive"
    else:
        if b > 0:
            return "a non-positive, b positive"
        else:
            return "both non-positive"


def multiple_returns(x):
    """Multiple returns from different blocks."""
    if x < 0:
        return -1
    if x == 0:
        return 0
    return 1


def try_except_finally():
    """Try / except / finally control flow."""
    try:
        x = 1 / 0
    except ZeroDivisionError:
        x = 0
    finally:
        x = -1
    return x


def empty_function():
    """Function with no body statements."""
    pass


def early_return(x):
    """Return in the middle of a function."""
    if x is None:
        return None
    result = x * 2
    return result


def nested_loops(matrix):
    """Nested for loops — two-level break/continue context."""
    total = 0
    for row in matrix:
        for cell in row:
            if cell < 0:
                continue
            total += cell
        if total > 100:
            break
    return total
