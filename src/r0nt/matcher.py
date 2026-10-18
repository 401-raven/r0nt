"""Path pattern matching for exclude rules (SPEC_PHASE2 §2).

Provides gitignore-style glob pattern matching against canonical relative paths.
"""

from __future__ import annotations

import re


def _glob_to_regex(pat: str) -> re.Pattern:
    """Translate a glob pattern into a compiled regex Pattern.

    Supports:
      - '*' matches any characters within a path component (excluding '/').
      - '**' matches any characters including '/'.
      - '?' matches a single character (excluding '/').
      - Patterns without '/' match against either the whole path or the filename.
    """
    pat = pat.strip().replace('\\', '/')
    pat = pat.lstrip('/')
    has_slash = '/' in pat

    i = 0
    n = len(pat)
    res: list[str] = []

    while i < n:
        c = pat[i]
        if c == '*':
            if i + 1 < n and pat[i + 1] == '*':
                # '**'
                i += 2
                if i < n and pat[i] == '/':
                    i += 1
                    res.append('(?:.*/)?')
                else:
                    res.append('.*')
                continue
            else:
                res.append('[^/]*')
                i += 1
                continue
        elif c == '?':
            res.append('[^/]')
            i += 1
            continue
        elif c in r'\[]{}()^$+.|':
            res.append('\\' + c)
            i += 1
            continue
        else:
            res.append(c)
            i += 1

    pattern_body = ''.join(res)
    if not has_slash:
        # Match filename at any nesting level, or entire string
        full_regex = f'^(?:.*/)?{pattern_body}$'
    else:
        full_regex = f'^{pattern_body}$'

    return re.compile(full_regex, re.IGNORECASE)


class PathMatcher:
    """Matches canonical paths against a set of glob patterns."""

    def __init__(self, patterns: list[str] | None = None) -> None:
        self.patterns = patterns or []
        self._compiled: list[re.Pattern] = []
        for p in self.patterns:
            p = p.strip()
            if p and not p.startswith('#'):
                self._compiled.append(_glob_to_regex(p))

    def matches(self, canonical_path: str) -> bool:
        """Return True if canonical_path matches any configured pattern."""
        if not self._compiled:
            return False
        normalized = canonical_path.replace('\\', '/').lstrip('/')
        for regex in self._compiled:
            if regex.match(normalized):
                return True
        return False
