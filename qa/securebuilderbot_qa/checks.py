"""The QA gate's diff analyzers (PRD § The QA gate, checks 1, 3 and 4), as pure functions over what a range added.

- A skipped test added in the range is a blocking finding unless a commit touching that file names
  a ticket. The patterns are the floor guard's, in Python.
- A route added or changed in the range needs a test that references its path and asserts an
  unauthenticated rejection, and, when the route carries an id parameter, a cross-user denial.
- A mocked database module inside a test on an integration path proves the mock, not the code.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from .coverage_changed import is_test_path, production_files

# ── 1. skipped tests ───────────────────────────────────────────────────────────
SKIP = re.compile(
    r"\b(?:it|test|describe|context|suite)\.(?:skip|only|todo)(?:\.each)?\s*[(`]|\b[xf](?:it|describe|test)\("
    r"|@pytest\.mark\.(?:skip|skipif|xfail)\b|\bpytest\.(?:skip|xfail|importorskip)\(|\bt\.Skip\(|\bunittest\.skip|^\s*@skip\b"
)
COMMENT = re.compile(r"^\s*(#|//|/\*|\*)")
TICKET = re.compile(r"\bT-(?:[A-Z][A-Z0-9]*-\d{2,}|\d{3,})\b|(?:^|[\s(])#\d+\b|\b[A-Z]{2,}-\d+\b", re.M)


@dataclass(frozen=True)
class Site:
    path: str
    line: int
    text: str
    detail: str = ""


def has_ticket_reference(messages: Iterable[str]) -> bool:
    """A ticket id (T-QA-07, T-123, ABC-42) or an issue number (#123) in any of the commit messages."""
    return any(TICKET.search(m) for m in messages)


def added_skips(added: Mapping[str, Mapping[int, str]], excused: Callable[[str], bool]) -> list[Site]:
    """Skipped, focused or expected-to-fail tests the range added to test files, minus files a ticket excuses."""
    out: list[Site] = []
    for path in sorted(added):
        if not is_test_path(path) or excused(path):
            continue
        for n, text in sorted(added[path].items()):
            if SKIP.search(text) and not COMMENT.match(text):
                out.append(Site(path, n, text.strip(), "a skipped test added without a ticket reference in the commit"))
    return out


# ── 3. routes and their negative tests ─────────────────────────────────────────
ROUTE_JS = re.compile(r"\.(?:get|post|put|patch|delete|del|all|head|options)\(\s*[`'\"](/[^`'\"]*)[`'\"]")
ROUTE_PY = re.compile(
    r"@[\w.]+\.(?:get|post|put|patch|delete|route|api_route|options|head)\(\s*['\"]([^'\"]+)['\"]"
    r"|@route\(\s*['\"]([^'\"]+)['\"]|\b(?:re_)?path\(\s*r?['\"]([^'\"]+)['\"]"
)
PARAM = re.compile(r":\w+|\{\w+\}|<[^>]+>")
AUTH_REJECT = re.compile(r"\b40[13]\b|Unauthori[sz]ed|Forbidden|PermissionDenied|NotAuthenticated")
CROSS_USER = re.compile(r"user\s?_?b(?![a-z0-9])|(?:other|another|second|foreign|cross)[-_ ]?(?:user|owner|tenant|account|org)"
                        r"|not[-_ ](?:the[-_ ])?owner|someone else", re.I)


@dataclass(frozen=True)
class Route:
    path: str
    line: int
    route: str
    has_id: bool


@dataclass(frozen=True)
class RouteGap:
    route: Route
    missing: str
    tests: tuple[str, ...] = ()  # the test files that reference the route, if any


def added_routes(added: Mapping[str, Mapping[int, str]]) -> list[Route]:
    """Route definitions on lines the range added to production files: Express/Koa/Fastify, FastAPI/Flask/Django, and `@route(...)`."""
    out: list[Route] = []
    for path in production_files(sorted(added)):
        for n, text in sorted(added[path].items()):
            if COMMENT.match(text):
                continue
            m = ROUTE_JS.search(text) or ROUTE_PY.search(text)
            if m:
                route = next(g for g in m.groups() if g)
                out.append(Route(path, n, route, bool(PARAM.search(route))))
    return out


def route_pattern(route: str) -> re.Pattern:
    """A pattern a test's request to the route would match: parameters take any one segment, the leading slash is optional."""
    parts = [p for p in route.strip().lstrip("^").rstrip("$").strip("/").split("/") if p]
    body = "/".join("[^/'\"`\\s?#]+" if PARAM.fullmatch(p) else re.escape(p) for p in parts)
    return re.compile(r"(?<![\w])/" + body + r"/?(?=[?'\"`\s#)]|$)")


CASE_START = re.compile(r"^\s*(?:async\s+)?def\s+test_|^\s*(?:it|test|describe|context)(?:\.\w+)*\s*\(", re.M)


def test_cases(text: str) -> list[str]:
    """A test file split into its cases, so a route reference and the assertion about it must sit in the same test."""
    starts = [m.start() for m in CASE_START.finditer(text)]
    if not starts:
        return [text]
    return [text[a:b] for a, b in zip(starts, [*starts[1:], len(text)], strict=False)]


def routes_without_negative_tests(routes: Iterable[Route], tests: Mapping[str, str]) -> list[RouteGap]:
    """Each route with no test case that names it and asserts 401/403; an id-carrying route also needs a case showing a cross-user denial."""
    cases = {p: test_cases(text) for p, text in tests.items()}
    gaps: list[RouteGap] = []
    for r in routes:
        pat = route_pattern(r.route)
        naming: set[str] = set()
        rejects = cross = False
        for p, chunks in cases.items():
            for case in chunks:
                if pat.search(case):
                    naming.add(p)
                    rejects = rejects or bool(AUTH_REJECT.search(case))
                    cross = cross or bool(CROSS_USER.search(case))
        named = tuple(sorted(naming))
        if not named:
            gaps.append(RouteGap(r, f"no test references {r.route}"))
        elif not rejects:
            gaps.append(RouteGap(r, f"no test referencing {r.route} asserts an unauthenticated rejection (401/403)", named))
        elif r.has_id and not cross:
            gaps.append(RouteGap(r, f"no test referencing {r.route} shows user A denied user B's record (cross-user denial)", named))
    return gaps


# ── 4. a mocked database on an integration path ────────────────────────────────
MOCK_JS = re.compile(r"\b(?:jest|vi)\.mock\(\s*['\"]([^'\"]+)['\"]")
MOCK_PY = re.compile(r"(?:@|\b(?:mock\.)?)patch(?:\.object)?\(\s*['\"]([^'\"]+)['\"]")
DB_MODULE = re.compile(r"(?:^|[^a-z])(?:db|database|prisma|knex|pg|sequelize|mongoose|sqlalchemy|typeorm|drizzle|mongo)(?:[^a-z]|$)", re.I)
# An inner directory, never the app itself: an app named api/ holds unit tests too.
INTEGRATION_DIR = re.compile(r"(?<=/)(integration|e2e|api|acceptance)(?=/)", re.I)
SERVER_IMPORT = re.compile(r"""from\s+['"][^'"]*(?:server|app|main|index)['"]|require\(\s*['"][^'"]*(?:server|app|main)['"]\)"""
                           r"""|^\s*from\s+\S*(?:server|app|main)\b\S*\s+import|^\s*import\s+\S*(?:server|app)\b""", re.M)


def mocked_db_sites(added: Mapping[str, Mapping[int, str]], file_text: Callable[[str], str]) -> list[Site]:
    """jest.mock / vi.mock / unittest.mock.patch of a database module, on an added line of a test under an integration, e2e or api directory or one that imports the app's server."""
    out: list[Site] = []
    for path in sorted(added):
        if not is_test_path(path):
            continue
        integration = bool(INTEGRATION_DIR.search(path)) or bool(SERVER_IMPORT.search(file_text(path)))
        if not integration:
            continue
        for n, text in sorted(added[path].items()):
            m = MOCK_JS.search(text) or MOCK_PY.search(text)
            if m and DB_MODULE.search(m.group(1)) and not COMMENT.match(text):
                out.append(Site(path, n, text.strip(), m.group(1)))
    return out
