"""The QA gate's three diff analyzers: skips added, routes without a negative test, a mocked database on an integration path.

The skip-shaped strings below are assembled from pieces, so this file's own lines never look like
a skipped test to the floor guard, which reads every added line.
"""

from __future__ import annotations

from securebuilderbot_qa.checks import (
    Route,
    added_routes,
    added_skips,
    has_ticket_reference,
    mocked_db_sites,
    route_pattern,
    routes_without_negative_tests,
)

DOT = "."
IT_SKIP = "it" + DOT + "skip('later', () => {})"
ONLY = "it" + DOT + "only('just me', () => {})"
XIT = "x" + "it('never', () => {})"
MARK_SKIP = "@pytest.mark" + DOT + "skip(reason='flaky')"
PY_SKIP = "    pytest" + DOT + "skip('no db')"
XFAIL = "@pytest.mark" + DOT + "xfail"


def test_added_skips_are_found_in_test_files_only_and_excused_by_a_ticket():
    added = {
        "api/src/__tests__/a.test.ts": {3: IT_SKIP, 9: ONLY, 12: XIT, 14: "it('fine', () => {})"},
        "pkg/tests/test_b.py": {1: MARK_SKIP, 5: PY_SKIP, 8: XFAIL, 9: "def test_ok(): pass"},
        "pkg/service.py": {2: "def skip(x): return x"},
        "docs/notes.md": {1: IT_SKIP},
    }
    sites = added_skips(added, excused=lambda path: False)
    assert [(s.path, s.line) for s in sites] == [
        ("api/src/__tests__/a.test.ts", 3), ("api/src/__tests__/a.test.ts", 9), ("api/src/__tests__/a.test.ts", 12),
        ("pkg/tests/test_b.py", 1), ("pkg/tests/test_b.py", 5), ("pkg/tests/test_b.py", 8),
    ]
    excused = added_skips(added, excused=lambda path: path.endswith(".py"))
    assert all(s.path.endswith(".ts") for s in excused) and len(excused) == 3


def test_a_ticket_reference_is_a_ticket_id_or_an_issue_number():
    assert has_ticket_reference(["skip the flaky one for now\n\nT-QA-07 tracks the fix"])
    assert has_ticket_reference(["quarantine (see #123)"]) and has_ticket_reference(["ABC-42: quarantine"])
    assert not has_ticket_reference(["skip it", "temporary"]) and not has_ticket_reference([])


def test_added_routes_are_read_from_express_fastapi_flask_django_and_the_fixture_framework():
    added = {
        "api/src/routes/items.ts": {4: "router.get('/items/:id', requireAuth, getItem)", 8: "app.post(\"/items\", create)",
                                    9: "router.use(helmet())", 10: "fastify.delete(`/items/:id/tags/:tag`, h)"},
        "svc/main.py": {3: '@app.get("/users/{user_id}")', 7: "@router.post('/users')", 11: "@route(\"/items/{id}\")",
                        15: "@bp.route('/health')", 20: "    path('orders/<int:pk>/', views.order),", 22: "re_path(r'^legacy/$', v)"},
        "api/src/__tests__/items.test.ts": {1: "router.get('/not/a/route')"},
        "README.md": {1: "router.get('/docs')"},
    }
    routes = added_routes(added)
    assert [(r.path, r.line, r.route, r.has_id) for r in routes] == [
        ("api/src/routes/items.ts", 4, "/items/:id", True), ("api/src/routes/items.ts", 8, "/items", False),
        ("api/src/routes/items.ts", 10, "/items/:id/tags/:tag", True),
        ("svc/main.py", 3, "/users/{user_id}", True), ("svc/main.py", 7, "/users", False), ("svc/main.py", 11, "/items/{id}", True),
        ("svc/main.py", 15, "/health", False), ("svc/main.py", 20, "orders/<int:pk>/", True), ("svc/main.py", 22, "^legacy/$", False),
    ]


def test_route_patterns_match_the_paths_a_test_would_use():
    assert route_pattern("/items/:id").search("await request(app).get('/items/42')")
    assert route_pattern("/items/{id}").search('client.get("/items/abc")')
    assert route_pattern("orders/<int:pk>/").search("self.client.get('/orders/7/')")
    assert not route_pattern("/items/:id").search("get('/items')") and not route_pattern("/items").search("get('/item')")
    assert route_pattern("/items").search("get('/items/')") and route_pattern("/items").search("get('/items?x=1')")


def test_routes_need_a_test_that_names_them_and_asserts_a_rejection():
    routes = [Route("api/r.ts", 4, "/items/:id", True), Route("api/r.ts", 8, "/items", False),
              Route("api/r.ts", 9, "/health", False), Route("api/r.ts", 12, "/users/:id", True)]
    tests = {
        "api/__tests__/items.test.ts": "it('401 without a token', async () => { expect((await get('/items/1')).status).toBe(401) })\n"
                                       "it('user A cannot read user B', async () => { expect((await as(a).get(`/items/${bItem}`)).status).toBe(403) })\n",
        "api/__tests__/list.test.ts": "it('lists', async () => { expect((await get('/items')).status).toBe(200) })\n",
        "api/__tests__/users.test.ts": "it('needs a token', async () => { expect((await get('/users/1')).status).toBe(401) })\n",
    }
    gaps = routes_without_negative_tests(routes, tests)
    assert [(g.route.route, g.missing) for g in gaps] == [
        ("/items", "no test referencing /items asserts an unauthenticated rejection (401/403)"),
        ("/health", "no test references /health"),
        ("/users/:id", "no test referencing /users/:id shows user A denied user B's record (cross-user denial)"),
    ]


def test_mocked_db_counts_only_on_an_integration_path():
    added = {
        "api/test/integration/orders.test.ts": {2: "jest.mock('../../src/db')", 3: "jest.mock('./helpers')"},
        "api/test/unit/orders.test.ts": {2: "jest.mock('../../src/db')"},
        "api/test/unit/server.test.ts": {1: "import { app } from '../../src/server'", 2: "vi.mock('@prisma/client')"},
        "svc/tests/e2e/test_flow.py": {4: "@patch('svc.database.session')", 6: "mock.patch('svc.sqlalchemy_session')", 7: "patch('svc.clock')"},
        "svc/tests/test_unit.py": {4: "@patch('svc.db')"},
        "svc/service.py": {1: "jest.mock('db')"},
    }
    texts = {k: "\n".join(v.values()) for k, v in added.items()}
    sites = mocked_db_sites(added, lambda p: texts.get(p, ""))
    assert [(s.path, s.line, s.detail) for s in sites] == [
        ("api/test/integration/orders.test.ts", 2, "../../src/db"),
        ("api/test/unit/server.test.ts", 2, "@prisma/client"),
        ("svc/tests/e2e/test_flow.py", 4, "svc.database.session"),
        ("svc/tests/e2e/test_flow.py", 6, "svc.sqlalchemy_session"),
    ]
