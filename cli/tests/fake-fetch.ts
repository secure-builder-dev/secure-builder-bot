// A fake fetch: routes keyed "METHOD /path" return canned JSON, and every request is recorded (url,
// method, path, lower-cased headers, parsed body) so a test can assert exactly what would have left
// the machine. An unrouted request is a 404, recorded too.
import type { FetchLike } from "../src/io.ts";

export interface Recorded {
  url: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface Route {
  status?: number;
  json?: unknown;
}

export function fakeFetch(routes: Record<string, Route>): { fetch: FetchLike; calls: Recorded[]; of(route: string): Recorded[] } {
  const table = new Map(Object.entries(routes));
  const calls: Recorded[] = [];
  const fetch: FetchLike = (input, init) => {
    const url = new URL(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = Object.fromEntries(new Headers(init?.headers));
    const body: unknown = typeof init?.body === "string" && init.body !== "" ? JSON.parse(init.body) : undefined;
    calls.push({ url: url.origin + url.pathname, method, path: url.pathname, headers, body });
    const route = table.get(`${method} ${url.pathname}`) ?? { status: 404, json: { message: `no route for ${method} ${url.pathname}` } };
    return Promise.resolve(new Response(JSON.stringify(route.json ?? null), { status: route.status ?? 200, headers: { "content-type": "application/json" } }));
  };
  return { fetch, calls, of: (route) => calls.filter((c) => `${c.method} ${c.path}` === route) };
}
