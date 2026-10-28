// A fake fetch for the GitHub client: routes keyed "METHOD /path" return canned responses, and
// every request is recorded (method, path, query, parsed JSON body) so a test can assert exactly
// what would have reached GitHub. An unrouted request is a 404 and is recorded too.
import type { FetchLike } from '../src/github-api.ts';

export interface RecordedCall {
  method: string;
  path: string;
  query: string;
  body: unknown;
  headers: Record<string, string>;
}

export type Canned = { status?: number; json?: unknown; headers?: Record<string, string> } | ((call: RecordedCall) => { status?: number; json?: unknown; headers?: Record<string, string> });

export interface Fake {
  fetch: FetchLike;
  calls: RecordedCall[];
  /** Calls to one route, e.g. `of('POST /repos/o/r/check-runs')`. */
  of(route: string): RecordedCall[];
}

export function fakeFetch(routes: Record<string, Canned>): Fake {
  const calls: RecordedCall[] = [];
  const fetch: FetchLike = async (input, init) => {
    const url = new URL(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(init?.headers ?? {})) headers[k.toLowerCase()] = String(v);
    const body = typeof init?.body === 'string' && init.body.length ? JSON.parse(init.body) : undefined;
    const call: RecordedCall = { method, path: url.pathname, query: url.search.replace(/^\?/, ''), body, headers };
    calls.push(call);
    const route = routes[`${method} ${url.pathname}`];
    const canned = route === undefined ? { status: 404, json: { message: `no route for ${method} ${url.pathname}` } } : typeof route === 'function' ? route(call) : route;
    const status = canned.status ?? 200;
    return new Response(canned.json === undefined ? null : JSON.stringify(canned.json), {
      status,
      headers: { 'content-type': 'application/json', ...(canned.headers ?? {}) },
    });
  };
  return { fetch, calls, of: (route) => calls.filter((c) => `${c.method} ${c.path}` === route) };
}
