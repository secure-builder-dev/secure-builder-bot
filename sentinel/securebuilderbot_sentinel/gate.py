"""The Sentinel gate: the cold reviewer on the range core hands it (docs/PRD.md § The three gates).

1. The config: the file named by SB_CONFIG (the one `core/run run --config` was given), else
   `.securebuilderbot.yml` at the checkout's root. Core validated it before any gate ran; a config
   this gate cannot read is not_run. The `sentinel` section — provider, endpoint, model, key_secret,
   depth, the diff budget — is read from that file AT THE BASE COMMIT when the file is in the
   checkout, never from the pull request: otherwise a pull request could send the key to any host,
   or name another CI secret as the key (gate run 1, N-03). A pull request that changes the section
   is reported, and the base values are used. The base copy is read by blob id from the base
   commit's tree with refs/replace ignored, and a config that is a symbolic link — in the working
   tree, into or out of the checkout, or in the base commit — is refused (gate run 2, B-01).
2. The key: read from the environment variable `sentinel.key_secret` names. Missing or empty is
   not_run with the variable's NAME in the reason; the value is never logged, never in a receipt,
   never in a file under the run directory (`without_key`, CM-51), whatever the model echoes back.
3. The request (inputs.py), the review (review.py), the verdict: a blocking finding fails; a diff cut
   to the budget is yellow at best; an answer that cannot be read is not_run. Never a silent pass.

Every request and every answer is kept under the run directory as evidence (requests/, responses/),
and the receipt lists exactly which files were sent, to which provider and model.

When core runs the gates, steps 1 and 2 and every input of step 3 are read in `prepare`, which core
calls before any gate runs: QA runs the pull request's own suite in this checkout, as this user, and
nothing it leaves in the working tree or in .git reaches the review. The provider is built there too,
importing its modules, and the reviewer's instructions are read there from the bot's install, which the
job user can also write (gate run 3, B-01). Only QA's own evidence (what it proved) is read when the
gate runs. The receipt's `inputs_read` says which happened.
"""

from __future__ import annotations

import importlib
import os
import re
from dataclasses import dataclass, replace
from collections.abc import Callable, Mapping
from pathlib import Path

from securebuilderbot_core.config import ConfigError, SentinelConfig, load_config
from securebuilderbot_core.classify import classify
from securebuilderbot_core.gate import Finding, GateContext, GateResult
from securebuilderbot_core.receipt import redact

from . import review as rv
from .checklist import ChecklistError, gaps
from .inputs import ReviewRequest, Settings, build_request, tracked_blob, with_qa_evidence
from .providers import Provider, ProviderError, make_provider

CONFIG_FILE = ".securebuilderbot.yml"
KEY_REDACTED = "[redacted: model key]"
SENTINEL_KEYS = ("provider", "endpoint", "model", "key_secret", "depth", "max_diff_bytes")
# Standard-library modules the provider's request path imports on first use, not when the provider is
# built: ssl encodes the endpoint's host name with the idna codec on the first HTTPS request. Imported
# in prepare with the rest (gate run 3, B-01; measured against a real TLS endpoint).
LAZY_MODULES = ("encodings.idna",)
KEY_ALPHABET = re.compile(r"[!#-&(-\[\]-~]+")  # printable ASCII less space, quotes and backslash


def without_key(value: object, key: str) -> object:
    """CM-51: the structure with every occurrence of the model key replaced, in every string and key."""
    if not key:
        return value
    if isinstance(value, str):
        return value.replace(key, KEY_REDACTED)
    if isinstance(value, dict):
        return {without_key(k, key): without_key(v, key) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(without_key(v, key) for v in value)
    return value


def _clean(value: object, key: str) -> object:
    """The key removed, then every secret-shaped string redacted by core's rule, so the receipt core
    writes is never refused for what a model quoted back."""
    value = without_key(value, key)
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, dict):
        return {_clean(k, key): _clean(v, key) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_clean(v, key) for v in value)
    return value


def model_key(name: str, environ: Mapping[str, str]) -> str:
    """The key as it is used: the variable's value with surrounding whitespace (a stored newline) removed."""
    return environ.get(name, "").strip()


def missing_key(name: str, environ: Mapping[str, str]) -> str | None:
    """CM-58: why the gate cannot run for want of a usable key — the variable's NAME, never a value — or None.

    A usable key is printable ASCII with no space, quote or backslash once its surrounding whitespace is
    stripped. Anything else is refused rather than sent: a control character makes the transport raise
    with the header (and so the key) in its message, and a key outside that alphabet could reach an
    error message escaped, where without_key cannot recognise it (gate run 1, S-01)."""
    value = model_key(name, environ)
    if not value:
        return (f"the model key is not set: the environment has no {name} (the CI secret sentinel.key_secret names) — "
                "add it as a repository secret, or remove sentinel from gates")
    if not KEY_ALPHABET.fullmatch(value):
        return (f"the model key in {name} carries a control character, inner whitespace, a quote, a backslash or a "
                "non-ASCII character; it was not used, and its value is not shown — store the key alone")
    return None


def status_of(blocking: list, omitted: tuple[str, ...]) -> tuple[str, str]:
    """CM-57: a blocking finding fails the gate; a diff cut to the budget is yellow at best; otherwise a pass."""
    if blocking:
        first = blocking[0]
        where = f" at {first.path}:{first.line}" if first.path and first.line else (f" in {first.path}" if first.path else "")
        return "fail", f"{len(blocking)} blocking finding(s); first: {first.rule_id}{where} — {first.message}"
    if omitted:
        return "yellow", (f"the diff was over sentinel.max_diff_bytes; {len(omitted)} file(s) were not reviewed: "
                          f"{', '.join(omitted)}")
    return "pass", ""


def _stop(reason: str, receipt: dict, key: str = "", extra: dict | None = None) -> GateResult:
    return GateResult(gate="sentinel", status="not_run", reason=_clean(reason, key),
                      receipt=_clean({**receipt, **(extra or {})}, key))


def _in_checkout(path: Path, repo: Path) -> tuple[str | None, bool]:
    """(the config's repo-relative path, whether a symbolic link is involved), judged on the path as
    written and on the file it resolves to: a link in the checkout, or one between the checkout and
    outside it, is something the pull request's code could have planted."""
    lexical = Path(os.path.abspath(path))
    roots = (Path(os.path.abspath(repo)), repo.resolve())
    rel = next((lexical.relative_to(r).as_posix() for r in roots if lexical.is_relative_to(r)), None)
    resolved = path.resolve()
    rel_resolved = resolved.relative_to(roots[1]).as_posix() if resolved.is_relative_to(roots[1]) else None
    if rel is None and rel_resolved is None:
        return None, False
    return rel or rel_resolved, rel != rel_resolved  # a link at the path itself always resolves elsewhere


@dataclass(frozen=True)
class _Captured:
    """Everything the review needs, read at one moment: the settings, the key and the request."""
    ctx: GateContext
    config: object
    key: str
    req: ReviewRequest
    receipt: dict
    provider: Provider
    texts: rv.Instructions


class SentinelGate:
    name = "sentinel"

    def __init__(self, provider_factory: Callable[[SentinelConfig, str], Provider] = make_provider,
                 environ: Mapping[str, str] | None = None):
        self._factory = provider_factory
        self._environ = environ
        self._captured: tuple[GateContext, _Captured | GateResult] | None = None

    def _env(self) -> Mapping[str, str]:
        return os.environ if self._environ is None else self._environ

    def _configs(self, ctx: GateContext):
        """(the config the gate uses, the sentinel keys the pull request changed, its repo-relative path, an error).

        The config used is the head's with its `sentinel` section taken from the base commit's copy of
        the same file; a config outside the checkout is not the pull request's to change and is used whole."""
        raw = self._env().get("SB_CONFIG") or CONFIG_FILE
        path = Path(raw) if Path(raw).is_absolute() else ctx.repo / raw
        if not path.is_file():
            return None, [], None, f"no config at {raw}: the sentinel gate reads the file core/run was given (SB_CONFIG) or {CONFIG_FILE}"
        rel, linked = _in_checkout(path, ctx.repo)
        if linked:
            return None, [], rel, (f"the config {raw} is a symbolic link, or is reached through one, in the checkout: Sentinel "
                                   "refuses it rather than follow a link the pull request's code could have planted")
        try:
            head = load_config(path)
        except ConfigError as e:
            return None, [], None, f"the config could not be read: {e}"
        if rel is None:
            return head, [], None, ""
        ref = ctx.config_ref or ctx.base  # the target branch's tip, never the merge base the pull request chooses
        mode, data = tracked_blob(ctx.repo, ref, rel)
        if mode == "120000":
            return None, [], rel, (f"the config at {rel} is a symbolic link in the base commit {ref[:12]}: Sentinel reads "
                                   "its settings from a file in the base commit, never through a link")
        if data is None:
            return None, [], rel, (f"no config at {rel} in the base commit {ref[:12]}: the sentinel settings are read from "
                                   "the base, never from the pull request, so Sentinel runs once the config is merged")
        copy = ctx.run_dir / "config-at-base.yml"
        copy.write_bytes(data)
        try:
            base = load_config(copy)
        except ConfigError as e:
            return None, [], rel, f"the config at the base commit could not be read: {e}"
        changed = [f"sentinel.{k}" for k in sorted(SENTINEL_KEYS) if getattr(base.sentinel, k) != getattr(head.sentinel, k)]
        # Core's governing copy (the target tip's) decides every other setting, qa.manifest included: it
        # picks a file Sentinel reads and sends. Run on its own, outside core, the head's copy stands in.
        return replace(ctx.config if ctx.config is not None else head, sentinel=base.sentinel), changed, rel, ""

    def prepare(self, ctx: GateContext) -> None:
        """Core calls this before any gate runs: read the settings, the key and every input now, while
        the checkout and .git are as the CI left them (gate run 2, B-01). Never raises."""
        self._captured = (ctx, self._capture(ctx, "before any gate ran"))

    def run(self, ctx: GateContext) -> GateResult:
        if self._captured is not None and self._captured[0] == ctx:
            got = self._captured[1]
        else:  # not prepared (the gate run on its own, outside core's runner): read now
            got = self._capture(ctx, "when the sentinel gate ran")
        return got if isinstance(got, GateResult) else self._review(got)

    def _capture(self, ctx: GateContext, when: str) -> _Captured | GateResult:
        receipt: dict = {"sent_to_model_endpoint": [], "controls_assessed": [], "inputs_read": when}
        key = ""
        try:
            config, changed, config_rel, error = self._configs(ctx)
            if config is None:
                return _stop(error, receipt)
            receipt["config_file"] = config_rel
            if changed:
                receipt["config_changed_by_pr"] = changed
            name = config.sentinel.key_secret
            if not name:
                return _stop("sentinel.key_secret is not set in the config: name the CI secret that holds the model key", receipt)
            why = missing_key(name, self._env())
            if why:
                return _stop(why, receipt)
            key = model_key(name, self._env())
            if "sentinel.depth" in changed:  # core took the depth from the pull request's config; the base's decides
                ctx = replace(ctx, depth={"always-deep": "deep", "always-light": "light"}.get(config.sentinel.depth)
                              or classify(ctx.base, ctx.head, ctx.repo).depth)
            settings = Settings(config_path=config_rel, manifest=config.qa.manifest, max_diff_bytes=config.sentinel.max_diff_bytes)
            try:
                req = build_request(ctx, settings, self._env())
            except ChecklistError as e:
                return _stop(f"the checklist could not be read: {e}", receipt, key)
            # The reviewer's code and instructions come from the bot's install, which the job user can
            # write: the provider is built (its modules imported) and every instruction read now.
            try:
                provider = self._factory(config.sentinel, key)
            except ProviderError as e:
                return _stop(str(e), receipt, key)
            for module in LAZY_MODULES:
                importlib.import_module(module)
            receipt["provider"] = {"name": provider.name, "model": provider.model}
            return _Captured(ctx=ctx, config=config, key=key, req=req, receipt=receipt, provider=provider,
                             texts=rv.instructions())
        except Exception as e:  # anything at all: not_run, its message scrubbed of the key before it leaves the gate
            return _stop(f"the sentinel gate could not complete: {type(e).__name__}: {e}", receipt, key)

    def _review(self, got: _Captured) -> GateResult:
        ctx, key, receipt = got.ctx, got.key, dict(got.receipt)

        def stop(reason: str, extra: dict | None = None) -> GateResult:
            return _stop(reason, receipt, key, extra)
        try:
            provider = got.provider
            req = with_qa_evidence(got.req, ctx.run_dir)
            receipt.update(self._request_receipt(req))
            out = rv.Outcome()
            try:
                rv.review(req, provider, out, got.texts)
            except (rv.Unreadable, ProviderError) as e:
                self._evidence(ctx, out.exchanges, key)
                return stop(str(e), self._exchange_receipt(out.exchanges))
            self._evidence(ctx, out.exchanges, key)
            return self._verdict(ctx, req, out, receipt, key)
        except Exception as e:  # anything at all: not_run, its message scrubbed of the key before it leaves the gate
            return stop(f"the sentinel gate could not complete: {type(e).__name__}: {e}")

    # ── the receipt ───────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _request_receipt(req: ReviewRequest) -> dict:
        return {"depth": req.depth, "profile": req.profile.name, "checklist_blocks": list(req.profile.checklist_blocks),
                "items": len(req.items), "sanitized_lines": req.sanitized_lines, "redacted_secrets": req.redacted_secrets,
                "unsafe_paths": req.unsafe_paths,
                "not_sent": [{"path": p, "why": w} for p, w in req.not_sent], "omitted_for_budget": list(req.omitted),
                "named_files_missing": list(req.missing_named), "manifest_trust": req.qa.note, "notes": list(req.notes)}

    @staticmethod
    def _exchange_receipt(exchanges: list) -> dict:
        """Every request made, and the files they carried: what reached the endpoint, even when the run then stopped."""
        return {"requests": [{"n": i, "kind": ex.kind, "attempt": ex.attempt, "bytes": ex.bytes, "files": ex.files,
                              "answered": ex.answered} for i, ex in enumerate(exchanges, 1)],
                "sent_to_model_endpoint": sorted({f for ex in exchanges for f in ex.files})}

    def _evidence(self, ctx: GateContext, exchanges: list, key: str) -> None:
        for i, ex in enumerate(exchanges, 1):
            for sub, text in (("requests", f"SYSTEM\n{ex.system}\n\nUSER\n{ex.user}\n"), ("responses", ex.answer)):
                path = ctx.run_dir / sub / f"{i:02d}-{ex.kind}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(_clean(text, key))

    def _verdict(self, ctx: GateContext, req: ReviewRequest, out: rv.Outcome, receipt: dict, key: str) -> GateResult:
        findings = rv.findings_of(req, out)
        if receipt.get("config_changed_by_pr"):
            findings.append(Finding(severity="advisory", rule_id="CM-3", path=receipt.get("config_file"), message=(
                f"this pull request changes {', '.join(receipt['config_changed_by_pr'])}; the Sentinel gate reads its settings "
                f"from the base commit, so it used the base commit's values {rv.SUFFIX}")))
        got = rv.assessed(req, out)
        sent = {f.path for f in req.files} | {f.path for f in req.named}
        receipt.update(self._exchange_receipt(out.exchanges))
        evidence = {a.id: {**a.evidence, "path": req.real(a.evidence.get("path"))} for a in out.checklist
                    if isinstance(a.evidence, dict)}  # a placeholder the reviewer cited, as the real path (B-02)
        receipt["checklist"] = [{"id": a.id, "answer": a.answer, "controls": list(next(i.controls for i in req.items if i.id == a.id)),
                                 **({"evidence": evidence[a.id]} if a.evidence else {}), **({"reason": a.reason} if a.reason else {}),
                                 **({"findings": len(a.findings)} if a.findings else {}),
                                 "assessed": a.answer == "cited" and (evidence.get(a.id) or {}).get("path") in sent}
                                for a in out.checklist]
        if req.depth != "deep":
            for k in ("control_completeness", "adversarial", "edge_case"):
                receipt[k] = "skipped — light range"
        else:
            rows = {r.id: r for r in req.touched}
            receipt["control_completeness"] = [{"id": b.id, "implementation": rows[b.id].implementation,
                                                "answers": b.answers, "verdict": b.verdict, "unasked": list(b.unasked),
                                                "block": rv.cc_block_text(rows[b.id], b)} for b in out.cc] \
                if out.cc is not None else "skipped — no manifest control is touched by this range"
            receipt["adversarial"] = {"examined": out.adversarial.examined, "findings": len(out.adversarial.findings)}
            receipt["edge_case"] = {"findings": len(out.edge_cases or [])}
        receipt["controls_assessed"] = sorted(got)
        receipt["controls_not_assessed"] = sorted(gaps(ctx.profile, got))
        status, reason = status_of([f for f in findings if f.severity == "blocking"], req.omitted)
        cleaned = [type(f)(**_clean(f.__dict__, key)) for f in findings]
        return GateResult(gate="sentinel", status=status, reason=_clean(reason, key), findings=tuple(cleaned),
                          receipt=_clean(receipt, key))
