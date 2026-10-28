# Secure Builder Bot

One open-source bot that puts three gates on every pull request:

| Gate | Question it answers | Needs an LLM |
|---|---|---|
| **Scan** | Is anything in this tree known-bad? Seven pinned scanners, CVE data pulled live. | No |
| **QA** | Do the tests prove the code, including every declared security control? | No |
| **Sentinel** | Does the code keep every user in their lane, against a NIST 800-53 baseline? | Yes, with your own key |

Install it on GitHub or GitLab, pick a compliance profile (`il4` for NIST 800-53 Moderate,
`il6` for High), pick which gates to turn on, and every one of them runs on your next pull
request. Standards, STIGs, OWASP lists, CVE feeds and scanner versions keep themselves current.

**Status:** planning. The product requirements are in [`docs/PRD.md`](docs/PRD.md). The scan and
gate scripts under `engine/` are the working core, ported once from the App Building Engine; the
bot around them is not built yet. Development follows
[Addy Osmani's agent-skills](https://github.com/addyosmani/agent-skills), vendored under `.claude/`
(see `NOTICE`).

## Planned install

```
npx securebuilderbot init
```

Detects GitHub or GitLab, asks three questions, writes `.securebuilderbot.yml`, opens the setup PR.

```yaml
# .securebuilderbot.yml
profile: il4            # none | il4 | il6
gates: [scan, qa]       # any of scan, qa, sentinel
version: latest
```

## License

Apache 2.0. See [LICENSE](LICENSE).
