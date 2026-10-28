# Secure Builder Bot on GitLab

Two files in your repository and the gates run on your next merge request.

## 1. Include the component in `.gitlab-ci.yml`

```yaml
include:
  - component: $CI_SERVER_FQDN/<group>/secure-builder-bot/secure-builder@0.4.0
```

`<group>` is the group your GitLab instance mirrors the bot's project into (an air-gapped instance
keeps its own copy; GitLab's container and project mirroring do this). The version after `@` is the
bot release the component runs. Inputs, each with a default:

| Input | Default | What it is |
|---|---|---|
| `version` | `latest` | The bot release to run: `latest` (the newest release tag, never a branch), or a pinned `x.y.z` |
| `base` | `$CI_MERGE_REQUEST_DIFF_BASE_SHA` | The base of the range the gates review |
| `python_version` | `"3.12"` | The python image tag the job runs on |
| `token_variable` | `SECURE_BUILDER_TOKEN` | The **name** of the CI/CD variable holding a project access token with the `api` scope |

The component runs three jobs. `secure-builder` runs Scan and QA, and with them your merge
request's own code (its build scripts, its tests); it holds no token and no key, and is red when a
gate failed. `secure-builder-verdict` runs after it, whatever its result, runs none of your code,
reads the gates job's result as that job's claim (every Scan and QA section says so), runs Sentinel
and decides the verdict. `secure-builder-publish` posts it.

The job token cannot post merge request notes on every GitLab, so the publisher uses a project
access token, and that token must reach the publish job alone: a job that runs your merge
request's tests must never hold it. A project CI/CD variable reaches every job unless it is scoped
to an environment, so the publish job declares the environment `secure-builder`. Create a project
access token with the `api` scope, then under **Settings → CI/CD → Variables** add it as:

| Setting | Value | Why |
|---|---|---|
| Key | `SECURE_BUILDER_TOKEN` (or another name, passed as `token_variable`) | The bot reads the variable by this name |
| Visibility | Masked (or masked and hidden) | GitLab keeps it out of job logs |
| Protect variable | **Off** | Merge request pipelines on unprotected branches do not receive protected variables, and the publisher would exit 1 with "is not set" |
| Environments | `secure-builder` | Only the publish job declares it, so the gates job never receives the token |

Leaving it unscoped (`*`) hands the token to the gates job, where your merge request's tests could
read it. Anyone who can push a branch can also change `.gitlab-ci.yml` on it; to limit which
pipelines may use the `secure-builder` environment at all, make it a protected environment
(**Settings → CI/CD → Protected environments**) and choose who is allowed to deploy to it. The
value is never written to a file, a log or an artifact. Air-gapped installs set
`SECURE_BUILDER_SOURCE` to the mirror both jobs clone the bot from; `version: latest` takes the
newest `vX.Y.Z` tag there, so the mirror must carry the release tags.

## 2. Answer the three questions in `.securebuilderbot.yml`

```yaml
# .securebuilderbot.yml — Secure Builder Bot
# Which compliance profile? none (OWASP only) | il4 (NIST 800-53 Moderate) | il6 (High)
profile: il4
# Which gates? any of scan, qa, sentinel. A gate that is off is absent, never skipped-green.
gates: [scan, qa]
# Which bot release? latest, or a pinned x.y.z
version: latest
```

Turning Sentinel on adds a `sentinel:` block naming the CI secret that holds your model key, by
name only:

```yaml
# Where Sentinel runs, and the NAME of the CI/CD variable holding your model key — never the value
sentinel:
  provider: anthropic   # anthropic | openai | self-hosted
  key_secret: SB_MODEL_KEY
  depth: auto             # auto | always-deep | always-light
```

The component names no model key itself. Sentinel runs in `secure-builder-verdict`, which runs none
of your merge request's code and declares the environment `secure-builder-sentinel`: add the key as a
masked CI/CD variable under the name `key_secret` gives it, with **Environments** set to
`secure-builder-sentinel`, so it reaches that job and no other. Never leave it unscoped (`*`): it
would reach the gates job, where your merge request's tests could read it.

A scope is only as strong as the environment behind it: a merge request can edit `.gitlab-ci.yml`
and give any job `environment: secure-builder-sentinel`. Make **both** `secure-builder` and
`secure-builder-sentinel` protected environments (**Settings → CI/CD → Protected environments**),
deployable only by the people you trust with the token and the key. Run the three jobs on a docker
or Kubernetes executor, a fresh container per job: on a shell executor, or with a reused build
volume, what the gates job leaves on the machine is there when the verdict job runs.

`npx securebuilderbot init` writes both files from the same three answers.

## What the merge request shows

- **One note** with the verdict block and a section per gate: status, the verdict line, the reason
  when it did not pass, the controls it assessed, the run id. The next run edits the same note.
- **One discussion per finding on a diff line**, with its severity, rule id, message and what would
  fix it. A finding gone on the next push gets a reply and the discussion is resolved. Nothing is
  posted twice on the same line.
- **The code quality widget**, fed by `gl-code-quality-report.json`.
- **The receipt**, under `gate-records/runs/` in the `secure-builder` job's artifacts, written for
  an assessor.
