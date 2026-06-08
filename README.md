# obfuscan action

Detect obfuscated code and likely backdoors in pull-request diffs. Multi-language. Diff-aware. Pure offline. Built for GitHub code review.

## Quick start

```yaml
name: obfuscan

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: ByteBardOrg/obfuscan-action@v1
        with:
          fail-on: block
```

The action scans the PR diff, annotates findings, writes a job summary, and upserts one Markdown PR comment.

## What it catches

obfuscan looks for the patterns common to supply-chain attacks:

- Decode-then-execute chains like `eval(Buffer.from(payload, "base64").toString())`.
- Dynamic execution of non-literal code across JavaScript, Python, PowerShell, Bash, PHP, Ruby, Go, Rust, C#, Java, Kotlin, Lua, Perl, and VBScript.
- Suspicious install-time behavior in `package.json`, `setup.py`, `build.rs`, GitHub Actions workflows, and Dockerfiles.
- Obfuscation signals including high-entropy strings, encoded string arrays, bidi controls, homoglyph identifiers, and very long generated lines.

Static analysis is a reviewer aid, not a proof of safety. Treat findings as high-signal review prompts.

## Distribution model

GitHub runs JavaScript actions directly from the checked-out action repository and does not run `npm install`. This repo therefore contains generated runtime artifacts under `dist/`, including a bundled copy of the exact `@obfuscan/rules` JSON files used by the scanner.

Do not edit `dist/` or `dist/rules` by hand. They are generated from the main obfuscan repository:

```bash
cd packages/action
npm run marketplace
```

Source of truth:

- Action source: <https://github.com/ByteBardOrg/obfuscan/tree/main/packages/action>
- Rules source: <https://github.com/ByteBardOrg/obfuscan/tree/main/packages/rules>

## Inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | `${{ github.token }}` | Token used to read diffs and write PR comments. |
| `fail-on` | `block` | Fails the workflow at `block`, `warn`, or `never`. |
| `min-severity` | `info` | Minimum severity to report: `info`, `warn`, or `block`. |
| `comment` | `true` | Create or update a PR comment. Set to `false` for annotations and summaries only. |
| `max-findings` | `50` | Maximum findings shown in the Markdown report. |
| `allowlist-path` | `.obfuscan/allowlist.json` | Workspace-relative allowlist path. |
| `disabled-detectors` | empty | Comma or newline separated detector ids to disable. |
| `file-timeout-ms` | engine default | Optional per-file detector timeout in milliseconds. |

## Outputs

| Output | Description |
|---|---|
| `findings-total` | Total number of findings. |
| `findings-block` | Number of block findings. |
| `findings-warn` | Number of warn findings. |
| `findings-info` | Number of info findings. |
| `conclusion` | `pass` or `fail`. |

## Examples

Fail on warnings too:

```yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    fail-on: warn
```

Only report blocking findings:

```yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    min-severity: block
```

Run without PR comments:

```yaml
permissions:
  contents: read
  pull-requests: read

steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}
  - uses: ByteBardOrg/obfuscan-action@v1
    with:
      comment: false
```

Disable a detector:

```yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    disabled-detectors: |
      obf.high-entropy-literal
      obf.long-line
```

## Permissions

Use these permissions when `comment: true`:

```yaml
permissions:
  contents: read
  pull-requests: read
  issues: write
```

Use these permissions when `comment: false`:

```yaml
permissions:
  contents: read
  pull-requests: read
```

GitHub may restrict `GITHUB_TOKEN` on pull requests from forks. In that case, obfuscan still emits annotations and a job summary, but PR comment creation can be skipped or fail with a warning.

## Suppressions

Suppress a known false positive inline:

```js
// obfuscan-disable-next-line obf.high-entropy-literal
const fixture = "U29tZSBsb25nIGRldGVjdG9yIGZpeHR1cmU=";
```

Or use `.obfuscan/allowlist.json`:

```json
{
  "paths": [
    { "pattern": "vendor/**", "maxSeverity": "warn", "reason": "third-party bundle" }
  ]
}
```

## Releases

This repo should maintain a moving major tag:

```bash
git tag v1
git push origin v1
```

For future `1.x` releases, move the major tag after publishing the release tag:

```bash
git tag v1.0.1
git push origin v1.0.1
git tag -f v1 v1.0.1
git push -f origin v1
```

## License

Apache-2.0. See [LICENSE](./LICENSE).

