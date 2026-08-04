# Tribe closed-feature Vector releases

Builds immutable GitHub Release assets for Tribe workstation capture.

## Supported targets

| Triple | Runner |
| --- | --- |
| `arm64-apple-darwin` | `macos-14` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |

## Features

```text
api,sources-http_server,transforms-remap,transforms-filter,sinks-http
```

## Trigger

From the `tribe/release-ci` branch:

```sh
gh workflow run tribe-release.yml \
  --ref tribe/release-ci \
  -f source_sha=06592198acaa966fd32277456e0fe6bbb33b3c51 \
  -f version=0.58.0-dev.06592198.tribe1 \
  -f create_release=true
```

The release tag points at `source_sha` (never at this CI branch tip). Do not
retag or overwrite assets after publish.
