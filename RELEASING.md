# Releasing

Watcher-system currently uses per-child release tags so Mother can consume each child as an independently installable release unit.

## Tag shape

```text
folder-watch-actor-v0.1.0
watch-null-sink-v0.1.0
```

## Required release assets

For each child release, attach:

```text
<child-wasm>.wasm
<child-wasm>.wasm.sha256
child.toml
child.toml.sha256
checksums.txt
```

`child.toml` is the child identity source of truth. Its `[child].version` must match the Cargo package version and the release tag version.

## Build commands

```bash
cargo component build --release -p patina-ai-child-folder-watch-actor
cargo component build --release -p patina-ai-child-watch-null-sink
```

## Current registry note

Richer multi-child bundle registry behavior is deferred to the Patina Slate `mother-multi-child-bundle-registry`. Until then, treat each child tag as a separate release stream.
