# Patina Child Watcher System

Watcher-system is a Patina child-bundle repository. It owns related watcher children and shared watch WIT contracts while keeping each child independently installable by Mother.

## Children

- `children/folder-watch-actor` — producer/service actor that scans a folder and emits typed watch events.
- `children/watch-null-sink` — reference downstream sink that accepts watch events, logs them, and drops them.

## Build

Build each child with `cargo component`:

```bash
cargo component build --release -p patina-ai-child-folder-watch-actor
cargo component build --release -p patina-ai-child-watch-null-sink
```

## Install smoke

After building, install each child from its package directory with the produced WASM artifact:

```bash
patina child install children/folder-watch-actor \
  --wasm target/wasm32-wasip1/release/patina_ai_child_folder_watch_actor.wasm \
  --force

patina child install children/watch-null-sink \
  --wasm target/wasm32-wasip1/release/patina_ai_child_watch_null_sink.wasm \
  --force
```

## Release-unit model

The v1 release model uses one release tag per child, for example:

- `folder-watch-actor-v0.1.0`
- `watch-null-sink-v0.1.0`

Each release unit should include the child WASM, `child.toml`, sidecar checksums, and `checksums.txt`.
