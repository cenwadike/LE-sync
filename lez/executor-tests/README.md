# executor tests (M2)

    cargo test --release --manifest-path lez/executor-tests/Cargo.toml
    cargo run  --release --manifest-path lez/executor-tests/Cargo.toml --bin gas        # 512
    cargo test --release --manifest-path lez/executor-tests/Cargo.toml -- --ignored     # cap at 512
