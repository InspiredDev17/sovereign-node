use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn production_source_has_no_generic_process_or_panic_escape_hatches() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut rust_files = Vec::new();
    collect_files(&root.join("src"), &mut rust_files)?;
    let forbidden = [
        ["std::process::", "Command"].concat(),
        ["tokio::process::", "Command"].concat(),
        ["Command", "::new("].concat(),
        ["unsafe", " {"].concat(),
        ["todo", "!("].concat(),
        ["unimplemented", "!("].concat(),
        [".unwrap", "()"].concat(),
        [".expect", "("].concat(),
    ];
    for path in rust_files {
        let source = fs::read_to_string(&path)?;
        for needle in &forbidden {
            assert!(
                !source.contains(needle),
                "{} contains forbidden production boundary {needle}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn workload_is_separate_from_legacy_actions_and_cognitive_or_inference_dependencies() -> TestResult
{
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workload = fs::read_to_string(root.join("src/workload.rs"))?;
    assert!(!workload.contains(&["crate::", "capabilities"].concat()));

    let cargo = fs::read_to_string(root.join("Cargo.toml"))?;
    for dependency in [
        "tokenizers",
        "candle-",
        "tch",
        "ort",
        "llama",
        "reqwest",
        "hyper",
        "axum",
    ] {
        assert!(!cargo.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with(&format!("{dependency} ="))
                || line.starts_with(&format!("{dependency}="))
        }));
    }

    let mut files = Vec::new();
    collect_files(&root, &mut files)?;
    assert!(files.iter().all(|path| {
        !matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("py" | "ts" | "tsx")
        )
    }));
    Ok(())
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) -> TestResult {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|name| name.to_str());
        if path.is_dir() {
            if !matches!(name, Some(".git" | "target" | "corpus" | "artifacts")) {
                collect_files(&path, output)?;
            }
        } else {
            output.push(path);
        }
    }
    Ok(())
}
