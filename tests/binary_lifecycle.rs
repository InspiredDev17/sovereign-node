#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sovereign_node::lifecycle::{LeaseKind, LifecycleLease};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn compiled_binary_init_status_offline_serve_shutdown_and_restart() -> TestResult {
    let temporary = tempfile::TempDir::new()?;
    let data_dir = temporary.path().join("node-state");
    let configuration = temporary.path().join("sovereign-node.toml");

    let initialized = run(&[
        "init",
        "--data-dir",
        path_text(&data_dir)?,
        "--label",
        "black-box-node",
    ])?;
    require_success(&initialized, "init")?;
    let init_json: serde_json::Value = serde_json::from_slice(&initialized.stdout)?;
    assert_eq!(init_json["created"], true);
    let node_id = init_json["node_id"]
        .as_str()
        .ok_or("init omitted NodeId")?
        .to_owned();

    let example = run(&["config-example", "--data-dir", path_text(&data_dir)?])?;
    require_success(&example, "config-example")?;
    fs::write(&configuration, &example.stdout)?;
    fs::set_permissions(&configuration, fs::Permissions::from_mode(0o600))?;

    let first_status = run(&["status", path_text(&configuration)?])?;
    require_success(&first_status, "status")?;
    let status_json: serde_json::Value = serde_json::from_slice(&first_status.stdout)?;
    assert_eq!(status_json["node_id"], node_id);
    assert_eq!(status_json["trusted_peer_count"], 0);

    run_offline_daemon_once(&configuration, &data_dir)?;
    run_offline_daemon_once(&configuration, &data_dir)?;

    let final_status = run(&["status", path_text(&configuration)?])?;
    require_success(&final_status, "status after restart")?;
    let final_json: serde_json::Value = serde_json::from_slice(&final_status.stdout)?;
    assert_eq!(final_json["node_id"], node_id);

    for private_file in [
        data_dir.join("identity.json"),
        data_dir.join("state.sqlite3"),
    ] {
        let mode = fs::symlink_metadata(private_file)?.permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
    Ok(())
}

fn run(arguments: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sovereign-node"))
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?)
}

fn run_offline_daemon_once(configuration: &Path, data_dir: &Path) -> TestResult {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sovereign-node"))
        .args(["serve", path_text(configuration)?])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_daemon_lease(&mut child, data_dir)?;

    let signal = Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .output()?;
    require_success(&signal, "SIGINT delivery")?;
    let output = child.wait_with_output()?;
    require_success(&output, "offline daemon clean shutdown")?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("local-only offline mode"));
    Ok(())
}

fn wait_for_daemon_lease(child: &mut Child, data_dir: &Path) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match LifecycleLease::acquire(data_dir, LeaseKind::Daemon) {
            Ok(lease) => drop(lease),
            Err(_) => return Ok(()),
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("daemon exited before readiness: {status}").into());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err("daemon did not establish its lifecycle lease".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn require_success(output: &Output, operation: &str) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn path_text(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}
