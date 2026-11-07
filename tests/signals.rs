//! Signal delivery to the CLI wrapper, without signalling its process group.
#![cfg(all(feature = "test-store", unix))]

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// On failure, clean up the wrapper and its descendants, not just the wrapper.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child did not create {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn forwards_signal(signal: i32, expected_code: i32) {
    let dir = tempfile::tempdir().unwrap();
    let secret = "signal-test-secret-0123456789";
    let mut command = Command::new(assert_cmd::cargo::cargo_bin("sealkeep"));
    command
        .env("SEALKEEP_TEST_KEYRING_FILE", dir.path().join("keyring.ron"))
        .env("SEALKEEP_CONFIG", dir.path().join("config.toml"))
        .env("SEALKEEP_AUDIT_LOG", dir.path().join("audit.jsonl"))
        .env("XDG_RUNTIME_DIR", dir.path())
        .current_dir(dir.path());
    std::fs::write(dir.path().join("secret"), secret).unwrap();
    assert!(
        command
            .args(["set", "API_KEY", "--from-file", "secret"])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Reuse only the isolated environment, not the arguments of `set`.
    let mut run = Command::new(command.get_program());
    for (key, value) in command.get_envs() {
        run.env(key, value.unwrap());
    }
    let stdout = std::fs::File::create(dir.path().join("stdout")).unwrap();
    let stderr = std::fs::File::create(dir.path().join("stderr")).unwrap();
    let mut running = Running(
        run.current_dir(dir.path())
            .args([
                "run", "API_KEY", "--dotenv", "API_KEY", "--", "sh", "-c",
                "trap 'echo TERM > received; echo \"$API_KEY\"; echo \"$API_KEY\" >&2; exit 42' TERM\n\
                 trap 'echo INT > received; echo \"$API_KEY\"; echo \"$API_KEY\" >&2; exit 43' INT\n\
                 printf '%s' \"$1\" > dotenv-path\n\
                 echo ready > ready\n\
                 while :; do sleep 0.05; done",
                "sh", "{dotenv}",
            ])
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    wait_for_file(&dir.path().join("ready"));
    let dotenv = std::fs::read_to_string(dir.path().join("dotenv-path")).unwrap();
    assert!(Path::new(&dotenv).exists());

    // Positive PID: model systemd KillMode=process, not a terminal group signal.
    assert_eq!(
        unsafe { libc::kill(running.0.id() as libc::pid_t, signal) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = running.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "sealkeep did not stop after {signal}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(expected_code));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("received"))
            .unwrap()
            .trim(),
        if signal == libc::SIGTERM {
            "TERM"
        } else {
            "INT"
        }
    );
    assert!(!Path::new(&dotenv).exists(), "dotenv file was not removed");
    for stream in ["stdout", "stderr"] {
        let output = std::fs::read_to_string(dir.path().join(stream)).unwrap();
        assert!(output.contains("[sealkeep:API_KEY]"), "{output}");
        assert!(!output.contains(secret), "secret leaked to {stream}");
    }
}

#[test]
fn term_to_wrapper_reaches_child() {
    forwards_signal(libc::SIGTERM, 42);
}

#[test]
fn int_to_wrapper_reaches_child() {
    forwards_signal(libc::SIGINT, 43);
}
