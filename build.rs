use std::{env, fs, path::PathBuf, process::Command};

fn run(cmd: &mut Command) {
    let status = cmd
        .status()
        .unwrap_or_else(|_| panic!("failed to run {cmd:?}"));
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap();

    // Build vibe-usernet.
    // Limit this to Apple hosts; on others, create a stub file so we can still run `cargo check` (e.g., from within Vibe =D)
    if host.contains("apple-darwin") && target == "aarch64-apple-darwin" {
        let usernet_dir = manifest_dir.join("helpers/vibe-usernet");
        let usernet_helper_path = out_dir.join("vibe-usernet");

        let mut go = Command::new("go");
        go.current_dir(&usernet_dir)
            .env("CGO_ENABLED", "1")
            .env("GOOS", "darwin")
            .env("GOARCH", "arm64")
            .args(["build", "-trimpath", "-ldflags", "-w -s", "-o"])
            .arg(&usernet_helper_path)
            .arg(".");
        run(&mut go);

        println!(
            "cargo:rustc-env=BUNDLED_USERNET_HELPER_PATH={}",
            usernet_helper_path.display()
        );

        for entry in fs::read_dir(&usernet_dir)
            .expect("read vibe-usernet dir")
            .flatten()
        {
            let path = entry.path();
            if let Some("go" | "mod" | "sum") = path.extension().and_then(|e| e.to_str()) {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
        println!("cargo:rerun-if-env-changed=TARGET");
    } else {
        let stub_path = out_dir.join("stub-vibe-usernet");
        fs::write(&stub_path, []).expect("write stub vibe-usernet");
        println!(
            "cargo:rustc-env=BUNDLED_USERNET_HELPER_PATH={}",
            stub_path.display()
        );
    }

    {
        let provisioning_dir = manifest_dir.join("provisioning");
        println!("cargo:rerun-if-changed={}", provisioning_dir.display());
        let scripts = fs::read_dir(&provisioning_dir)
            .expect("read provisioning dir")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("sh"));

        let mut generated = String::from(
            r#"
#[derive(Clone)]
struct ProvisionScript {
    name: std::borrow::Cow<'static, str>,
    description: std::borrow::Cow<'static, str>,
    content: std::borrow::Cow<'static, str>,
}

const BUILTIN_PROVISION_SCRIPTS: &[ProvisionScript] = &[
"#,
        );
        for path in scripts {
            println!("cargo:rerun-if-changed={}", path.display());
            let name = path.file_stem().unwrap();
            let content = fs::read_to_string(&path).expect("read provisioning script");
            let description = content
                .lines()
                .nth(1)
                .map(|line| line.trim_start_matches('#').trim())
                .unwrap_or("")
                .to_string();
            generated.push_str(&format!(
                "    ProvisionScript {{ name: std::borrow::Cow::Borrowed({:?}), description: std::borrow::Cow::Borrowed({:?}), content: std::borrow::Cow::Borrowed(include_str!({:?})) }},\n",
                name,
                description,
                path.display(),
            ));
        }
        generated.push_str("];");
        fs::write(out_dir.join("provisioning.rs"), generated).expect("write provisioning.rs");
    }

    // Expose GIT_SHA and BUILD_DATE vars so Vibe can embed them in its version info
    {
        let sha = Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .map_or_else(
                |_| "unknown".into(),
                |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
            );
        let build_date = Command::new("date")
            .args(["-u", "+%F"])
            .output()
            .map_or_else(
                |_| "unknown".into(),
                |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
            );

        println!("cargo:rustc-env=GIT_SHA={sha}");
        println!("cargo:rustc-env=BUILD_DATE={build_date}");
        println!("cargo:rerun-if-changed=.git/HEAD");
    }
}
