//! Standalone regression-test runner for OSV fixed-version matching.
//!
//! The normal `cargo test --lib` harness fails to start on this Tauri/Windows
//! lib crate (STATUS_ENTRYPOINT_NOT_FOUND when loading the test exe). A plain
//! binary links and runs fine, so this runner executes the same assertions and
//! exits non-zero on any failure. Run: `cargo run --bin osv_tests`.

use cyclonedx_tauri_ui_lib::osv_client::{compare_versions, extract_fixed_version};
use cyclonedx_tauri_ui_lib::config_env_path_from;
use serde_json::json;
use std::cmp::Ordering;

fn adv(pkg: &str, eco: &str, ranges: serde_json::Value) -> serde_json::Value {
    json!({ "id": "TEST-0001",
        "affected": [ { "package": { "name": pkg, "ecosystem": eco }, "ranges": ranges } ] })
}
fn eco_range(events: serde_json::Value) -> serde_json::Value {
    json!([ { "type": "ECOSYSTEM", "events": events } ])
}

fn main() {
    let mut failures = 0;
    let mut checks = 0;

    macro_rules! check {
        ($name:expr, $got:expr, $want:expr) => {{
            checks += 1;
            if $got != $want {
                failures += 1;
                println!("FAIL {}: got {:?}, want {:?}", $name, $got, $want);
            } else {
                println!("ok   {}", $name);
            }
        }};
    }

    // ── version comparison: numeric, not lexical ──
    check!("cmp 1.10.0 > 1.9.0", compare_versions("1.10.0", "1.9.0", "PyPI"), Some(Ordering::Greater));
    check!("cmp equal", compare_versions("1.2.3", "1.2.3", "npm"), Some(Ordering::Equal));
    check!("cmp 2.0.0 < 10.0.0", compare_versions("2.0.0", "10.0.0", "crates.io"), Some(Ordering::Less));
    check!("cmp prerelease < release", compare_versions("1.0.0rc1", "1.0.0", "PyPI"), Some(Ordering::Less));
    check!("cmp release > alpha", compare_versions("1.0.0", "1.0.0-alpha", "npm"), Some(Ordering::Greater));
    check!("cmp build-metadata equal", compare_versions("1.0.0+build", "1.0.0", "crates.io"), Some(Ordering::Equal));
    check!("cmp undeterminable -> None", compare_versions("weird", "1.0.0", "PyPI"), None::<Ordering>);

    // ── fixed-version extraction ──
    let a1 = adv("agno", "PyPI", eco_range(json!([{ "introduced": "0" }, { "fixed": "2.3.24" }])));
    check!("matched single range -> fix", extract_fixed_version(&a1, "agno", "PyPI", "1.7.2"), Some("2.3.24".to_string()));
    check!("mismatched package -> None", extract_fixed_version(&a1, "other", "PyPI", "1.7.2"), None::<String>);
    check!("mismatched ecosystem -> None", extract_fixed_version(&a1, "agno", "npm", "1.7.2"), None::<String>);
    check!("already-fixed -> None", extract_fixed_version(&a1, "agno", "PyPI", "2.5.0"), None::<String>);

    let a2 = adv("pkg", "PyPI", eco_range(json!([
        { "introduced": "1.0" }, { "fixed": "1.4.2" },
        { "introduced": "2.0" }, { "fixed": "2.1.0" }])));
    check!("multi-range branch 1", extract_fixed_version(&a2, "pkg", "PyPI", "1.3.0"), Some("1.4.2".to_string()));
    check!("multi-range branch 2", extract_fixed_version(&a2, "pkg", "PyPI", "2.0.5"), Some("2.1.0".to_string()));

    let a3 = adv("agno", "PyPI", eco_range(json!([{ "introduced": "0" }])));
    check!("missing fixed event -> None", extract_fixed_version(&a3, "agno", "PyPI", "1.7.2"), None::<String>);

    let a4 = adv("pkg", "PyPI", eco_range(json!([{ "introduced": "1.0" }, { "last_affected": "1.9.9" }])));
    check!("last_affected (no fix) -> None", extract_fixed_version(&a4, "pkg", "PyPI", "1.5.0"), None::<String>);

    let a5 = adv("pkg", "PyPI", json!([
        { "type": "GIT", "events": [ { "introduced": "0" }, { "fixed": "abc123def" } ] }]));
    check!("git range ignored -> None", extract_fixed_version(&a5, "pkg", "PyPI", "1.0.0"), None::<String>);

    let a6 = adv("pkg", "PyPI", eco_range(json!([{ "introduced": "0" }, { "fixed": "2.0.0" }])));
    check!("undeterminable scanned version -> None", extract_fixed_version(&a6, "pkg", "PyPI", "not-a-version"), None::<String>);

    // ── env/config loader scoping (dummy credentials only) ──

    // (a) Config path derives from APPDATA + identifier on Windows.
    #[cfg(windows)]
    {
        let get = |k: &str| if k == "APPDATA" { Some("C:\\Users\\tester\\AppData\\Roaming".to_string()) } else { None };
        let p = config_env_path_from(&get).map(|p| p.to_string_lossy().replace('/', "\\"));
        check!("config path uses APPDATA\\com.strazh.app\\.env",
            p, Some("C:\\Users\\tester\\AppData\\Roaming\\com.strazh.app\\.env".to_string()));
        // Missing APPDATA -> no path (don't guess).
        let none = |_k: &str| None;
        check!("missing APPDATA -> None", config_env_path_from(&none), None::<std::path::PathBuf>);
    }

    // (b) Environment variable takes precedence over a file value.
    //     dotenvy::from_path must NOT override an already-set var.
    {
        let dir = std::env::temp_dir().join(format!("strazh_env_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dir.join(".env");
        std::fs::write(&cfg, "STRAZH_TEST_KEY=from_file\n").unwrap();

        // Case 1: var already set -> keeps the environment value.
        std::env::set_var("STRAZH_TEST_KEY", "from_env");
        let _ = dotenvy::from_path(&cfg); // scoped load of exactly this file
        check!("env precedence over file", std::env::var("STRAZH_TEST_KEY").ok(), Some("from_env".to_string()));

        // Case 2: a DIFFERENT var, unset, IS populated from the intended file.
        std::env::remove_var("STRAZH_TEST_KEY2");
        std::fs::write(&cfg, "STRAZH_TEST_KEY2=from_config\n").unwrap();
        let _ = dotenvy::from_path(&cfg);
        check!("intended config file value is used", std::env::var("STRAZH_TEST_KEY2").ok(), Some("from_config".to_string()));

        // Case 3: an unrelated parent/repo .env (different dir) is NOT consulted
        //         by the scoped loader. We create one but only load `cfg`.
        let parent_env = dir.join("parent.env");
        std::fs::write(&parent_env, "STRAZH_TEST_KEY3=from_parent_repo\n").unwrap();
        std::env::remove_var("STRAZH_TEST_KEY3");
        let _ = dotenvy::from_path(&cfg); // load only the intended file
        check!("unrelated parent/repo .env ignored", std::env::var("STRAZH_TEST_KEY3").ok(), None::<String>);

        // cleanup
        std::env::remove_var("STRAZH_TEST_KEY");
        std::env::remove_var("STRAZH_TEST_KEY2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Pro license validation (HMAC key gate) ──
    {
        use cyclonedx_tauri_ui_lib::license::{sign, status_from_key, validate, LicensePayload};

        let mk = |name: &str, plan: &str, exp: u64| sign(&LicensePayload {
            name: name.into(), plan: plan.into(), exp,
        });

        // Valid perpetual Pro key unlocks.
        let pro = mk("acme", "pro", 0);
        check!("valid Pro key -> pro", status_from_key(Some(pro.clone())).pro, true);
        check!("valid Pro key validates", validate(&pro).is_ok(), true);

        // Far-future Pro key (subscription-like) unlocks.
        let sub_pro = status_from_key(Some(mk("acme", "pro", 4_102_444_800))).pro;
        check!("far-future Pro key -> pro", sub_pro, true);

        // Expired Pro key is rejected with an "expired" plan label.
        // (Bind results first — the check! macro evaluates its arg twice.)
        let expired = status_from_key(Some(mk("acme", "pro", 1)));
        let expired_pro = expired.pro;
        let expired_plan = expired.plan.clone();
        check!("expired Pro key -> not pro", expired_pro, false);
        check!("expired Pro key -> plan=expired", expired_plan, "expired".to_string());

        // Non-Pro plan does not unlock.
        let free_plan_pro = status_from_key(Some(mk("acme", "free", 0))).pro;
        check!("free-plan key -> not pro", free_plan_pro, false);

        // Tampered signature is rejected.
        let mut tampered = pro.clone();
        tampered.pop();
        tampered.push(if pro.ends_with('A') { 'B' } else { 'A' });
        let tampered_invalid = validate(&tampered).is_err();
        check!("tampered key -> invalid", tampered_invalid, true);

        // Garbage / absent keys are Free.
        let garbage_pro = status_from_key(Some("not-a-key".into())).pro;
        let none_pro = status_from_key(None).pro;
        check!("garbage key -> not pro", garbage_pro, false);
        check!("no key -> not pro", none_pro, false);

        // License path derives from the same per-user dir as the credential file.
        #[cfg(windows)]
        {
            use cyclonedx_tauri_ui_lib::license::license_path_from;
            let get = |k: &str| if k == "APPDATA" { Some("C:\\Users\\tester\\AppData\\Roaming".to_string()) } else { None };
            let p = license_path_from(&get).map(|p| p.to_string_lossy().replace('/', "\\"));
            let want = Some("C:\\Users\\tester\\AppData\\Roaming\\com.strazh.app\\license.key".to_string());
            check!("license path uses APPDATA\\com.strazh.app\\license.key", p, want);
        }
    }

    println!("\n{}/{} checks passed, {} failed", checks - failures, checks, failures);
    if failures > 0 {
        std::process::exit(1);
    }
}

