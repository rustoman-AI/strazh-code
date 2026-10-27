//! Strazh Pro license key generator (internal tool).
//!
//! Issues signed, offline license keys for the desktop app. The signing secret
//! is embedded in `license.rs`; this binary links the lib and reuses it, so
//! keys produced here validate in the app as long as the secret matches.
//!
//! Usage:
//!   cargo run --bin keygen -- --name "Ada Lovelace" --plan pro            # perpetual
//!   cargo run --bin keygen -- --name "order_12345" --plan pro --days 365  # 1-year
//!   cargo run --bin keygen -- --test                                      # print 3 test keys
//!
//! After someone pays, run this with their name/order id and email them the key.
//! They paste it into Strazh → About → License.

use cyclonedx_tauri_ui_lib::license::{sign, validate, LicensePayload};

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn print_key(label: &str, name: &str, plan: &str, exp: u64) {
    let key = sign(&LicensePayload { name: name.into(), plan: plan.into(), exp });
    // Self-check so a bad build fails loudly rather than shipping dead keys.
    let ok = validate(&key).is_ok();
    let when = if exp == 0 { "perpetual".to_string() } else { format!("expires unix {exp}") };
    println!("# {label} (name=\"{name}\", plan={plan}, {when}) valid={ok}");
    println!("{key}\n");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // --test prints a stable set of keys for verifying the in-app flow.
    if args.iter().any(|a| a == "--test") {
        println!("=== Strazh test license keys ===\n");
        // Perpetual Pro.
        print_key("TEST KEY 1 — perpetual Pro", "test-pro-perpetual", "pro", 0);
        // Pro expiring far in the future (acts like an active subscription).
        print_key("TEST KEY 2 — Pro, far-future expiry", "test-pro-subscription", "pro", 4102444800); // 2100-01-01
        // Already-expired Pro (should be rejected by the app).
        print_key("TEST KEY 3 — expired Pro (must be rejected)", "test-pro-expired", "pro", 1);
        return;
    }

    let mut name = String::from("licensee");
    let mut plan = String::from("pro");
    let mut days: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => { i += 1; name = args.get(i).cloned().unwrap_or_default(); }
            "--plan" => { i += 1; plan = args.get(i).cloned().unwrap_or_else(|| "pro".into()); }
            "--days" => {
                i += 1;
                days = args.get(i).and_then(|v| v.parse::<u64>().ok());
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Try: --name <who> --plan pro [--days N]  |  --test");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let exp = match days {
        Some(d) => now_unix() + d * 86_400,
        None => 0,
    };
    print_key("ISSUED KEY", &name, &plan, exp);
}
