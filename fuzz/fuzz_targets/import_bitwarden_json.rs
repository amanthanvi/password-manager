#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let export: Value = match serde_json::from_slice(data) {
        Ok(value) => value,
        Err(_) => return,
    };

    let Some(items) = export.get("items").and_then(Value::as_array) else {
        return;
    };

    for item in items.iter().take(256) {
        let Some(totp) = item
            .get("login")
            .and_then(|login| login.get("totp"))
            .and_then(Value::as_str)
        else {
            continue;
        };

        if totp.len() > 4096 {
            continue;
        }

        if totp.starts_with("otpauth://") {
            let _ = npw_core::parse_otpauth_uri(totp);
        } else {
            let _ = npw_core::decode_base32_secret(totp);
        }
    }
});

