#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(data);

    let headers = match reader.headers() {
        Ok(value) => value.clone(),
        Err(_) => return,
    };

    let totp_index = headers.iter().position(|value| value == "totp_uri");
    for record in reader.records().take(512) {
        let Ok(record) = record else {
            return;
        };
        let Some(index) = totp_index else {
            continue;
        };
        let Some(candidate) = record.get(index) else {
            continue;
        };
        if candidate.len() > 2048 {
            continue;
        }
        let _ = npw_core::parse_otpauth_uri(candidate);
    }
});

