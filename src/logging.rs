use std::{fmt::Arguments, time::SystemTime};

fn timestamp(now: SystemTime) -> String {
    let elapsed = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs() as _;
    let mut utc = unsafe { std::mem::zeroed::<libc::tm>() };
    unsafe { libc::gmtime_r(&seconds, &mut utc) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        elapsed.subsec_millis()
    )
}

pub fn log(message: Arguments<'_>) {
    eprintln!("[{}] marriedsh: {message}", timestamp(SystemTime::now()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamp_is_utc_with_milliseconds() {
        assert_eq!(
            timestamp(SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123)),
            "2023-11-14T22:13:20.123Z"
        );
    }
}
