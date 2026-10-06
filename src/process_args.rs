#[cfg(target_os = "linux")]
pub fn scrub() {
    use std::{fs, ptr};

    // Linux exposes the original argv memory bounds in /proc/self/stat. Fields
    // 48 and 49 are arg_start and arg_end; split after the final ')' because
    // the comm field itself may contain spaces or parentheses.
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
        return;
    };
    let Some((_, fields)) = stat.rsplit_once(')') else {
        return;
    };
    let fields: Vec<&str> = fields.split_whitespace().collect();
    let (Some(start), Some(end)) = (fields.get(45), fields.get(46)) else {
        return;
    };
    let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) else {
        return;
    };
    if start == 0 || end <= start {
        return;
    }

    // Preserve argv[0] including its terminating NUL, then blank the remaining
    // argument strings in place. The argument area is writable process memory.
    let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, end - start) };
    let Some(argv0_end) = bytes.iter().position(|byte| *byte == 0) else {
        return;
    };
    let clear_start = start.saturating_add(argv0_end + 1);
    if clear_start < end {
        unsafe { ptr::write_bytes(clear_start as *mut u8, 0, end - clear_start) };
    }
}

#[cfg(not(target_os = "linux"))]
pub fn scrub() {}
