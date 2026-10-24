//! Time helpers.
//!
//! AETHER stores every timestamp as milliseconds since the Unix epoch and
//! formats to RFC 3339 only at the report boundary. That keeps arithmetic
//! exact and avoids a calendar dependency for what is a few dozen lines.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format epoch milliseconds as RFC 3339 / ISO 8601 in UTC.
pub fn format_rfc3339(millis: u64) -> String {
    let secs = (millis / 1000) as i64;
    let ms = millis % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
}

/// Howard Hinnant's `civil_from_days`: days since the epoch to a y/m/d triple.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Human-friendly elapsed duration, for CLI status output.
pub fn format_duration_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let (h, m, s) = (total_secs / 3600, (total_secs % 3600) / 60, total_secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}.{:03}s", ms % 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epochs() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
        // 2024-02-29T12:34:56.789Z - a leap day, to exercise the calendar math.
        assert_eq!(format_rfc3339(1_709_210_096_789), "2024-02-29T12:34:56.789Z");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration_ms(1_500), "1.500s");
        assert_eq!(format_duration_ms(61_000), "1m01s");
        assert_eq!(format_duration_ms(3_661_000), "1h01m01s");
    }
}
