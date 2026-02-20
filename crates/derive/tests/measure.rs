use derive_4mica::measure;
use std::cell::Cell;
use std::time::Duration;

thread_local! {
    static LAST_REPORT: Cell<Option<(&'static str, Duration)>> = const { Cell::new(None) };
}

fn capture(name: &'static str, duration: Duration) {
    LAST_REPORT.with(|c| c.set(Some((name, duration))));
}

#[measure(capture)]
fn add(a: u32, b: u32) -> u32 {
    a + b
}

#[measure(capture, name = "custom_operation")]
fn multiply(a: u32, b: u32) -> u32 {
    a * b
}

#[test]
fn reports_name_and_nonzero_duration() {
    let result = add(2, 3);
    assert_eq!(result, 5);

    let (name, duration) = LAST_REPORT
        .with(|c| c.get())
        .expect("report was not called");
    assert_eq!(name, "add");
    assert!(duration >= Duration::ZERO);
}

#[test]
fn name_override_reports_custom_name() {
    let result = multiply(4, 5);
    assert_eq!(result, 20);

    let (name, duration) = LAST_REPORT
        .with(|c| c.get())
        .expect("report was not called");
    assert_eq!(name, "custom_operation");
    assert!(duration >= Duration::ZERO);
}
