// Prepare the same exact subject as the timed live tests.
#[path = "../tests/support/subject.rs"]
mod subject;

fn main() {
    let _ = subject::build_real_binaries();
}
