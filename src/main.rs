use std::process::ExitCode;

fn main() -> ExitCode {
    crush_ssh::session::run_from_env()
}
