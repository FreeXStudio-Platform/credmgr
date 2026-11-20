// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// C4 F-1: `--version` / `--help` answer on the command line and exit. Before this, any argument started the whole
/// GUI, so `CredMgr.app/Contents/MacOS/desktop --version` never returned.
fn answer_flag(arg: &str) -> Option<String> {
    match arg {
        "--version" | "-V" => Some(format!("CredMgr {}", env!("CARGO_PKG_VERSION"))),
        "--help" | "-h" => Some(format!(
            "CredMgr {}\nThe desktop app. Open it from the Applications folder, or with `open CredMgr.app`; the bare\nexecutable has no link to the broker. The command line is `credmgr`.",
            env!("CARGO_PKG_VERSION")
        )),
        _ => None,
    }
}

fn main() {
    if let Some(text) = std::env::args().nth(1).and_then(|a| answer_flag(&a)) {
        println!("{text}");
        return;
    }
    desktop_lib::run()
}

#[cfg(test)]
mod tests {
    use super::answer_flag;

    #[test]
    fn version_and_help_answer_without_starting_the_window() {
        assert!(answer_flag("--version").unwrap().starts_with("CredMgr 2."));
        assert_eq!(answer_flag("-V"), answer_flag("--version"));
        assert!(answer_flag("--help").unwrap().contains("credmgr"));
        assert_eq!(answer_flag("--something-else"), None);
        assert_eq!(answer_flag(""), None);
    }
}
