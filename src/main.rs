use anyhow::Result;

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if matches!(args.as_slice(), [flag] if flag == "-v" || flag == "--version") {
        println!("mypass {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if !args.is_empty() {
        anyhow::bail!(
            "mypass no longer accepts command-line arguments. Run ./mypass to start TUI mode."
        );
    }

    mypass::tui::run().map_err(|err| anyhow::anyhow!(err))
}
