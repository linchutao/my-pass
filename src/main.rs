use anyhow::Result;

fn main() -> Result<()> {
    if std::env::args_os().len() > 1 {
        anyhow::bail!(
            "mypass no longer accepts command-line arguments. Run ./mypass to start TUI mode."
        );
    }

    mypass::tui::run().map_err(|err| anyhow::anyhow!(err))
}
