mod command;
mod start;
mod stop;
mod sync;

use command::{BootstrapCommand, Cli, ErrorOutput, ParseOutcome};

fn main() {
    let parsed = Cli::parse_from_env();
    let cli = match parsed {
        Ok(ParseOutcome::Run(cli)) => cli,
        Ok(ParseOutcome::Help(help)) => {
            println!("{help}");
            return;
        }
        Err(error) => {
            let output = ErrorOutput {
                ok: false,
                error: error.to_string(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize error output")
            );
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        BootstrapCommand::Sync(args) => sync::run(args)
            .map(|output| serde_json::to_string_pretty(&output).expect("serialize sync output")),
        BootstrapCommand::Start(args) => start::run(args)
            .map(|output| serde_json::to_string_pretty(&output).expect("serialize start output")),
        BootstrapCommand::Stop(args) => stop::run(args)
            .map(|output| serde_json::to_string_pretty(&output).expect("serialize stop output")),
    };

    match result {
        Ok(json) => {
            println!("{json}");
        }
        Err(error) => {
            let output = ErrorOutput {
                ok: false,
                error: error.to_string(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize error output")
            );
            std::process::exit(1);
        }
    }
}
