mod command;
mod start;
mod state;
mod stop;
mod sync;

use command::{BootstrapCommand, Cli, ErrorOutput, ParseOutcome};

fn main() {
    let parsed = match Cli::parse_from_env() {
        Ok(parsed) => parsed,
        Err(error) => {
            print_error_and_exit(error.to_string());
        }
    };

    let cli = match parsed {
        ParseOutcome::Run(cli) => cli,
        ParseOutcome::Help(help) => {
            println!("{help}");
            return;
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
        Ok(json) => println!("{json}"),
        Err(error) => print_error_and_exit(error.to_string()),
    }
}

fn print_error_and_exit(error: String) -> ! {
    let output = ErrorOutput { ok: false, error };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("serialize error output")
    );
    std::process::exit(1);
}
