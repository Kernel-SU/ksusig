mod cli;

use cli::Cli;

fn main() {
    let cli = Cli::parse_args();

    if let Err(e) = cli.execute() {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}
