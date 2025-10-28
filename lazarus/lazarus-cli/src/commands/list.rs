use clap::Args;

#[derive(Args)]
pub struct ListArgs {
    #[arg(short, long)]
    pub source: String,
}
