use clap::Args;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(short, long)]
    pub source: String,
}
