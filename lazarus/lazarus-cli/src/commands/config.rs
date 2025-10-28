use clap::Args;

#[derive(Args)]
pub struct ConfigArgs {
    #[arg(short, long)]
    pub key: String,

    #[arg(short, long)]
    pub value: String,
}
