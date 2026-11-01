//! Checks a TDX quote's signature chain back to Intel's root and prints what it attests.
//!   verify-quote <file holding the quote as hex>
use anyhow::{bail, Context, Result};
use dcap_qvl::collateral::{CollateralClient, PHALA_PCCS_URL};
use dcap_qvl::quote::Report;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).context("usage: verify-quote <quote hex file>")?;
    let quote = hex::decode(std::fs::read_to_string(path)?.trim())?;
    let collateral = CollateralClient::with_default_http(PHALA_PCCS_URL)?.fetch(&quote).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let verified = dcap_qvl::verify::verify(&quote, &collateral, now)?;
    let Report::TD10(report) = verified.report else { bail!("not a TDX 1.0 report") };
    println!("{}", json!({
        "tcb_status": verified.status,
        "advisories": verified.advisory_ids,
        "mr_td": hex::encode(report.mr_td),
        "rtmr0": hex::encode(report.rt_mr0),
        "rtmr1": hex::encode(report.rt_mr1),
        "rtmr2": hex::encode(report.rt_mr2),
        "rtmr3": hex::encode(report.rt_mr3),
        "report_data": hex::encode(report.report_data),
    }));
    Ok(())
}
