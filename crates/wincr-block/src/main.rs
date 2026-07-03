use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wincr_block::{
    coverage_report_for_suite, emit_recovery_report, emit_suite, recover_blocks_from_path,
    validate_candidate_mapping, CandidateValidationOptions, CoverageOptions, SuiteOptions,
};

#[derive(Debug, Parser)]
#[command(
    name = "wincr-block",
    about = "Rust block-conformance analysis and candidate validation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Recover executable block obligations from a PE image.
    Recover {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },

    /// Emit a private block conformance suite.
    EmitSuite {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "trace")]
        traces: Vec<PathBuf>,
        #[arg(long)]
        max_cases_per_block: Option<usize>,
    },

    /// Rebuild suite characterization from a trace file.
    Characterize {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long = "trace", required = true)]
        traces: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        max_cases_per_block: Option<usize>,
    },

    /// Report whether all recovered blocks are covered or explicitly waived.
    Coverage {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        waivers: Option<PathBuf>,
        #[arg(long)]
        allow_incomplete_side_effects: bool,
    },

    /// Validate candidate block mapping and available conformance cases.
    ValidateCandidate {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        mapping: PathBuf,
        #[arg(long)]
        waivers: Option<PathBuf>,
        #[arg(long)]
        candidate_trace: Option<PathBuf>,
        #[arg(long)]
        allow_incomplete_characterization: bool,
        #[arg(long)]
        allow_incomplete_side_effects: bool,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("wincr-block: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Recover { binary, out } => {
            let recovery = recover_blocks_from_path(&binary)?;
            emit_recovery_report(&recovery, &out)?;
        }
        Command::EmitSuite {
            binary,
            out,
            traces,
            max_cases_per_block,
        } => {
            emit_suite(
                &binary,
                &out,
                &SuiteOptions {
                    traces,
                    max_cases_per_block,
                },
            )?;
        }
        Command::Characterize {
            binary,
            traces,
            out,
            max_cases_per_block,
        } => {
            emit_suite(
                &binary,
                &out,
                &SuiteOptions {
                    traces,
                    max_cases_per_block,
                },
            )?;
        }
        Command::Coverage {
            suite,
            waivers,
            allow_incomplete_side_effects,
        } => {
            let report = coverage_report_for_suite(
                &suite,
                &CoverageOptions {
                    waivers,
                    allow_incomplete_side_effects,
                },
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|err| format!("serialize coverage report: {err}"))?
            );
            if report.status != "pass" {
                return Err("block coverage gate failed".to_string());
            }
        }
        Command::ValidateCandidate {
            suite,
            mapping,
            waivers,
            candidate_trace,
            allow_incomplete_characterization,
            allow_incomplete_side_effects,
        } => {
            let report = validate_candidate_mapping(
                &suite,
                &mapping,
                &CandidateValidationOptions {
                    allow_incomplete_characterization,
                    allow_incomplete_side_effects,
                    waivers,
                    candidate_trace,
                },
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|err| format!("serialize validation report: {err}"))?
            );
            if report.status != "pass" {
                return Err("candidate validation failed".to_string());
            }
        }
    }
    Ok(())
}
