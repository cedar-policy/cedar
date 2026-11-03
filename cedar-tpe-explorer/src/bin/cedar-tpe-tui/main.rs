/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Interactive explorer for Cedar type-aware partial evaluation.
//!
//! Build up a partial request on the left; watch the residual policies on
//! the right. SymCC + CVC5 suggest small sets of facts that settle a policy.

mod app;
mod files;
mod theme;
mod ui;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Directory to discover `*.cedarschema` / `*.cedar` files in.
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Schema file (Cedar or JSON syntax). Discovered if omitted.
    #[arg(long)]
    schema: Option<PathBuf>,
    /// Policy file(s). All `*.cedar` files in DIR if omitted.
    #[arg(long)]
    policies: Vec<PathBuf>,
    /// Per-query CVC5 time limit in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    solver_timeout_ms: u32,
}

fn main() {
    let args = Args::parse();
    let paths = match files::discover(&args.dir, args.schema, args.policies) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cedar-tpe-tui: {e}");
            std::process::exit(2);
        }
    };
    let app = match app::App::load(&paths, args.solver_timeout_ms) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("cedar-tpe-tui: {e}");
            std::process::exit(1);
        }
    };
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal);
    ratatui::restore();
    if let Err(e) = res {
        eprintln!("cedar-tpe-tui: {e}");
        std::process::exit(1);
    }
}
