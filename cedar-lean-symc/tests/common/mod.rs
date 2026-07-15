//! Transpile Cedar → Lean and compile the result against a minimal stub of the
//! `Cedar.Spec` AST (`tests/cedar_spec_stub.lean`), proving emitted output is
//! type-correct Cedar AST rather than just a matching string.
//!
//! Requires a Lean 4 toolchain: `lean` must be on `PATH`. `lean` is run from
//! `tests/`, whose `lean-toolchain` file pins the version (elan resolves the
//! pin from the working directory, not the source-file path).

use std::path::PathBuf;
use std::process::Command;

use cedar_lean_symc::{
    policyset_to_lean, policyset_to_lean_with_properties, policysets_to_lean_with_properties,
    Property,
};

/// The crate's `tests/` directory.
fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Transpile `src`, type-check it against the stub, and return the emitted Lean.
pub fn lean(src: &str) -> String {
    let emitted = policyset_to_lean(src).expect("policy set should transpile");
    typecheck(src, &emitted);
    emitted
}

/// Like [`lean`], but returns just the `Expr` term of a single `when` condition
/// so expression-focused snapshots stay small.
pub fn cond_expr(e: &str) -> String {
    let src = format!("permit(principal, action, resource) when {{ {e} }};");
    let out = lean(&src);
    let start = out
        .find("[⟨.when, ")
        .expect("expected a when-condition in output");
    let tail = &out[start + "[⟨.when, ".len()..];
    let end = tail.rfind("⟩] ⟩").expect("expected condition terminator");
    tail[..end].to_string()
}

/// Like [`lean`], but also emits the given properties and type-checks the whole
/// thing (policies + theorem stubs) against the stub.
pub fn lean_with_properties(src: &str, props: &[Property]) -> String {
    let emitted =
        policyset_to_lean_with_properties(src, props).expect("policy set should transpile");
    typecheck(src, &emitted);
    emitted
}

/// Two-set variant: emits both sets plus the (possibly binary) properties and
/// type-checks against the stub.
pub fn lean_two_with_properties(src: &str, src_b: &str, props: &[Property]) -> String {
    let emitted = policysets_to_lean_with_properties(src, src_b, props)
        .expect("policy sets should transpile");
    typecheck(src, &emitted);
    emitted
}

pub fn stub_path() -> PathBuf {
    tests_dir().join("cedar_spec_stub.lean")
}

fn run_lean(path: &PathBuf) -> std::process::Output {
    match Command::new("lean").arg(path).current_dir(tests_dir()).output() {
        Ok(output) => output,
        // A clear, actionable message beats the default "No such file" error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => panic!(
            "`lean` was not found on PATH.\n\
             These tests type-check emitted output against the Cedar.Spec stub and \
             require a Lean 4 toolchain.\n\
             Install it via elan (https://github.com/leanprover/elan) and ensure \
             `lean` is on your PATH:\n    \
             curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh\n\
             Then re-run `cargo test`."
        ),
        Err(e) => panic!("failed to run `lean`: {e}"),
    }
}

pub fn typecheck(src: &str, emitted: &str) {
    // Splice the stub in for the emitted `import Cedar.Spec` so `lean` needs no
    // search path.
    let stub = std::fs::read_to_string(stub_path()).expect("stub file should be readable");
    let body: String = emitted
        .lines()
        .filter(|l| l.trim() != "import Cedar.Spec")
        .collect::<Vec<_>>()
        .join("\n");
    let combined = format!("{stub}\n{body}\n");

    let mut file = TempLean::new();
    file.write(combined.as_bytes());
    let output = run_lean(file.path());

    assert!(
        output.status.success(),
        "emitted Lean failed to type-check against the Cedar.Spec stub.\n\
         --- cedar source ---\n{src}\n\
         --- lean stdout ---\n{}\n--- lean stderr ---\n{}\n--- combined source ---\n{combined}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Temp `.lean` file removed on drop (including on unwind).
struct TempLean {
    path: PathBuf,
}

impl TempLean {
    fn new() -> Self {
        // Unique per call so concurrent tests don't collide.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cedar_lean_symc_{}_{n}.lean", std::process::id()));
        TempLean { path }
    }
    fn path(&self) -> &PathBuf {
        &self.path
    }
    fn write(&mut self, bytes: &[u8]) {
        std::fs::write(&self.path, bytes).expect("write combined Lean source");
    }
}

impl Drop for TempLean {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
