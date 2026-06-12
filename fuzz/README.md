# Fuzz

This directory contains fuzzing targets for dress-up as well as helper scripts, using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer).

## Contents

### Targets

#### pure mutation-based:
- `raw_unauth`: fuzzing functions on an unauthenticated manifest
- `raw_auth`: fuzzing functions on an authenticated manifest

#### structure-aware:
- `suit_manifest_auth`: wrapping fuzzer input into syntactically valid SUIT Envelope with valid authentication block and using this input for fuzzing the authenticated manifest

### Helper Scripts

- `run_fuzz.sh`: runs the specified target and exports exit code and time-to-crash into a JSON file (**Important**: build the target before running it with the script because otherwise the build process will be included in the measured time)
- `fuzz_cov.sh`: generates code coverage reports (HTML and text) for specified target

## Setup

Install Rust nightly toolchain:
```bash
rustup update nightly && rustup default nightly
```

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

Install llvm-tools (needed for coverage reports):
```bash
rustup component add --toolchain nightly llvm-tools-preview
```

## Usage

### Running targets

List available targets:
```bash
cargo fuzz list
```

Run a specific target:
```bash
cargo fuzz run <target_name>
```

Run with time limit (example: 60 seconds):
```bash
cargo fuzz run <target_name> -- -max_total_time=60
```

Run with timeout (example: 2 seconds):
```bash
cargo fuzz run <target_name> -- -timeout=2
```

### Measure runtime / time-to-crash

To get some metrics for evaluating the different targets, you can use the helper script `run_fuzz.sh`. This will run the specified target with your arguments and save the target name, exit code and elapsed time to a JSON file.

**Important**: For comparable results, you should build the target beforehand. Otherwise, the build process will be included in the measured time, which can distort the results.

Build the target:
```bash
cargo fuzz build <target_name>
```

Run the script (execute from project root):
```bash
./fuzz/run_fuzz.sh <target_name> -- [libFuzzer_arguments]
```
example:
```bash
./fuzz/run_fuzz.sh raw_unauth -- -timeout=30 -max_total_time=3600
```

The JSON with the results can then be found in `fuzz/results/metrics`.

### Generate coverage reports

For an overview, how much of the projects code was covered by the specific target, the helper script `fuzz_cov.sh` will generate an HTML and a text code coverage report.

Run the script (execute from project root):
```bash
./fuzz/fuzz_cov.sh <target_name>
```

The coverage reports can then be found in `fuzz/results/cov_reports`.
