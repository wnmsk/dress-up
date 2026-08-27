# Fuzz

This directory contains fuzzing tests for dress-up, using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (LibFuzzer).

## Contents

### Targets
located in `fuzz_targets/`:

- `unaware`: Tries to parse arbitrary bytes as a complete SUIT Manifest and executes dress-up functions on it.
- `envlp_wrap`: Wraps arbitrary bytes into syntactically valid SUIT Envelope with valid authentication and tries to parse and call functions on it.



## Setup

Install Rust nightly toolchain:
```bash
rustup update nightly && rustup default nightly
```

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```


## Usage

### Using Corpus

There exists one prepopulated corpus for each of the two targets:
- `corpus_complete_manifest`: contains examples of complete SUIT Manifests including envelope; used by the target `unaware`
- `corpus_inner_manifest`: contains examples of only inner manifests without envelope or auth bloc; used by the target `envlp_wrap`

The files contained in those directories can be used as "seed" for the target.

To use the prepopulated corpus, you need to copy it before running the corresponding target:
```bash
cp -r <corpus_prepop>/* <corpus_dir>
```

For example, for the `unaware` target (executed from project root):
```bash
cp -r fuzz/corpus_complete_manifest fuzz/corpus_unaware
```

### Running targets

List available targets:
```bash
cargo fuzz list
```

Run a specific target:
```bash
cargo fuzz run <target_name>
```

Run the target with a prepopulated corpus directory:
```bash
cargo fuzz run <target_name> -- <corpus_dir>
```

Run with time limit (example: 60 seconds):
```bash
cargo fuzz run <target_name> -- -max_total_time=60
```

Run with timeout (example: 2 seconds):
```bash
cargo fuzz run <target_name> -- -timeout=2
```

For other possible parameters, have a look at the [LibFuzzer docs](https://llvm.org/docs/LibFuzzer.html).


## Example

Running the target `envlp_wrap` (from project root):

Copy the corpus directory
```bash
cp -r fuzz/corpus_inner_manifest fuzz/corpus_envlp_wrap
```
Run the target with a timeout of 5 seconds for a total duration of 5 minutes on the seed corpus
```bash
cargo fuzz run envlp_wrap -- fuzz/corpus_envlp_wrap --timeout=5 -max_total_time=300
```

---
---

# Evaluation

To evaluate the different stages of structure-awareness, there are some test scripts included.

## Setup

To be able to run the test code, you need to have `llvm-tools-preview` and `matplotlib` installed:
```
rustup component add --toolchain nightly llvm-tools-preview
```
```
pip install matplotlib
```

*note:* The script automatically checks for a `.venv` directory in the root directory and activates it if present.

## Run the test script

The test script and the other scripts that it calls can be found in the directory `scripts`.

Execute the following from the project's root directory:
```bash
./fuzz/scripts/run_tests.sh [--skip-cov] <runtime> [TARGET ...]
```

Example:
```bash
./fuzz/scripts/run_tests.sh 3600
```
This will run all available targets after each other for 1h each.

If you want to only run specific targets, you can list them after the runtime
```bash
./fuzz/scripts/run_tests.sh 3600 unaware envlp_wrap
```

You also can add a `--skip-cov` argument, if you do not want a coverage report generated.
This feature was mainly added for CI usage.

After the script is done, you can find the following in the `results` directory:
- `artifacts`/`corpus`: The corresponding directories from the fuzzing run.
- `cov_reports`: Coverage reports (text and HTML) for each target and for all combined.
- `csv`: CSV files parsed from the fuzzer output from each run, containing all the necessary information for evaluating the run.
- `metrics`: JSON files for each target that contain the exit code of the run and the actual runtime. Helpful to indicate if the fuzzer did crash and after what time.
- `plots`: Plots generated out of the CSV files, showing the coverage, exec/s and corpus growth over time.
- `run_summary`: Quick summaries with the most important information about the runs.
- `test_logs`: The complete fuzzer output of the run preceded by hardware information about the machine used to run the tests.

## Other tools:

There are also some other helper scripts included in the `tools` directory that generally come in handy:

- `convert_suit_to_inner.sh`: A small bash script that calls the script `manifest_extractor.py` on all SUIT manifest files in a directory.
- `line_counter.py`: A Python script that counts the LoC of a Rust file, excluding comments and newlines.
- `manifest_extractor.py`: A Python script that extracts the inner manifest from a SUIT envelope.
- `metrics_parser.py`: A Python script that can parse the `LibFuzzer` output to a CSV or JSON file.
- `metrics_plotter.py`: A Python script that takes a CSV file from `metrics_parser.py` and plots a graph showing the coverage, exec/s and corpus development during the run.
- `suit_decode.py`: A Python script that decodes the contents of a CBOR encoded manifest to JSON.

*note:* The scripts `manifest_extractor.py` and `suit_decode.py` need the Python package `cbor2` installed.
