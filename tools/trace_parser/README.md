# Trace Parser & Sanitizer Tool

`tools/trace_parser/trace_parser.py` parses EDIABAS `api32.dll` diagnostic execution trace files (`*.trc`) and structured benchmark session logs (`*.jsonl`).

## Features
- **EDIABAS TRC Parsing**: Extracts diagnostic job names, target device identifiers, argument strings, binary data payloads, and execution return statuses (`JOB_STATUS`).
- **Privacy Sanitization**: Automatically scans for and redacts 17-character vehicle identification numbers (VINs) and sensitive cryptographic keys before storage or differential comparison.
- **Conversion to JSONL**: Outputs normalized event streams compatible with `bench_diff.py` and automated verification test harnesses.

## Usage

```bash
# Parse a trace file and display summary:
python3 tools/trace_parser/trace_parser.py traces/sanitized/sanitized_flash_session.trc

# Convert a TRC file to JSONL:
python3 tools/trace_parser/trace_parser.py input.trc -o output.jsonl
```
