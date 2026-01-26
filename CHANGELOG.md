# Omni-Decoder v2.0 - Changelog

## Major Improvements & New Features

### 1. **Output Management (New Feature)**
- ✅ Implemented `-o` / `--output` flag to save decoded results to a file
- ✅ File overwrite protection with user confirmation
- ✅ Graceful error handling for write failures

**Usage:**
```bash
omnidecoder.sh -s "SGVsbG8gV29ybGQ=" -o result.txt
omnidecoder.sh -f input.txt -o output.txt
```

### 2. **Expanded Encoding Support**
- ✅ **ROT13** decoding (utility function `decode_rot13()` available)
- ✅ **ASCII85/Base85** decoding support via Perl or Python fallback
- ✅ Improved heuristic logic with `is_likely_hex()` function to distinguish between:
  - Hex strings (must be 8+ chars, high digit count, or few alpha chars)
  - Plain text words (short strings like "cafe", "dead" treated as text, not hex)
  - Base64, Base32, and URL encoding
- ✅ Reduced false positives in encoding detection

**Supported Encodings:**
- Base64 (standard & URL-safe)
- Base32
- Base85 / ASCII85
- Hexadecimal (Hex)
- Binary (Base2)
- URL Encoding (with Python3/Python fallback)
- ROT13 (available for manual use)

### 3. **Robust Argument Parsing**
- ✅ Replaced manual `if` statement parsing with `getopts` for clean flag handling
- ✅ Supports both short flags (`-s`, `-f`, `-o`, `-v`, `-q`, `-h`) and long options (`--string`, `--file`, `--output`, `--verbose`, `--quiet`, `--help`)
- ✅ Proper error messages for invalid or missing arguments
- ✅ Centralized argument parsing in `parse_arguments()` function

**Supported Flags:**
- `-s, --string <value>` - Input string to decode
- `-f, --file <path>` - Read input from file
- `-o, --output <path>` - Save decoded output to file
- `-v, --verbose` - Show detailed decoding layers
- `-q, --quiet` - Output only final result
- `-h, --help` - Display help message

### 4. **Code Quality & Safety**
- ✅ Bash shebang changed to `#!/usr/bin/env bash` for better portability
- ✅ Added `set -o pipefail` for robust error handling in pipelines
- ✅ Script compatible with both **Bash** and **Zsh** (POSIX-compliant syntax)
- ✅ Uses only standard Linux utilities (base64, xxd, tr, grep, perl, python3)
- ✅ **Verbose Mode** (`-v`): Shows detailed "layer peeling" process with debug info
- ✅ **Quiet Mode** (`-q`): Outputs only the final result (useful for scripting)
- ✅ Color-coded output with helpful status indicators

**Utilities Used:**
- `base64` - Base64 encoding/decoding
- `xxd` - Hex viewing and conversion
- `tr` - Text translation (ROT13)
- `grep` - Pattern matching
- `perl` - Advanced encoding (binary, Base85)
- `python3` - URL decoding & Base85 fallback

### 5. **Error Handling & Validation**
- ✅ `check_dependencies()` - Validates all required tools are installed
- ✅ File existence checks before reading
- ✅ Graceful handling of missing dependencies with helpful error messages
- ✅ Input validation (empty input, invalid files)
- ✅ Safe file operations with overwrite confirmation

**Error Messages Include:**
- Missing required dependencies
- File not found errors
- File write failures
- Invalid command-line arguments

### 6. **Additional Improvements**
- ✅ New colorized help screen with ASCII banner
- ✅ Better documentation and usage examples
- ✅ Improved `safe_print()` function with max preview length parameter
- ✅ New `verbose_log()` function for debug output
- ✅ Centralized configuration (MAX_DEPTH, color codes)
- ✅ Proper exit codes (0 for success, 1 for failure)

---

## Usage Examples

### Basic Decoding
```bash
# Decode Base64 string
./omnidecoder.sh -s "SGVsbG8gV29ybGQ="
# Output: Hello World

# Decode from file
./omnidecoder.sh -f encoded.txt
```

### With Output Options
```bash
# Save to file with overwrite protection
./omnidecoder.sh -s "data" -o result.txt

# Quiet mode (useful for piping)
./omnidecoder.sh -s "SGVsbG8gV29ybGQ=" -q > clean_output.txt
```

### Verbose Mode
```bash
# See detailed decoding process
./omnidecoder.sh -f input.txt -v

# Combination: verbose input + save output
./omnidecoder.sh -s "data" -v -o result.txt
```

---

## Technical Details

### Encoding Detection Order
The script uses an intelligent detection pipeline:

1. **Binary** (0s/1s, multiple of 8)
2. **Hex** (0-9, A-F, even length, with smart heuristics)
3. **URL Encoding** (contains %)
4. **Base32** (A-Z, 2-7, with padding)
5. **Base85/ASCII85** (special character range)
6. **Base64** (A-Z, a-z, 0-9, +, /, =)

### Heuristics for Hex Detection
The improved `is_likely_hex()` function prevents false positives by:
- Rejecting strings shorter than 8 characters
- Checking for high digit count (>33% digits)
- Evaluating alphabetic character ratio
- Avoiding decoding of English words accidentally matching hex pattern

### Multi-Layer Decoding
The recursive engine automatically:
- Detects encoding at each layer
- Decodes progressively
- Stops at plaintext or binary payload
- Respects MAX_DEPTH limit (10 levels by default)
- Shows layer-by-layer progress in verbose mode

---

## Compatibility

- **Shell:** Bash 4.0+, Zsh 5.0+
- **OS:** Linux (Ubuntu, Debian, Kali Linux, etc.)
- **Dependencies:** Base64, XXD, TR, GREP, PERL, PYTHON3 (optional)

---

## Testing

The refactored script has been tested with:
- ✅ Base64 decoding
- ✅ Hexadecimal decoding
- ✅ Binary decoding
- ✅ URL decoding
- ✅ Verbose mode output
- ✅ Quiet mode output
- ✅ File output with confirmation
- ✅ Multi-layer recursive decoding

---

## Version History

### v2.0 (Current)
- Complete refactor with all requested improvements
- Output file support
- Expanded encoding formats
- getopts-based argument parsing
- Comprehensive error handling
- Verbose and quiet modes

### v1.0 (Original)
- Basic recursive decoder
- Support for Base64, Base32, Hex, Binary, URL encoding
- Manual argument parsing

