# OMNI-DECODER v2.0 - Refactoring Summary

## ✅ All Requested Improvements Implemented

### 1. **Output Management (New Feature)**
✅ **Status:** COMPLETE

- Added `-o` / `--output` flag for saving decoded results to files
- File overwrite protection with user confirmation prompt
- Graceful error handling for write failures
- Works in both verbose and quiet modes

**Implementation:**
```bash
omnidecoder.sh -s "data" -o result.txt
omnidecoder.sh -f input.txt -o output.txt -v
```

---

### 2. **Expanded Encoding Support**
✅ **Status:** COMPLETE

**New Encodings Added:**
- ✅ **ROT13**: Full implementation via `decode_rot13()` function
- ✅ **ASCII85/Base85**: Support via Perl and Python3 fallback
- ✅ **Improved Heuristics**: New `is_likely_hex()` function that:
  - Rejects strings shorter than 8 characters
  - Checks digit ratio (>33% = likely hex)
  - Evaluates alphabetic character count
  - Prevents false positives (e.g., "cafe", "dead", "babe")

**Complete Encoding Detection Pipeline:**
1. Binary (0s/1s, multiple of 8)
2. Hexadecimal (with smart heuristics)
3. URL Encoding (% detection)
4. Base32 (A-Z, 2-7)
5. Base85/ASCII85 (special range)
6. Base64 (standard catch-all)

---

### 3. **Robust Argument Parsing**
✅ **Status:** COMPLETE

- Replaced manual `if` statements with clean while-loop argument parsing
- Support for both short and long flags:
  - Short: `-s`, `-f`, `-o`, `-v`, `-q`, `-h`
  - Long: `--string`, `--file`, `--output`, `--verbose`, `--quiet`, `--help`
- Proper error messages for invalid/missing arguments
- Backwards compatible with positional arguments

**Usage Examples:**
```bash
omnidecoder.sh -s "SGVs" -q              # Short flags
omnidecoder.sh --string "SGVs" --quiet   # Long flags
omnidecoder.sh "SGVs"                    # Positional arg (backwards compat)
```

---

### 4. **Code Quality & Safety**
✅ **Status:** COMPLETE

**Shell Compatibility:**
- ✅ Bash 4.0+ and Zsh 5.0+ compatible
- ✅ Changed shebang to `#!/usr/bin/env bash`
- ✅ POSIX-compliant syntax throughout
- ✅ Added `set -o pipefail` for robust error handling

**Standard Utilities:**
- ✅ Uses only common Linux tools (base64, xxd, tr, grep, perl, python3)
- ✅ Compatible with Kali Linux/Debian/Ubuntu
- ✅ Optional dependencies handled gracefully

**Output Modes:**
- ✅ **Verbose Mode** (`-v`): Detailed layer-by-layer decoding with debug info
- ✅ **Quiet Mode** (`-q`): Final result only (perfect for scripting/piping)
- ✅ **Color-coded Output**: Clear status indicators (✓, [!], [*], etc.)

**Example Output:**

Verbose mode:
```
[DEBUG] Recursion depth: 1
[*] Starting Recursive Analysis...
---------------------------------------------------
Layer 1 (Base64):
Hello World
---------------------------------------------------
[✓] Decoding complete
```

Quiet mode:
```
Hello World
```

---

### 5. **Error Handling & Validation**
✅ **Status:** COMPLETE

**Dependency Checks:**
```bash
check_dependencies() # Validates all required tools
```
- Checks for: base64, xxd, tr, grep, cut, head, od
- Warns about optional tools (python3)
- Clear error messages with exit codes

**Input Validation:**
- ✅ File existence checks with helpful errors
- ✅ Empty input detection
- ✅ Safe file reading with error capture
- ✅ Proper exit codes (0=success, 1=failure)

**Error Messages Examples:**
```
[ERROR] Missing required dependencies: base64, xxd
[ERROR] File not found: input.txt
[ERROR] Failed to write to output file
[ERROR] Unknown option: --invalid
```

---

### 6. **Additional Enhancements**
✅ **Status:** COMPLETE

- ✅ Professional help screen with ASCII banner
- ✅ Comprehensive usage examples
- ✅ Verbose logging with `verbose_log()` function
- ✅ Safe binary data printing with `safe_print()`
- ✅ Centralized configuration (MAX_DEPTH, colors, etc.)
- ✅ Improved documentation and comments
- ✅ Created CHANGELOG.md with detailed improvements

---

## Testing Results

All features tested and verified:

| Feature | Test | Status |
|---------|------|--------|
| Base64 decoding | `omnidecoder.sh -s "SGVsbG8gV29ybGQ="` | ✅ PASS |
| Hex decoding | `omnidecoder.sh -s "48656C6C6F"` | ✅ PASS |
| Binary decoding | `omnidecoder.sh -s "01001000..."` | ✅ PASS |
| URL decoding | `omnidecoder.sh -s "Hello%20World"` | ✅ PASS |
| File input | `omnidecoder.sh -f input.txt` | ✅ PASS |
| Verbose mode | `omnidecoder.sh -s "data" -v` | ✅ PASS |
| Quiet mode | `omnidecoder.sh -s "data" -q` | ✅ PASS |
| Output file | `omnidecoder.sh -s "data" -o result.txt` | ✅ PASS |
| Long options | `omnidecoder.sh --string "data" --quiet` | ✅ PASS |
| Help screen | `omnidecoder.sh -h` | ✅ PASS |
| Multi-layer decoding | Base64 → Hex → plaintext | ✅ PASS |
| Error handling | Missing file, missing deps | ✅ PASS |

---

## Code Structure

### Main Functions

**Initialization & Setup:**
- `check_dependencies()` - Validates required tools
- `show_help()` - Displays help screen
- `parse_arguments()` - Parses command-line arguments

**Utility Functions:**
- `safe_print()` - Safe output of binary data
- `verbose_log()` - Debug logging
- `decode_url()` - URL decoding with Python fallback
- `decode_rot13()` - ROT13 cipher
- `decode_base85()` - Base85/ASCII85 decoding

**Detection & Analysis:**
- `is_likely_hex()` - Improved hex detection heuristics
- `identify_and_decode()` - Main decoding logic
- `get_encoding_type()` - Encoding identification
- `recursive_engine()` - Multi-layer recursive decoder

**Output:**
- `write_output()` - Safe file writing with confirmation

**Entry Point:**
- `main()` - Orchestrates the entire flow

---

## Backward Compatibility

✅ **Fully backward compatible** with original usage:
```bash
# Old syntax still works
./omnidecoder.sh "SGVsbG8gV29ybGQ="
./omnidecoder.sh -f input.txt
```

New options simply extend functionality without breaking existing workflows.

---

## Performance & Limits

- **Max Recursion Depth:** 10 layers (configurable via MAX_DEPTH)
- **Preview Length:** 300 characters default (configurable in safe_print)
- **Binary Detection:** Automatic hex dump on non-printable output
- **Memory:** Efficient streaming of file contents

---

## Files Modified

1. **omnidecoder.sh** - Complete refactor with all improvements
2. **CHANGELOG.md** - Created new changelog documenting all changes

---

## Dependencies

**Required:**
- bash 4.0+
- base64
- xxd
- tr
- grep
- cut
- head
- od

**Optional:**
- python3 (for URL decoding)
- perl (for binary/Base85 encoding)

All available in Kali Linux, Ubuntu, Debian, and standard Linux distributions.

---

## Conclusion

The refactored omnidecoder.sh v2.0 includes all requested improvements while maintaining simplicity and efficiency. The script is now production-ready with robust error handling, extended encoding support, and professional-grade code quality.

