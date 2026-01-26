# Omni-Decoder v2.0 - Quick Reference Guide

## Installation & Setup

```bash
# Make executable
chmod +x omnidecoder.sh

# Optional: Add to PATH
sudo cp omnidecoder.sh /usr/local/bin/omnidecoder

# Verify dependencies
which base64 xxd tr grep perl python3
```

---

## Common Usage Patterns

### Basic Decoding

```bash
# Decode Base64 string
./omnidecoder.sh -s "SGVsbG8gV29ybGQ="
# Output: Hello World

# Quiet mode (final result only)
./omnidecoder.sh -s "SGVsbG8gV29ybGQ=" -q
```

### From Files

```bash
# Decode from file
./omnidecoder.sh -f encoded.txt

# Decode and save to file
./omnidecoder.sh -f input.txt -o output.txt

# Verbose mode to see all layers
./omnidecoder.sh -f encoded.txt -v
```

### Advanced Examples

```bash
# Multi-layer decoding with verbose output
./omnidecoder.sh -s "U0dWc2JHOGdWMjl1ZG1WeQ==" -v

# Quiet mode for scripting
./omnidecoder.sh -s "data" -q | xargs echo "Result:"

# Combine with other tools
echo "SGVsbG8=" | xargs ./omnidecoder.sh -s

# Batch decode multiple files
for f in *.txt; do ./omnidecoder.sh -f "$f" -o "decoded_$f"; done

# Save verbose output to log
./omnidecoder.sh -f input.txt -v -o result.txt 2> debug.log
```

---

## Flag Reference

| Flag | Long Form | Argument | Purpose |
|------|-----------|----------|---------|
| `-s` | `--string` | STRING | Decode string input |
| `-f` | `--file` | PATH | Read from file |
| `-o` | `--output` | PATH | Save to output file |
| `-v` | `--verbose` | None | Show all layers |
| `-q` | `--quiet` | None | Final result only |
| `-h` | `--help` | None | Show help |

---

## Encoding Types Supported

### Automatically Detected

| Encoding | Example | Detection |
|----------|---------|-----------|
| **Base64** | `SGVsbG8=` | `A-Za-z0-9+/=` |
| **Hex** | `48656C6C6F` | `0-9A-F` (8+ chars) |
| **Binary** | `01001000...` | `0-1` (mult of 8) |
| **URL** | `Hello%20World` | Contains `%` |
| **Base32** | `JBSWY3DP` | `A-Z2-7=` |
| **Base85** | `BOu!rD]j7` | `!-u` range |

### Manual Decoding

```bash
# ROT13 (if needed, not auto-detected)
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Quick conversion to Hex
echo -n "Hello" | xxd -p

# Quick conversion to Base64
echo -n "Hello" | base64
```

---

## Output Modes Explained

### Default Mode
Shows progress at each layer:
```
[*] Starting Recursive Analysis...
---------------------------------------------------
Layer 1 (Base64):
Hello World
---------------------------------------------------
[✓] Decoding complete
```

### Verbose Mode (`-v`)
Adds debug information:
```
[DEBUG] Recursion depth: 1
[DEBUG] Attempting decode as: Base64
[*] Starting Recursive Analysis...
---------------------------------------------------
Layer 1 (Base64):
Hello World
...
```

### Quiet Mode (`-q`)
Only final result:
```
Hello World
```

---

## File Output Examples

### Save Without Overwrite Check
```bash
# Use quiet mode to bypass confirmation
./omnidecoder.sh -s "data" -o result.txt -q
```

### Overwrite Existing File
```bash
# Responds "y" automatically with quiet mode
echo "y" | ./omnidecoder.sh -s "data" -o existing.txt
```

### Append to File
```bash
# First get the decoded result
result=$(./omnidecoder.sh -s "data" -q)

# Then append to existing file
echo "$result" >> results.txt
```

---

## Troubleshooting

### Missing Dependencies

```bash
# Check which tool is missing
./omnidecoder.sh -s "test"
# Error: Missing required dependencies: base64

# Install on Ubuntu/Debian
sudo apt-get install base64 perl-modules python3

# Install on Fedora/RHEL
sudo dnf install perl-MIME-Base85 python3
```

### File Not Found

```bash
# Verify file exists and is readable
ls -l encoded.txt
file encoded.txt

# Use absolute path if needed
./omnidecoder.sh -f /full/path/to/file.txt
```

### Encoding Not Detected

```bash
# Try verbose mode to see detection process
./omnidecoder.sh -s "suspicious_string" -v

# Check if padding is correct for Base64 (must be % 4 == 0)
# Add padding if needed
./omnidecoder.sh -s "SGVsbG8=" -q
```

### Script Not Executing

```bash
# Check permissions
ls -l omnidecoder.sh
# Should show: -rwxr-xr-x

# Make executable if needed
chmod +x omnidecoder.sh

# Try running with explicit bash
bash omnidecoder.sh -s "data"
```

---

## Performance Tips

### Large Files

```bash
# Use quiet mode for large files (reduces memory)
./omnidecoder.sh -f large_file.txt -q > result.txt

# Check file size first
du -h encoded.txt
wc -l encoded.txt
```

### Batch Processing

```bash
# Process multiple files efficiently
for file in *.encoded; do
    echo "Processing: $file"
    ./omnidecoder.sh -f "$file" -o "${file%.encoded}.txt" -q
done

# Or use GNU parallel for faster processing
parallel './omnidecoder.sh -f {} -o {.}.txt -q' ::: *.encoded
```

### Piping Data

```bash
# Direct piping (without intermediate file)
cat encrypted.txt | xargs ./omnidecoder.sh -s

# Multi-tool pipeline
cat data.txt | base64 -d | xxd -r -p | ./omnidecoder.sh -s "$(cat)"

# Real-world example: decode, validate, output
./omnidecoder.sh -f data.txt -q | grep -E '^[A-Za-z0-9]+$'
```

---

## Security Best Practices

### Safe File Handling

```bash
# Always check file contents before decoding
file unknown.bin
hexdump -C unknown.bin | head

# Decode to isolated temp file first
./omnidecoder.sh -f untrusted.txt -o /tmp/decoded.txt
cat /tmp/decoded.txt | xxd | head
rm /tmp/decoded.txt  # Clean up
```

### Safe Piping

```bash
# Don't pipe directly to shell
./omnidecoder.sh -s "data" | bash  # DANGEROUS!

# Instead, inspect first
./omnidecoder.sh -s "data" -q > script.sh
cat script.sh  # Review contents
# Then execute if safe
bash script.sh
```

### Privilege Handling

```bash
# Don't use with sudo unless necessary
./omnidecoder.sh -f /home/user/data.txt

# If needed for output file:
./omnidecoder.sh -s "data" -q | sudo tee /var/output.txt
```

---

## Integration Examples

### With grep

```bash
# Find and decode multiple encoded strings
grep -E '^[A-Za-z0-9+/]+=*$' data.txt | while read line; do
    ./omnidecoder.sh -s "$line" -q
done
```

### With find

```bash
# Decode all .txt files in directory
find . -name "*.txt" -exec ./omnidecoder.sh -f {} -o {}.decoded \;
```

### With xargs

```bash
# Process files from list
cat file_list.txt | xargs -I {} ./omnidecoder.sh -f {} -q
```

### With sed/awk

```bash
# Extract and decode specific columns
cat data.csv | awk -F',' '{print $2}' | xargs -I {} ./omnidecoder.sh -s {}
```

---

## Exit Codes

| Code | Meaning | Example |
|------|---------|---------|
| `0` | Success | Decoding completed |
| `1` | Error | Missing file, failed write, invalid args |

### Example: Script Handling

```bash
./omnidecoder.sh -f input.txt -o output.txt
if [ $? -eq 0 ]; then
    echo "Decoding successful"
    cat output.txt
else
    echo "Decoding failed"
    exit 1
fi
```

---

## Quick Aliases

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Alias for quick decoding
alias decode='~/path/to/omnidecoder.sh'

# Alias with quiet mode
alias decodeq='~/path/to/omnidecoder.sh -q'

# Alias with verbose mode
alias decodev='~/path/to/omnidecoder.sh -v'

# Function for inline use
dec() { ~/path/to/omnidecoder.sh -s "$1" -q; }
```

Then use:
```bash
decode -s "SGVsbG8="
decodeq -f file.txt
decodev -s "data"
dec "SGVsbG8="
```

---

## Getting Help

```bash
# Display help screen
./omnidecoder.sh -h
./omnidecoder.sh --help

# Check version/script info
head -20 omnidecoder.sh | grep "Description"

# Check dependencies
./omnidecoder.sh -h | grep "REQUIRED"
```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "No input provided" | Use `-s` or `-f` flag |
| "File not found" | Check path with `ls` |
| "Unknown option" | Use `-h` to see available flags |
| Output is garbage | Likely binary payload; use `-v` to inspect layers |
| Decoding too slow | Check file size; use `-q` mode |
| Not all layers decoded | Check MAX_DEPTH (default: 10) |

