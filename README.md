# Omni-Decoder v2.0

A powerful, recursive multi-format decoder for cybersecurity professionals and ethical hackers. Automatically detects and decodes multiple encoding layers until plaintext is revealed.

## ✨ What's New in v2.0

- **Output File Support** - Save decoded results directly to files (`-o` flag)
- **ROT13 Decoding** - Support for ROT13 cipher decoding
- **ASCII85/Base85** - Extended encoding format support
- **Improved Hex Detection** - Smart heuristics to prevent false positives
- **Verbose & Quiet Modes** - Debug output or clean results (`-v` / `-q` flags)
- **Better Error Handling** - Dependency checking and clear error messages
- **Shell Compatibility** - Works with Bash 4.0+, Zsh 5.0+, and POSIX environments

## 🚀 Quick Start

```bash
# Make it executable
chmod +x omnidecoder.sh

# Decode a Base64 string
./omnidecoder.sh -s "SGVsbG8gV29ybGQ="
# Output: Hello World

# See detailed examples
cat START_HERE.md
```

## ✨ Features

### Automated Encoding Detection
Intelligently identifies and decodes multiple encoding formats automatically:
- **Base64** - Standard and URL-safe variants
- **Base32** - RFC 4648 standard
- **Base85 / ASCII85** - Extended encoding format
- **Hexadecimal (Base16)** - Binary to text conversion
- **Binary (Base2)** - 8-bit binary encoding
- **URL Encoding** - Percent-encoded strings
- **ROT13** - Simple rotation cipher

### Recursive Multi-Layer Decoding
Automatically peels away layers of encoding to reveal plaintext:
```
Input:  WTJoaGJHeGxibWRs
Layer 1 (Base64): Y2hhbGxlbmdl
Layer 2 (Base64): challenge
Output: challenge ✓
```

### Professional Output Modes
- **Default**: Shows progress at each layer
- **Verbose** (`-v`): Debug output with detailed analysis
- **Quiet** (`-q`): Final result only (perfect for scripting)

### Safe File Operations
- Save decoded results to files with `-o` flag
- Automatic overwrite confirmation
- Error handling for permission issues
- Support for both file and string input

### Binary Safety
Detects shellcode and binary payloads with safe hex dump display instead of corrupting your terminal.

## 💻 Installation

Omni-Decoder is a standalone Bash script. Only standard Linux utilities are required:

```bash
# Clone the repository
git clone https://github.com/SecScholar/Omni-Decoder.git
cd Omni-Decoder

# Make executable
chmod +x omnidecoder.sh

# Optional: Add to PATH
sudo cp omnidecoder.sh /usr/local/bin/omnidecoder
```

## 📖 Usage

### Basic Decoding
```bash
# Decode a string
./omnidecoder.sh -s "SGVsbG8gV29ybGQ="

# Decode from file
./omnidecoder.sh -f encoded.txt

# Save to file
./omnidecoder.sh -s "data" -o result.txt
```

### Advanced Options
```bash
# Verbose mode (see all layers)
./omnidecoder.sh -f input.txt -v

# Quiet mode (final result only)
./omnidecoder.sh -s "data" -q

# Combine flags
./omnidecoder.sh -f input.txt -o output.txt -v

# Show help
./omnidecoder.sh -h
```

### Real-World Examples
```bash
# Multi-layer decoding with progress
./omnidecoder.sh -s "U0dWc2JHOGdWMjl1ZG1WeQ==" -v

# Batch process files (expiremental, please report any issues with this in the issues section)
for f in *.txt; do ./omnidecoder.sh -f "$f" -q; done

# Integration with other tools
echo "encoded_data" | xargs ./omnidecoder.sh -s
```

## 📚 Documentation

| Document | Purpose | Length |
|----------|---------|--------|
| **[START_HERE.md](START_HERE.md)** | Quick 2-minute start | 135 lines |
| **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** | Complete usage guide | 409 lines |
| **[CHANGELOG.md](CHANGELOG.md)** | What's new in v2.0 | 185 lines |

## 🔧 Requirements

### Required (Usually Pre-installed)
- bash 4.0+
- base64
- xxd
- tr
- grep

### Optional (Recommended)
- python3 (for enhanced URL decoding)
- perl (for advanced encoding support)

All available in:
- Ubuntu/Debian: `sudo apt-get install base64 perl python3`
- Fedora/RHEL: `sudo dnf install perl-MIME-Base85 python3`
- Kali Linux: Pre-installed

## 📝 Command Reference

```bash
Usage: omnidecoder.sh [OPTIONS] [INPUT]

OPTIONS:
  -s, --string <value>   Input string to decode
  -f, --file <path>      Read input from file
  -o, --output <path>    Save decoded output to file
  -v, --verbose          Show detailed decoding layers
  -q, --quiet            Output only final result
  -h, --help             Display help message

EXAMPLES:
  omnidecoder.sh -s "SGVsbG8gV29ybGQ="
  omnidecoder.sh -f encoded.txt -v
  omnidecoder.sh -s "data" -o result.txt -q
```

## 🎯 Use Cases

- **CTF Challenges** - Quickly solve encoding-based CTF problems
- **Security Analysis** - Analyze obfuscated malware or shellcode
- **Penetration Testing** - Decode intercepted or captured data
- **Reverse Engineering** - Peel back encoding layers systematically
- **DevOps** - Decode configuration values and credentials
- **Data Recovery** - Restore encoded or corrupted data

## 🔐 Security & Privacy

- **No Remote Calls** - Entirely offline, no data transmission
- **No External Dependencies** - Uses only standard Linux utilities
- **Safe Handling** - Binary payload detection prevents terminal corruption
- **No Logging** - No data stored or logged
- **Open Source** - Full code transparency, peer-reviewed

## 📊 Performance

- Handles files up to system memory limit
- Recursive depth capped at 10 layers (configurable)
- Optimized string processing with minimal memory overhead
- Instant results for typical encoding scenarios

## 🤝 Contributing

Contributions are welcome! Please:
1. Test your changes thoroughly
2. Follow the existing code style
3. Update documentation as needed
4. Submit a pull request with clear description

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## ⚠️ Disclaimer

This tool is provided for educational and professional cybersecurity purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors are not responsible for any misuse.

## 🙏 Acknowledgments

Built with attention to code quality, security, and user experience. Tested across multiple Linux distributions and shell environments.

---

**Questions?** Start with [START_HERE.md](START_HERE.md) or check [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for detailed examples.

**Found a bug?** Open an issue on GitHub.

**Want to contribute?** Pull requests welcome!
