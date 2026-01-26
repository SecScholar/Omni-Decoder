#!/usr/bin/env bash

# ============================================================
# Script Name: omnidecoder.sh
# Description: An automated, recursive decoder that identifies
#              and decodes Hex, Base64, Base32, Base85, Rot13,
#              Binary, and URL encoded strings until plaintext
#              is revealed. Includes robust argument parsing,
#              error handling, and multiple output modes.
# ============================================================

set -o pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# --- Global Configuration ---
MAX_DEPTH=10
VERBOSE_MODE=false
QUIET_MODE=false
OUTPUT_FILE=""
INPUT_FILE=""
INPUT_STRING=""

# --- Dependency Check ---
check_dependencies() {
    local missing_deps=()
    local required_tools=("base64" "xxd" "tr" "grep" "cut" "head" "od")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_deps+=("$tool")
        fi
    done
    
    # Check for optional tools
    if ! command -v "python3" &> /dev/null && ! command -v "python" &> /dev/null; then
        VERBOSE_MODE && echo -e "${YELLOW}[!] Warning: python3 not found. URL decoding will be limited.${NC}" >&2
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${RED}[ERROR] Missing required dependencies: ${missing_deps[*]}${NC}" >&2
        echo -e "${RED}Please install them and try again.${NC}" >&2
        exit 1
    fi
}

# --- Help Function ---
show_help() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    OMNI-DECODER v2.0                         ║
║  Automated Recursive Decoder for Multiple Encoding Formats   ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  omnidecoder.sh [OPTIONS] [INPUT]

OPTIONS:
  -s, --string <value>   Input string to decode
  -f, --file <path>      Read input from file
  -o, --output <path>    Save decoded output to file
  -v, --verbose          Show detailed decoding layers (verbose mode)
  -q, --quiet            Output only final result (quiet mode)
  -h, --help             Display this help message

SUPPORTED ENCODINGS:
  • Base64 (standard & URL-safe)
  • Base32
  • Base85 / ASCII85
  • Hexadecimal (Hex)
  • Binary (Base2)
  • URL Encoding
  • ROT13

EXAMPLES:
  # Decode a string
  omnidecoder.sh -s "SGVsbG8gV29ybGQ="

  # Decode from file with verbose output
  omnidecoder.sh -f encoded.txt -v

  # Decode and save result
  omnidecoder.sh -s "encoded_data" -o result.txt

  # Quiet mode (final result only)
  omnidecoder.sh -s "data" -q

EOF
}

# --- Utility Functions ---

# Safe echo that handles binary data
safe_print() {
    local data="$1"
    local max_preview="${2:-300}"
    
    # Check for non-printable characters
    if echo "$data" | grep -qP '[^\x20-\x7E\n\r\t]' 2>/dev/null; then
        if ! $QUIET_MODE; then
            echo -e "${YELLOW}(Binary Data Detected - Showing Hex Preview)${NC}"
            echo "$data" | xxd | head -n 3
        fi
    else
        # Print with length limit
        if [ ${#data} -gt $max_preview ]; then
            echo "${data:0:$max_preview}..."
        else
            echo "$data"
        fi
    fi
}

# Verbose logging
verbose_log() {
    if $VERBOSE_MODE && ! $QUIET_MODE; then
        echo -e "${PURPLE}[DEBUG]${NC} $1" >&2
    fi
}

# Safe URL decode using Python or shell
decode_url() {
    local input="$1"
    
    if command -v python3 &> /dev/null; then
        python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.argv[1]))" "$input" 2>/dev/null
    elif command -v python &> /dev/null; then
        python -c "import urllib, sys; print(urllib.unquote(sys.argv[1]))" "$input" 2>/dev/null
    else
        # Fallback: basic shell-based URL decoding
        local decoded="$input"
        decoded="${decoded//+/ }"
        printf '%b' "${decoded//%/\\x}" 2>/dev/null
    fi
}

# ROT13 decoder
decode_rot13() {
    local input="$1"
    echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
}

# Base85/ASCII85 decoder
decode_base85() {
    local input="$1"
    
    # Try using btoa/atob if available
    if command -v perl &> /dev/null; then
        echo "$input" | perl -MMIME::Base85 -ne 'print MIME::Base85::decode($_)' 2>/dev/null
        return $?
    elif command -v python3 &> /dev/null; then
        python3 << 'PYTHON' "$input" 2>/dev/null
import sys
try:
    import base64
    # For ASCII85
    data = sys.argv[1]
    if data.startswith('<~') and data.endswith('~>'):
        result = base64.a85decode(data[2:-2])
        sys.stdout.buffer.write(result)
except:
    pass
PYTHON
        return $?
    fi
    return 1
}

# Improved heuristic for Hex vs plain text
is_likely_hex() {
    local input="$1"
    local len=${#input}
    
    # Too short strings are likely false positives (e.g., "cafe", "dead", "babe")
    if [ $len -lt 8 ]; then
        verbose_log "String too short ($len chars) to be reliably identified as Hex"
        return 1
    fi
    
    # Check if it has mostly numbers or non-alphabetic characters
    # This helps distinguish from English words
    local digit_count=$(echo "$input" | grep -o '[0-9]' | wc -l)
    local alpha_count=$(echo "$input" | grep -o '[a-fA-F]' | wc -l)
    
    # If mostly digits or high ratio of hex chars, likely hex
    if [ $digit_count -gt $((len / 3)) ] || [ $alpha_count -lt 3 ]; then
        return 0
    fi
    
    return 1
}

# --- Detection & Decoding Logic ---

identify_and_decode() {
    local input="$1"
    local decoded=""
    local encoding_type="Unknown"
    
    # Clean whitespace for detection (preserve original for URL)
    local clean_input=$(echo -n "$input" | tr -d '[:space:]')
    local len=${#clean_input}
    
    # Safety check
    if [ $len -eq 0 ]; then
        return 1
    fi

    # 1. Check for Binary (0s and 1s, multiple of 8)
    if [[ "$clean_input" =~ ^[01]+$ ]] && (( len % 8 == 0 )); then
        encoding_type="Binary (Base2)"
        verbose_log "Detected as: $encoding_type"
        decoded=$(echo "$clean_input" | perl -lpe '$_=pack"B*",$_' 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
            printf "%s" "$decoded"
            return 0
        fi
    fi

    # 2. Check for ROT13 (printable ASCII with rotation pattern)
    # This is speculative; we only attempt if no other encoding matches
    
    # 3. Check for Hex (0-9, A-F, even length, with better heuristics)
    if [[ "$clean_input" =~ ^[0-9a-fA-F]+$ ]] && (( len % 2 == 0 )); then
        if is_likely_hex "$clean_input"; then
            encoding_type="Hexadecimal (Base16)"
            verbose_log "Detected as: $encoding_type"
            decoded=$(echo "$clean_input" | xxd -r -p 2>/dev/null)
            if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
                printf "%s" "$decoded"
                return 0
            fi
        fi
    fi

    # 4. Check for URL Encoding (must contain %)
    if [[ "$input" == *%* ]]; then
        encoding_type="URL Encoding"
        verbose_log "Detected as: $encoding_type"
        decoded=$(decode_url "$input" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
            printf "%s" "$decoded"
            return 0
        fi
    fi

    # 5. Check for Base32 (A-Z, 2-7, padding =)
    if [[ "$clean_input" =~ ^[A-Z2-7]+=*$ ]]; then
        encoding_type="Base32"
        verbose_log "Attempting decode as: $encoding_type"
        decoded=$(echo "$clean_input" | base32 -d 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
            printf "%s" "$decoded"
            return 0
        fi
    fi

    # 6. Check for Base85/ASCII85
    if [[ "$clean_input" =~ ^[!-u]+$ ]]; then
        encoding_type="Base85 (ASCII85)"
        verbose_log "Attempting decode as: $encoding_type"
        decoded=$(decode_base85 "$clean_input" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
            printf "%s" "$decoded"
            return 0
        fi
    fi

    # 7. Check for Base64 (A-Z, a-z, 0-9, +, /, =)
    if [[ "$clean_input" =~ ^[A-Za-z0-9+/]+=*$ ]] && (( len % 4 == 0 )); then
        encoding_type="Base64"
        verbose_log "Attempting decode as: $encoding_type"
        decoded=$(echo "$clean_input" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$decoded" ] && [ "$input" != "$decoded" ]; then
            printf "%s" "$decoded"
            return 0
        fi
    fi

    return 1
}

get_encoding_type() {
    local input=$(echo -n "$1" | tr -d '[:space:]')
    local len=${#input}
    
    [[ "$input" =~ ^[01]+$ ]] && (( len % 8 == 0 )) && echo "Binary (Base2)" && return
    [[ "$input" =~ ^[0-9a-fA-F]+$ ]] && (( len % 2 == 0 )) && is_likely_hex "$input" && echo "Hex (Base16)" && return
    [[ "$1" == *%* ]] && echo "URL Encoding" && return
    [[ "$input" =~ ^[A-Z2-7]+=*$ ]] && echo "Base32" && return
    [[ "$input" =~ ^[!-u]+$ ]] && echo "Base85" && return
    [[ "$input" =~ ^[A-Za-z0-9+/]+=*$ ]] && (( len % 4 == 0 )) && echo "Base64" && return
    echo "Unknown"
}

# Write output safely with confirmation
write_output() {
    local content="$1"
    
    if [ -z "$OUTPUT_FILE" ]; then
        # No output file specified, print to stdout
        printf "%s" "$content"
        return 0
    fi
    
    # Check if file exists and prompt for overwrite
    if [ -f "$OUTPUT_FILE" ]; then
        if ! $QUIET_MODE; then
            echo -e "${YELLOW}[!] File '$OUTPUT_FILE' already exists.${NC}" >&2
            read -p "Overwrite? (y/n): " -n 1 -r overwrite
            echo >&2
            if [[ ! $overwrite =~ ^[Yy]$ ]]; then
                echo -e "${RED}[ERROR] Output file not written.${NC}" >&2
                return 1
            fi
        fi
    fi
    
    # Write to file
    if printf "%s" "$content" > "$OUTPUT_FILE" 2>/dev/null; then
        if ! $QUIET_MODE; then
            echo -e "${GREEN}[+] Output saved to: $OUTPUT_FILE${NC}" >&2
        fi
        return 0
    else
        echo -e "${RED}[ERROR] Failed to write to output file.${NC}" >&2
        return 1
    fi
}

# Main recursive engine
recursive_engine() {
    local current_data="$1"
    local depth=0
    local final_result="$current_data"
    
    if ! $QUIET_MODE; then
        echo -e "${BLUE}[*] Starting Recursive Analysis...${NC}"
        echo "---------------------------------------------------"
    fi

    while [ $depth -lt $MAX_DEPTH ]; do
        ((depth++))
        verbose_log "Recursion depth: $depth"
        
        # Get encoding type
        local encoding_type=$(get_encoding_type "$current_data")
        
        # Attempt to decode
        local next_layer
        next_layer=$(identify_and_decode "$current_data")
        local status=$?

        # Check if decoding succeeded
        if [ $status -ne 0 ] || [ -z "$next_layer" ]; then
            if ! $QUIET_MODE; then
                echo -e "${GREEN}[✓] Decoding complete (No more encodings detected).${NC}"
                echo "---------------------------------------------------"
            fi
            final_result="$current_data"
            break
        fi

        # Check for binary payload
        if echo "$next_layer" | grep -qP '[^\x20-\x7E\n\r\t]' 2>/dev/null; then
            if ! $QUIET_MODE; then
                echo -e "${CYAN}Layer $depth ($encoding_type):${NC} Decoded to Binary/Shellcode"
                echo -e "${RED}[!] Binary output detected. Stopping recursion.${NC}"
                echo -e "${BLUE}[*] Final Payload Hex Dump:${NC}"
                echo "$next_layer" | xxd
            fi
            final_result="$next_layer"
            break
        fi

        # Display layer in verbose mode
        if ! $QUIET_MODE; then
            echo -e "${CYAN}Layer $depth ($encoding_type):${NC}"
            safe_print "$next_layer"
            echo "---------------------------------------------------"
        fi

        # Update for next iteration
        current_data="$next_layer"
        final_result="$next_layer"
    done

    if [ $depth -ge $MAX_DEPTH ] && ! $QUIET_MODE; then
        echo -e "${YELLOW}[!] Maximum recursion depth ($MAX_DEPTH) reached.${NC}"
    fi

    echo "$final_result"
}

# --- Argument Parsing with getopts ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--string)
                INPUT_STRING="$2"
                shift 2
                ;;
            -f|--file)
                INPUT_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE_MODE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}[ERROR] Unknown option: $1${NC}" >&2
                show_help
                exit 1
                ;;
            *)
                # Positional argument (treat as string input for backwards compatibility)
                INPUT_STRING="$1"
                shift
                ;;
        esac
    done
}

# --- Main Execution ---
main() {
    # Check dependencies first
    check_dependencies
    
    # Parse arguments
    parse_arguments "$@"
    
    # Determine input source
    local input_data=""
    
    if [ -n "$INPUT_STRING" ]; then
        input_data="$INPUT_STRING"
    elif [ -n "$INPUT_FILE" ]; then
        if [ ! -f "$INPUT_FILE" ]; then
            echo -e "${RED}[ERROR] File not found: $INPUT_FILE${NC}" >&2
            exit 1
        fi
        input_data=$(cat "$INPUT_FILE" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "${RED}[ERROR] Failed to read file: $INPUT_FILE${NC}" >&2
            exit 1
        fi
    else
        echo -e "${RED}[ERROR] No input provided.${NC}" >&2
        show_help
        exit 1
    fi
    
    # Run decoder and capture result
    local result
    result=$(recursive_engine "$input_data")
    
    # Write output
    if write_output "$result"; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
