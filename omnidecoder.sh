#!/bin/bash

# ============================================================
# Script Name: omni_decoder.sh
# Description: An automated, recursive decoder that identifies
#              and decodes Hex, Base64, Base32, Binary, and URL 
#              encoded strings until plaintext is revealed.
# ============================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Configuration ---
MAX_DEPTH=10   # Prevent infinite loops

# --- Utility Functions ---

# Safe echo that handles binary data visuals
safe_print() {
    local data="$1"
    # Check for non-printable characters
    if echo "$data" | grep -qP '[^\x20-\x7E\n\r\t]'; then
        echo -e "${YELLOW}(Binary Data Detected - Showing Hex Preview)${NC}"
        echo "$data" | xxd | head -n 2
    else
        # Print first 200 chars if it's long
        if [ ${#data} -gt 200 ]; then
            echo "${data:0:200}..."
        else
            echo "$data"
        fi
    fi
}

# --- Detection & Decoding Logic ---

identify_and_decode() {
    local input="$1"
    local decoded=""
    local type=""
    
    # Clean whitespace for detection (except for URL)
    local clean_input=$(echo -n "$input" | tr -d '[:space:]')
    local len=${#clean_input}

    # 1. Check for Binary (0s and 1s, multiple of 8)
    if [[ "$clean_input" =~ ^[01]+$ ]] && (( len % 8 == 0 )) && [ $len -gt 0 ]; then
        type="Binary"
        # Convert binary string to ascii using perl for robust conversion
        decoded=$(echo "$clean_input" | perl -lpe '$_=pack"B*",$_')
    
    # 2. Check for Hex (0-9, A-F, even length)
    elif [[ "$clean_input" =~ ^[0-9a-fA-F]+$ ]] && (( len % 2 == 0 )) && [ $len -gt 0 ]; then
        # Heuristic: Hex strings usually don't look like English words.
        # If it looks like pure text, it might just be a word like "fade" or "added".
        # We assume it is Hex if it's sufficiently long or contains numbers.
        type="Hex"
        decoded=$(echo "$clean_input" | xxd -r -p 2>/dev/null)

    # 3. Check for URL Encoding (Must contain %)
    elif [[ "$input" == *%* ]]; then
        # Simple heuristic: must have a %
        type="URL"
        decoded=$(python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.argv[1]))" "$input")

    # 4. Check for Base32 (A-Z, 2-7, padding =)
    elif [[ "$clean_input" =~ ^[A-Z2-7]+=*$ ]]; then
        # Base32 is rare, so we test decode.
        # Only attempt if length is reasonably valid for blocked encoding
        decoded=$(echo "$clean_input" | base32 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            type="Base32"
        fi

    # 5. Check for Base64 (A-Z, a-z, 0-9, +, /, padding =)
    # This is the catch-all, so we put it last and strict check it.
    elif [[ "$clean_input" =~ ^[A-Za-z0-9+/]+=*$ ]] && (( len % 4 == 0 )); then
        decoded=$(echo "$clean_input" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            type="Base64"
        fi
    fi

    # Return result in format: "TYPE|DECODED_CONTENT"
    if [ -n "$type" ] && [ -n "$decoded" ]; then
        # Verify decoding actually changed something (prevent loops)
        if [ "$input" != "$decoded" ]; then
            # We use a delimiter that is unlikely to be in the text to return both values
            # However, simpler to just return raw decoded and set global/return code
            # For this bash script, we print to stdout for the capturing function
            printf "%s" "$decoded"
            return 0 # Success
        fi
    fi

    return 1 # Failure to decode
}

get_encoding_type() {
    # Helper to re-run detection logic just to get the name for the log
    # (Duplicate logic simplified for display)
    local input=$(echo -n "$1" | tr -d '[:space:]')
    local len=${#input}
    
    if [[ "$input" =~ ^[01]+$ ]] && (( len % 8 == 0 )); then echo "Binary (Base2)"; return; fi
    if [[ "$input" =~ ^[0-9a-fA-F]+$ ]] && (( len % 2 == 0 )); then echo "Hex (Base16)"; return; fi
    if [[ "$1" == *%* ]]; then echo "URL Encoding"; return; fi
    if [[ "$input" =~ ^[A-Z2-7]+=*$ ]]; then echo "Base32"; return; fi
    if [[ "$input" =~ ^[A-Za-z0-9+/]+=*$ ]] && (( len % 4 == 0 )); then echo "Base64"; return; fi
    echo "Unknown"
}

recursive_engine() {
    local current_data="$1"
    local depth=0
    
    echo -e "${BLUE}[*] Starting Recursive Analysis...${NC}"
    echo "---------------------------------------------------"

    while [ $depth -lt $MAX_DEPTH ]; do
        ((depth++))
        
        # 1. Identify what we have currently
        local encoding_type=$(get_encoding_type "$current_data")
        
        # 2. Attempt to decode
        # We capture output. If function returns 1, detection failed.
        local next_layer
        next_layer=$(identify_and_decode "$current_data")
        status=$?

        # 3. Check status
        if [ $status -ne 0 ]; then
            echo -e "${GREEN}[V] End of line reached (Plaintext or Unknown format).${NC}"
            break
        fi

        # 4. Check if we decoded to garbage (Heuristic)
        # If the output has high non-printable chars, it might be the final payload (shellcode)
        if echo "$next_layer" | grep -qP '[^\x20-\x7E\n\r\t]'; then
            echo -e "${CYAN}Layer $depth ($encoding_type):${NC} Decoded to Binary/Shellcode"
            echo -e "${RED}[!] Binary output detected. Stopping recursion.${NC}"
            echo -e "${BLUE}[*] Final Payload Hex Dump:${NC}"
            echo -n "$next_layer" | xxd
            exit 0
        fi

        echo -e "${CYAN}Layer $depth ($encoding_type):${NC}"
        safe_print "$next_layer"
        echo "---------------------------------------------------"

        # Prepare for next loop
        current_data="$next_layer"
    done
}

# --- Main Execution ---

if [ $# -eq 0 ]; then
    echo -e "${BLUE}Usage:${NC} $0 <string> OR $0 -f <file>"
    exit 1
fi

input_data=""

if [ "$1" == "-f" ]; then
    if [ -f "$2" ]; then
        input_data=$(cat "$2")
    else
        echo -e "${RED}File not found.${NC}"
        exit 1
    fi
else
    input_data="$1"
fi

recursive_engine "$input_data"
