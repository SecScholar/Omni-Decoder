# Omni-Decoder
A simple, open-source utility for cybersecurity professionals and ethical hackers that automates the detection and decoding of encoded text.
Omni-Decoder is a robust Bash script designed to recursively peel back layers of encoding. Unlike standard decoders that require you to know the encoding type beforehand, Omni-Decoder uses heuristic logic to identify, decode, and loop through data until plaintext (or a raw binary payload) is revealed.

Features

    - Automated Detection: Intelligently identifies encoding types based on character sets and patterns.

    - Recursive Decoding: Automatically loops through layers of obfuscation (e.g., Base64 -> Hex -> URL -> Plaintext).

    -  Supported Formats:

        - Base64

        -  Base32

        -  Hexadecimal (Base16)

        -  Binary (Base2)

        -  URL Encoding

    -  Binary Safety: Detects shellcode or binary payloads and displays a safe Hex dump instead of corrupting your terminal.

    -  Input Flexibility: Accepts raw strings or file paths.

Installation

Omni-Decoder is a standalone Bash script. No dependencies are required other than standard Linux utilities (base64, base32, xxd, python3/perl).

Clone the repository:

git clone [https://github.com/SecScholar/omni-decoder.git](https://github.com/yourusername/omni-decoder.git)
cd omni-decoder


Make the script executable:

chmod +x omni_decoder.sh


Usage

Decode a String

./omni_decoder.sh "YOUR_ENCODED_STRING"


Decode a File

./omni_decoder.sh -f payload.txt


Example

Input: A string that is Base64 encoded, containing a Hex string, which contains a URL encoded string.

./omni_decoder.sh "WTJocGJGOWtaV2N2ZDI5eWJHUnZiZz09"


Output:

[*] Starting Recursive Analysis...
---------------------------------------------------
Layer 1 (Base64):
6368616c6c656e6765
---------------------------------------------------
Layer 2 (Hex):
challenge
---------------------------------------------------
[V] End of line reached (Plaintext or Unknown format).


Disclaimer

This tool is provided for educational and professional cybersecurity purposes only. The authors are not responsible for any misuse of this tool.

Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
