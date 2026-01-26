#!/usr/bin/env markdown
# 🎯 START HERE - Omni-Decoder v2.0

Welcome! This file will get you up and running in 2 minutes.

---

## ⚡ Quick Start (30 seconds)

```bash
# Make it executable
chmod +x omnidecoder.sh

# Try it!
./omnidecoder.sh -s "SGVsbG8gV29ybGQ="
# Output: Hello World
```

That's it! The script just decoded Base64. 🎉

---

## 📚 What Is This?

**Omni-Decoder** is a smart tool that:
- Automatically detects encoding types (Base64, Hex, Binary, URL, etc.)
- Recursively decodes layer by layer
- Shows you exactly what it's doing
- Saves results to files

---

## 🚀 Five Minute Tutorial

### 1. Decode from Command Line
```bash
./omnidecoder.sh -s "48656C6C6F"
# Decodes Hex → "Hello"
```

### 2. Decode from File
```bash
# Create a test file
echo "SGVsbG8gV29ybGQ=" > test.txt

# Decode it
./omnidecoder.sh -f test.txt
```

### 3. Save Results to File
```bash
./omnidecoder.sh -s "data" -o result.txt
# Saves decoded output to result.txt
```

### 4. Verbose Mode (See All Layers)
```bash
./omnidecoder.sh -s "encoded_data" -v
# Shows step-by-step what happened
```

### 5. Quiet Mode (Clean Output)
```bash
./omnidecoder.sh -s "data" -q
# Just gives you the final answer
```

---

## 🎨 Real-World Example

```bash
# Multi-layer encoding
./omnidecoder.sh -s "U0dWc2JHOGdWMjl1ZG1WeQ==" -v

# Output:
# Layer 1 (Base64): SGVsbG8gV29ybGQ=
# Layer 2 (Base64): Hello World
# Done!
```

---

## 📖 Documentation Files

Not sure what to read? Here's the guide:

| File | Read If... | Time |
|------|-----------|------|
| **QUICK_REFERENCE.md** | You want to use it (examples, flags, tips) | 10 min |
| **REFACTORING_SUMMARY.md** | You want to know what's new | 8 min |
| **IMPLEMENTATION_DETAILS.md** | You want to understand how it works | 20 min |
| **CHANGELOG.md** | You want the feature list | 5 min |

👉 **Start with QUICK_REFERENCE.md** for most use cases!

---

## 🔧 Common Commands Cheat Sheet

```bash
# Basic decoding
./omnidecoder.sh -s "SGVsbG8="

# From file
./omnidecoder.sh -f input.txt

# Save to file
./omnidecoder.sh -s "data" -o output.txt

# Verbose (see details)
./omnidecoder.sh -s "data" -v

# Quiet (just result)
./omnidecoder.sh -s "data" -q

# Show help
./omnidecoder.sh -h

# Combine options
./omnidecoder.sh -f input.txt -o output.txt -v
```

---

## ✨ What Can It Decode?

- ✅ **Base64** - `SGVsbG8=`
- ✅ **Hex** - `48656C6C6F`
- ✅ **Binary** - `01001000...`
- ✅ **URL** - `Hello%20World`
- ✅ **Base32** - `JBSWY3DP`
- ✅ **Base85** - Special characters
- ✅ **Multiple Layers** - Encodes within encodes

---

## ❓ Troubleshooting

### "Command not found"
```bash
# Make sure it's executable
chmod +x omnidecoder.sh

# Run with ./
./omnidecoder.sh -s "data"
```

### "File not found"
```bash
# Check the file exists
ls -l myfile.txt

# Use full path if needed
./omnidecoder.sh -f /full/path/to/file.txt
```

### "Nothing happened"
```bash
# Try verbose mode to see what's going on
./omnidecoder.sh -s "mydata" -v
```

### "Missing dependencies"
```bash
# Install on Ubuntu/Debian
sudo apt-get install perl python3

# The script will tell you what's missing!
```

---

## 🎯 Next Steps

1. **Run it once:** `./omnidecoder.sh -s "SGVsbG8gV29ybGQ="`
2. **Try verbose:** `./omnidecoder.sh -s "48656C6C6F" -v`
3. **Read more:** Open [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
4. **Explore:** Check out the other flags with `-h`

---

## 💡 Pro Tips

```bash
# Save to file without asking
./omnidecoder.sh -s "data" -o file.txt -q

# Use with other tools
cat data.txt | xargs ./omnidecoder.sh -s -q

# Batch process files
for f in *.txt; do ./omnidecoder.sh -f "$f" -q; done

# Create an alias
alias decode='./omnidecoder.sh'
```

---

## 📊 What's New in v2.0?

- ✅ Save to files (`-o` flag)
- ✅ Better encoding detection
- ✅ Verbose and quiet modes
- ✅ More encoding formats
- ✅ Better error messages
- ✅ Works with Bash and Zsh
- ✅ Full documentation

See [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) for details.

---

## 🆘 Need Help?

| Question | Answer |
|----------|--------|
| How do I use it? | Read [QUICK_REFERENCE.md](QUICK_REFERENCE.md) |
| What formats does it support? | See [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) |
| How does it work? | See [IMPLEMENTATION_DETAILS.md](IMPLEMENTATION_DETAILS.md) |
| What changed? | See [CHANGELOG.md](CHANGELOG.md) |
| What are all the options? | Run `./omnidecoder.sh -h` |

---

## 🎓 Learning Paths

### Path 1: Just Want to Use It (5 min)
1. This file (you are here!)
2. Run: `./omnidecoder.sh -s "test"`
3. Read: [QUICK_REFERENCE.md](QUICK_REFERENCE.md#basic-usage)

### Path 2: Understand the Tool (15 min)
1. This file
2. [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
3. [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)

### Path 3: Deep Dive (1 hour)
1. This file
2. [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
3. [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)
4. [IMPLEMENTATION_DETAILS.md](IMPLEMENTATION_DETAILS.md)
5. Study the source code

---

## ✅ Verification Checklist

Make sure everything works:

```bash
# Test 1: Basic decoding ✓
./omnidecoder.sh -s "SGVsbG8gV29ybGQ=" -q
# Should print: Hello World

# Test 2: Help works ✓
./omnidecoder.sh -h
# Should show help screen

# Test 3: File operations ✓
echo "48656C6C6F" > test.txt && ./omnidecoder.sh -f test.txt -q
# Should print: Hello
```

If all three work, you're ready to go! 🚀

---

## 🌟 You're All Set!

You now know:
- How to run the basic command
- What it does (decodes encodings)
- Where to find more help
- How to use common options

### Next: Read [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for more examples!

---

**Happy Decoding!** 🎉

Questions? Check the [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) for all files.
