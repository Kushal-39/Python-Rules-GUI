# Python Rules GUI

A simple Python-based GUI tool to generate YARA (and later Sigma) rules without writing syntax manually.

## 💡 Why This Exists

Writing YARA rules by hand is slow, error-prone, and full of syntax gotchas. This project aims to solve that by letting you:

- Fill in rule details via GUI fields
- Validate input with syntax checks and helpful suggestions
- Preview and export ready-to-use `.yara` rules

No more fighting indentation or regex modifiers.

## ✅ Current Status: Core Logic Ready

The backend logic (`builder.py`) handles:
- Rule name validation (with reserved word protection)
- Meta field checks (enforces snake_case format)
- String declarations: plain, regex, hex
- Modifier checks (e.g., avoids `ascii` + `wide` conflicts)
- Condition string parsing and reference validation
- Warning system for inefficient regex patterns

All inputs are validated defensively. Suggestions are given for typos, bad IDs, unsafe patterns, etc.

## 🧪 Example

```python
from builder import build_yara_rule

rule = build_yara_rule(
    name="Ransomware_Generic_Pattern",
    tags=["ransomware", "crypto", "malware"],
    meta={
        "author": "Security Team",
        "impact": "critical",
        "description": "Generic ransomware detection patterns"
    },
    strings=[
        {"id": "$ransom_note", "type": "text", "value": "YOUR FILES ARE ENCRYPTED"},
        {"id": "$crypto_api", "type": "text", "value": "CryptEncrypt", "modifiers": "ascii"},
        {"id": "$file_ext", "type": "regex", "value": "/\.(locked|encrypted|crypto)$/"}
    ],
    condition="filesize > 500KB and 2 of them"
)

print(rule)
```

## 📦 Project Roadmap

- [x] Backend rule builder with validations
- [ ] GUI implementation using PyQt5
- [ ] YAML export for Sigma rules
- [ ] Syntax highlighting in preview pane
- [ ] Templates for common threat patterns

## ⚠️ Note

This is a **GUI-first project**, not a command-line tool. Once the GUI is ready, the core logic will be used as a backend module.

## 📁 Repo Structure (Planned)

```
Python-Rules-GUI/
├── builder.py        # Rule logic and validation
├── gui.py            # GUI frontend (PyQt)
├── assets/           
├── README.md         # You're here.
├── .gitignore
```

---

Made with frustration and caffeine ☕ by [Kushal Arora](https://github.com/Kushal-39)
