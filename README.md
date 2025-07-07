# YARA & Sigma Rule Generator GUI

A modern, user-friendly graphical interface for creating and validating both **YARA** and **Sigma** rules with advanced error handling and usability features.

![YARA Rule Generator](https://img.shields.io/badge/YARA-Rule%20Generator-blue)
![Sigma Rule Generator](https://img.shields.io/badge/Sigma-Rule%20Generator-purple)
![PyQt5](https://img.shields.io/badge/PyQt5-GUI-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

## 🎯 Overview

This application provides an intuitive GUI for creating both YARA and Sigma rules, making malware detection and threat hunting rule development accessible to both beginners and advanced users. It features dynamic field management, real-time validation, template assistance, and comprehensive error handling for both rule types.

## ✨ Key Features

###  Dual Rule Support
- **YARA Rules**: Complete malware detection rule creation
- **Sigma Rules**: Log analysis and threat hunting rule generation
- **Mode Switching**: Easy dropdown to switch between YARA and Sigma modes
- **Unified Interface**: Same intuitive design for both rule types

###  Dynamic Rule Building
- **Dynamic Meta Fields** (YARA): Add/remove metadata key-value pairs with validation
- **Enhanced String Management** (YARA): Unlimited string definitions with scroll support
- **Detection Patterns** (Sigma): Dynamic detection entries with pattern lists
- **Logsource Configuration** (Sigma): Product, service, and category specification
- **Condition Templates**: Quick insertion of common patterns for both rule types
- **Real-time Validation**: Immediate feedback on rule syntax and structure

### 🎨 Modern UI/UX
- **Responsive Design**: Proper window resizing with stretch factors
- **Tooltips & Guidance**: Comprehensive help text for all fields
- **Status Bar**: Real-time operation feedback
- **Keyboard Navigation**: Tab order and shortcuts (Ctrl+Enter for YARA, Ctrl+Shift+Enter for Sigma)
- **Visual Mode Indicators**: Clear indication of current rule type

### 🛡️ Advanced Error Handling
- **Color-coded Feedback**: Red for errors, orange for warnings, green for success
- **Field-specific Highlighting**: Pinpoint exactly where issues occur
- **Inline Error Messages**: Descriptive feedback with suggested fixes
- **Performance Warnings**: Detection of potentially problematic patterns
- **Mode-specific Validation**: Tailored validation for YARA vs Sigma rules

### 📤 Export & Integration
- **One-click Export**: Save YARA rules to .yara files, Sigma rules to .yml files
- **Backend Integration**: Robust validation engines for both rule types
- **Format Compliance**: YARA and Sigma specification-compatible output
- **Dual Preview**: Real-time preview for both rule formats

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- PyQt5
- PyYAML (for Sigma rules)

### Installation

1. **Clone or download the project:**
   ```bash
   git clone https://github.com/Kushal-39/Python-Rules-GUI.git
   cd Python-Rules-GUI
   ```

2. **Install dependencies:**
   ```bash
   pip install PyQt5 PyYAML
   ```

3. **Launch the application:**
   ```bash
   python gui.py
   ```

## 🎮 Usage Guide

### Rule Type Selection

1. **Choose Rule Type**: Use the dropdown at the top to select between "YARA Rule" and "Sigma Rule"
2. **Mode Switching**: Switch between modes at any time - your data in the inactive mode is preserved

### YARA Rule Workflow

1. **Rule Header**
   - Enter a valid rule name (must start with letter/underscore)
   - Add optional tags separated by commas

2. **Meta Fields**
   - Click "+ Add Meta Field" to add metadata
   - Use snake_case format for keys (e.g., `threat_level`, `malware_family`)
   - Remove fields with the ✖ button

3. **String Definitions**
   - Define string patterns with unique IDs starting with `$`
   - Choose type: text, regex, or hex
   - Add optional modifiers (ascii, wide, nocase, etc.)
   - Use scroll area for managing many strings

4. **Condition Building**
   - Use template buttons for common patterns
   - Write custom boolean expressions
   - Reference strings by their IDs

5. **Preview & Export**
   - Click "Preview YARA Rule" or press Ctrl+Enter
   - Fix any highlighted errors
   - Export to `.yara` files

### Sigma Rule Workflow

1. **Rule Information**
   - Enter rule title and description
   - Description supports multi-line text

2. **Log Source**
   - Specify product (windows, linux, etc.)
   - Specify service (sysmon, auditd, etc.)
   - Optionally add category (process_creation, network_connection, etc.)

3. **Detection Patterns**
   - Click "+ Add Detection" to add detection blocks
   - Enter detection ID (using snake_case)
   - Add patterns one per line
   - Use scroll area for managing multiple detection blocks

4. **Condition Building**
   - Write boolean expressions using detection IDs
   - Use logical operators (and, or, not)
   - Reference detection blocks by their IDs

5. **Output Fields**
   - Specify comma-separated field names
   - Fields will be included in detection output

6. **Preview & Export**
   - Click "Preview Sigma Rule" or press Ctrl+Shift+Enter
   - Fix any highlighted errors
   - Export to `.yml` files
   - Export valid rules to .yara files

### Template Examples

The condition helper provides these quick templates:

- `any of them` - Match any defined string
- `all of them` - Match all defined strings  
- `2 of them` - Match at least 2 strings
- `$a and $b` - Match specific strings
- `filesize < 1MB` - File size constraints
- `at entrypoint` - Position-based matching

### Error Handling

The GUI provides intelligent error feedback:

- **� Red highlighting**: Critical syntax errors that prevent rule compilation
- **🟠 Orange warnings**: Performance concerns or potential issues
- **✅ Green success**: Valid rule ready for export

Common error types and fixes:

| Error Type | Example | Fix |
|------------|---------|-----|
| Invalid rule name | `123rule` | Start with letter: `rule_123` |
| Bad string ID | `invalid` | Add $ prefix: `$invalid` |
| Invalid meta key | `Author-Name` | Use snake_case: `author_name` |
| Undefined string | `$missing` | Define string or remove reference |
| Performance warning | `.*?` in regex | Use more specific patterns |

## 📁 File Structure

```
Python-Rules-GUI/
├── gui.py                          # Main GUI application (Enhanced)
├── builder.py                      # YARA rule validation engine
├── sigma_builder.py                # Sigma rule validation engine
└── README.md                       # This file
```

## 🔧 Technical Details

### Architecture

- **Frontend**: PyQt5-based GUI with custom widgets
- **Backend**: Comprehensive validation engine with YARA compliance
- **Error Handling**: Multi-level validation with user-friendly feedback
- **Integration**: Seamless data flow between GUI and validation engine

### Key Components

1. **YaraRuleBuilderGUI**: Main application window
2. **MetaEntryWidget**: Dynamic metadata field management
3. **StringEntryWidget**: Enhanced string definition handling
4. **ConditionHelperWidget**: Template insertion assistance

### Validation Features

- Rule name compliance (YARA identifier rules)
- String ID format validation
- Meta key snake_case enforcement
- Modifier conflict detection
- Performance pattern analysis
- Regex safety checks

## 🎯 Advanced Usage

### Performance Optimization

The GUI warns about potentially slow patterns:

- **Lazy quantifiers**: `.*?` in short patterns
- **Nested wildcards**: `.*.*` causing exponential backtracking
- **Unsafe regex flags**: PCRE flags not supported in YARA

### Best Practices

1. **Naming Conventions**
   - Use descriptive rule names: `apt32_backdoor`, `trojan_detector`
   - Follow snake_case for meta keys: `threat_level`, `detection_date`
   - Use meaningful string IDs: `$payload`, `$header`, `$signature`

2. **String Optimization**
   - Prefer specific patterns over wildcards
   - Use appropriate modifiers (ascii/wide, nocase)
   - Test regex patterns for performance

3. **Condition Logic**
   - Start with simple conditions
   - Use templates for common patterns
   - Reference all defined strings or mark unused ones as private

### Keyboard Shortcuts

- `Ctrl+Enter`: Preview rule
- `Tab`: Navigate between fields
- `Enter`: Add new meta/string field (when in add buttons)

## 🐛 Troubleshooting

### Common Issues

**GUI won't start:**
```bash
# Install PyQt5
pip install PyQt5

# Check Python version
python --version  # Should be 3.7+
```

**Import errors:**
```python
# Verify PyQt5 installation
python -c "from PyQt5.QtWidgets import QApplication; print('PyQt5 OK')"
```

**Rule validation fails:**
- Check that all string IDs start with `$`
- Ensure meta keys use snake_case format
- Verify condition references defined strings
- Review error highlighting for specific issues

### Performance Issues

If the GUI feels slow:
- Reduce number of string entries displayed
- Use scroll area for large string lists
- Check for complex regex patterns causing warnings

## 🧪 Example Output

Here's what the tool generates:

### YARA Rule Example
```yara
rule Ransomware_Generic_Pattern : ransomware crypto malware
{
    meta:
        author = "Security Team"
        description = "Generic ransomware detection patterns"
        impact = "critical"
    strings:
        $ransom_note = "YOUR FILES ARE ENCRYPTED"
        $crypto_api = "CryptEncrypt" ascii
        $file_ext = /\.(locked|encrypted|crypto)$/
    condition:
        filesize > 500KB and 2 of them
}
```

### Sigma Rule Example
```yaml
title: SuspiciousProcessCreation
description: Detects suspicious process creation events indicating potential malware execution
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
  - powershell.exe
  - cmd.exe
  - wscript.exe
  suspicious_args:
  - '*-EncodedCommand*'
  - '*-exec bypass*'
  - '*downloadstring*'
  network_indicators:
  - '*http://*'
  - '*https://*'
condition: selection and (suspicious_args or network_indicators)
fields:
- ProcessName
- CommandLine
- User
- ParentProcessName
tags:
- attack.execution
- attack.t1059
level: medium
```

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:

- Syntax highlighting in condition editor
- Auto-completion for string IDs
- Rule import/export in different formats
- Dark theme support
- File sample validation integration

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- YARA project for the rule specification
- PyQt5 community for the GUI framework
- Security researchers who rely on YARA rules
- Original creator: [Kushal Arora](https://github.com/Kushal-39)

## 📞 Support

For issues, questions, or feature requests:

1. Check the troubleshooting section above
2. Review error messages and tooltips in the GUI
3. Consult the YARA documentation for rule syntax
4. Create an issue with detailed error information

---

**Built with ❤️ for the cybersecurity community**

*Making YARA and Sigma rule creation accessible, reliable, and efficient.*
