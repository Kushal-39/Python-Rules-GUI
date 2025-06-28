# YARA Rule Generator GUI

A modern, user-friendly graphical interface for creating and validating YARA rules with advanced error handling and usability features.

![YARA Rule Generator](https://img.shields.io/badge/YARA-Rule%20Generator-blue)
![PyQt5](https://img.shields.io/badge/PyQt5-GUI-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

## 🎯 Overview

This application provides an intuitive GUI for creating YARA rules, making malware detection rule development accessible to both beginners and advanced users. It features dynamic field management, real-time validation, template assistance, and comprehensive error handling.

## ✨ Key Features

### 🔧 Dynamic Rule Building
- **Dynamic Meta Fields**: Add/remove metadata key-value pairs with validation
- **Enhanced String Management**: Unlimited string definitions with scroll support
- **Condition Templates**: Quick insertion of common YARA patterns
- **Real-time Validation**: Immediate feedback on rule syntax and structure

### 🎨 Modern UI/UX
- **Responsive Design**: Proper window resizing with stretch factors
- **Tooltips & Guidance**: Comprehensive help text for all fields
- **Status Bar**: Real-time operation feedback
- **Keyboard Navigation**: Tab order and Ctrl+Enter shortcuts

### 🛡️ Advanced Error Handling
- **Color-coded Feedback**: Red for errors, orange for warnings, green for success
- **Field-specific Highlighting**: Pinpoint exactly where issues occur
- **Inline Error Messages**: Descriptive feedback with suggested fixes
- **Performance Warnings**: Detection of potentially slow regex patterns

### 📤 Export & Integration
- **One-click Export**: Save rules to .yara files
- **Backend Integration**: Robust validation engine with comprehensive checks
- **Format Compliance**: YARA-compatible output

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- PyQt5

### Installation

1. **Clone or download the project:**
   ```bash
   git clone https://github.com/Kushal-39/Python-Rules-GUI.git
   cd Python-Rules-GUI
   ```

2. **Install dependencies:**
   ```bash
   pip install PyQt5
   ```

3. **Launch the application:**
   ```bash
   python gui.py
   ```

## 🎮 Usage Guide

### Basic Workflow

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
   - Click "Preview Rule" or press Ctrl+Enter
   - Fix any highlighted errors
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
├── builder.py                      # Backend validation engine
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

*Making YARA rule creation accessible, reliable, and efficient.*
