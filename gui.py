import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QFormLayout, QHBoxLayout,
    QLineEdit, QComboBox, QPushButton, QLabel, QPlainTextEdit, QTextEdit,
    QMessageBox, QFileDialog, QGroupBox, QSizePolicy, QScrollArea, QStatusBar,
    QShortcut
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QKeySequence
from builder import build_yara_rule, RuleWarning

class MetaEntryWidget(QWidget):
    def __init__(self, parent=None, remove_callback=None):
        super().__init__(parent)
        self.remove_callback = remove_callback
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("Meta key (e.g., author)")
        self.key_edit.setToolTip("Meta key should use snake_case format (e.g., 'threat_level', 'malware_family')")
        self.key_edit.setMinimumWidth(120)
        
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("Meta value")
        self.value_edit.setToolTip("Descriptive value for the meta field")
        self.value_edit.setMinimumWidth(200)
        
        self.remove_btn = QPushButton("✖")
        self.remove_btn.setFixedSize(24, 24)
        self.remove_btn.setToolTip("Remove this meta field")
        self.remove_btn.setStyleSheet("QPushButton { color: red; font-weight: bold; }")
        self.remove_btn.clicked.connect(self.remove_self)
        
        layout.addWidget(QLabel("Key:"))
        layout.addWidget(self.key_edit)
        layout.addWidget(QLabel("Value:"))
        layout.addWidget(self.value_edit)
        layout.addWidget(self.remove_btn)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def get_data(self):
        return self.key_edit.text().strip(), self.value_edit.text().strip()
    
    def remove_self(self):
        if self.remove_callback:
            self.remove_callback(self)
    
    def set_error(self, msg):
        if msg:
            self.key_edit.setStyleSheet("border: 1.5px solid red;")
            self.key_edit.setToolTip(f"Error: {msg}")
        else:
            self.key_edit.setStyleSheet("")
            self.key_edit.setToolTip("Meta key should use snake_case format")

class StringEntryWidget(QWidget):
    def __init__(self, parent=None, remove_callback=None):
        super().__init__(parent)
        self.remove_callback = remove_callback
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        self.id_edit = QLineEdit()
        self.id_edit.setPlaceholderText("$id")
        self.id_edit.setToolTip("String ID must start with $ and contain only letters, numbers, and underscores")
        self.id_edit.setMinimumWidth(80)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["text", "regex", "hex"])
        self.type_combo.setToolTip("String type: text (literal), regex (pattern), hex (binary)")
        
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("Value")
        self.value_edit.setToolTip("String content based on selected type")
        self.value_edit.setMinimumWidth(150)
        
        self.modifiers_edit = QLineEdit()
        self.modifiers_edit.setPlaceholderText("Modifiers (optional)")
        self.modifiers_edit.setToolTip("Modifiers: ascii, wide, nocase, private, fullword, xor(0x00-0xFF)")
        self.modifiers_edit.setMinimumWidth(120)
        
        self.remove_btn = QPushButton("✖")
        self.remove_btn.setFixedSize(24, 24)
        self.remove_btn.setToolTip("Remove this string entry")
        self.remove_btn.setStyleSheet("QPushButton { color: red; font-weight: bold; }")
        self.remove_btn.clicked.connect(self.remove_self)
        
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red")
        self.error_label.setVisible(False)
        
        layout.addWidget(QLabel("ID:"))
        layout.addWidget(self.id_edit)
        layout.addWidget(QLabel("Type:"))
        layout.addWidget(self.type_combo)
        layout.addWidget(QLabel("Value:"))
        layout.addWidget(self.value_edit)
        layout.addWidget(QLabel("Modifiers:"))
        layout.addWidget(self.modifiers_edit)
        layout.addWidget(self.remove_btn)
        
        # Add error label on new line
        main_layout = QVBoxLayout()
        main_layout.setSpacing(2)
        main_layout.addLayout(layout)
        main_layout.addWidget(self.error_label)
        self.setLayout(main_layout)
    
    def get_data(self):
        return {
            "id": self.id_edit.text().strip(),
            "type": self.type_combo.currentText(),
            "value": self.value_edit.text(),
            "modifiers": self.modifiers_edit.text().strip()
        }
    
    def remove_self(self):
        if self.remove_callback:
            self.remove_callback(self)
    
    def set_error(self, msg):
        if msg:
            self.error_label.setText(msg)
            self.error_label.setVisible(True)
            self.error_label.show()
            self.id_edit.setStyleSheet("border: 1.5px solid red;")
            self.value_edit.setStyleSheet("border: 1.5px solid red;")
        else:
            self.error_label.setVisible(False)
            self.error_label.hide()
            self.id_edit.setStyleSheet("")
            self.value_edit.setStyleSheet("")

class ConditionHelperWidget(QWidget):
    def __init__(self, parent=None, condition_edit=None):
        super().__init__(parent)
        self.condition_edit = condition_edit
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        label = QLabel("Quick Templates:")
        layout.addWidget(label)
        
        templates = [
            ("any of them", "any of them"),
            ("all of them", "all of them"),
            ("2 of them", "2 of them"),
            ("$a and $b", "$a and $b"),
            ("filesize < 1MB", "filesize < 1MB"),
            ("at entrypoint", "at entrypoint")
        ]
        
        for text, template in templates:
            btn = QPushButton(text)
            btn.setToolTip(f"Insert '{template}' at cursor position")
            btn.clicked.connect(lambda checked, t=template: self.insert_template(t))
            layout.addWidget(btn)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def insert_template(self, template):
        if self.condition_edit:
            cursor = self.condition_edit.textCursor()
            cursor.insertText(template)
            self.condition_edit.setFocus()

class YaraRuleBuilderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("YARA Rule Generator - Enhanced")
        self.setMinimumSize(1200, 800)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready to build YARA rules")
        
        # Main widget with scroll area
        scroll = QScrollArea()
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(8, 8, 8, 8)

        # Rule Header
        header_group = QGroupBox("Rule Header")
        header_layout = QFormLayout()
        header_layout.setSpacing(8)
        
        self.name_edit = QLineEdit()
        self.name_edit.setToolTip("Rule name must start with letter/underscore and contain only A-Z, 0-9, _")
        self.name_edit.setMinimumWidth(200)
        
        self.tags_edit = QLineEdit()
        self.tags_edit.setPlaceholderText("tag1, tag2, ...")
        self.tags_edit.setToolTip("Comma-separated tags for categorizing the rule")
        self.tags_edit.setMinimumWidth(200)
        
        self.name_error = QLabel()
        self.name_error.setStyleSheet("color: red")
        self.name_error.setVisible(False)
        
        header_layout.addRow("Rule Name:", self.name_edit)
        header_layout.addRow("Tags:", self.tags_edit)
        header_layout.addRow("", self.name_error)
        header_group.setLayout(header_layout)
        main_layout.addWidget(header_group)

        # Enhanced Meta Section
        meta_group = QGroupBox("Meta Fields")
        meta_vbox = QVBoxLayout()
        meta_vbox.setSpacing(8)
        
        self.meta_area = QVBoxLayout()
        self.meta_widgets = []
        self.add_meta_entry()  # Add one by default
        
        meta_vbox.addLayout(self.meta_area)
        
        add_meta_btn = QPushButton("+ Add Meta Field")
        add_meta_btn.setToolTip("Add a new metadata key-value pair")
        add_meta_btn.clicked.connect(self.add_meta_entry)
        meta_vbox.addWidget(add_meta_btn)
        
        meta_group.setLayout(meta_vbox)
        main_layout.addWidget(meta_group)

        # Enhanced Strings Section with Scroll
        strings_group = QGroupBox("String Definitions")
        strings_main_layout = QVBoxLayout()
        
        # Scroll area for strings
        self.strings_scroll = QScrollArea()
        self.strings_scroll.setWidgetResizable(True)
        self.strings_scroll.setMinimumHeight(200)
        self.strings_scroll.setMaximumHeight(400)
        
        strings_widget = QWidget()
        self.strings_area = QVBoxLayout()
        self.strings_area.setSpacing(8)
        self.string_widgets = []
        self.add_string_entry()  # Add one by default
        
        strings_widget.setLayout(self.strings_area)
        self.strings_scroll.setWidget(strings_widget)
        strings_main_layout.addWidget(self.strings_scroll)
        
        add_string_btn = QPushButton("+ Add String")
        add_string_btn.setToolTip("Add a new string definition")
        add_string_btn.clicked.connect(self.add_string_entry)
        strings_main_layout.addWidget(add_string_btn)
        
        strings_group.setLayout(strings_main_layout)
        main_layout.addWidget(strings_group)

        # Enhanced Condition Section
        condition_group = QGroupBox("Rule Condition")
        condition_layout = QVBoxLayout()
        condition_layout.setSpacing(8)
        
        # Condition helper
        self.condition_edit = QPlainTextEdit()
        self.condition_edit.setPlaceholderText("Enter YARA condition here...")
        self.condition_edit.setToolTip("Boolean expression using string references, operators, and YARA functions")
        self.condition_edit.setMinimumHeight(80)
        
        condition_helper = ConditionHelperWidget(condition_edit=self.condition_edit)
        condition_layout.addWidget(condition_helper)
        condition_layout.addWidget(self.condition_edit)
        
        self.condition_error = QLabel()
        self.condition_error.setStyleSheet("color: red")
        self.condition_error.setVisible(False)
        condition_layout.addWidget(self.condition_error)
        
        condition_group.setLayout(condition_layout)
        main_layout.addWidget(condition_group)

        # Enhanced Preview Area
        preview_group = QGroupBox("Rule Preview")
        preview_layout = QVBoxLayout()
        preview_layout.setSpacing(8)
        
        self.preview_edit = QTextEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setMinimumHeight(200)
        self.preview_edit.setFont(QFont("Courier New", 10))
        preview_layout.addWidget(self.preview_edit)
        
        preview_group.setLayout(preview_layout)
        main_layout.addWidget(preview_group)

        # Buttons with stretch
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        preview_btn = QPushButton("Preview Rule")
        preview_btn.setToolTip("Generate and preview the YARA rule (Ctrl+Enter)")
        preview_btn.clicked.connect(self.on_preview)
        preview_btn.setDefault(True)
        
        export_btn = QPushButton("Export to File")
        export_btn.setToolTip("Save the generated rule to a .yara file")
        export_btn.clicked.connect(self.on_export)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.setToolTip("Reset all fields to default state")
        clear_btn.clicked.connect(self.on_clear)
        
        btn_layout.addWidget(preview_btn)
        btn_layout.addWidget(export_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(clear_btn)
        main_layout.addLayout(btn_layout)

        # Set up main widget
        main_widget.setLayout(main_layout)
        scroll.setWidget(main_widget)
        scroll.setWidgetResizable(True)
        self.setCentralWidget(scroll)
        
        # Keyboard shortcuts
        preview_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        preview_shortcut.activated.connect(self.on_preview)
        
        # Set stretch factors for proper resizing
        main_layout.setStretchFactor(header_group, 0)
        main_layout.setStretchFactor(meta_group, 0) 
        main_layout.setStretchFactor(strings_group, 1)
        main_layout.setStretchFactor(condition_group, 0)
        main_layout.setStretchFactor(preview_group, 1)

    def add_meta_entry(self):
        widget = MetaEntryWidget(remove_callback=self.remove_meta_entry)
        self.meta_area.addWidget(widget)
        self.meta_widgets.append(widget)
        self.status_bar.showMessage("Meta field added", 2000)
    
    def remove_meta_entry(self, widget):
        if len(self.meta_widgets) > 1:  # Keep at least one
            widget.setParent(None)
            self.meta_widgets.remove(widget)
            self.status_bar.showMessage("Meta field removed", 2000)

    def add_string_entry(self):
        widget = StringEntryWidget(remove_callback=self.remove_string_entry)
        self.strings_area.addWidget(widget)
        self.string_widgets.append(widget)
        
        # Auto-scroll to bottom if >5 entries
        if len(self.string_widgets) > 5:
            self.strings_scroll.ensureWidgetVisible(widget)
        
        self.status_bar.showMessage("String entry added", 2000)
    
    def remove_string_entry(self, widget):
        if len(self.string_widgets) > 1:  # Keep at least one
            widget.setParent(None)
            self.string_widgets.remove(widget)
            self.status_bar.showMessage("String entry removed", 2000)

    def collect_rule_data(self):
        name = self.name_edit.text().strip()
        tags = [t.strip() for t in self.tags_edit.text().split(",") if t.strip()]
        
        # Collect dynamic meta fields
        meta = {}
        for w in self.meta_widgets:
            key, value = w.get_data()
            if key and value:
                meta[key] = value
        
        # Collect string entries
        strings = []
        for w in self.string_widgets:
            data = w.get_data()
            if data["id"] and data["value"]:
                entry = {"id": data["id"], "type": data["type"], "value": data["value"]}
                if data["modifiers"]:
                    entry["modifiers"] = data["modifiers"]
                strings.append(entry)
        
        condition = self.condition_edit.toPlainText()
        return name, tags, meta, strings, condition

    def clear_errors(self):
        self.name_error.setVisible(False)
        self.name_edit.setStyleSheet("")
        self.condition_error.setVisible(False)
        self.condition_edit.setStyleSheet("")
        for w in self.string_widgets:
            w.set_error("")
        for w in self.meta_widgets:
            w.set_error("")

    def show_errors(self, error_msg):
        # Enhanced error display in preview with color coding
        self.preview_edit.setHtml(f'''
        <div style="color: red; font-family: Courier New; white-space: pre-wrap;">
        <strong>❌ VALIDATION ERROR:</strong>
        
        {error_msg}
        </div>
        ''')
        
        # Parse error message for field-specific highlighting
        error_lower = error_msg.lower()
        
        # Rule name errors
        if any(pattern in error_lower for pattern in ["rule name", "invalid rule name", "must be a string"]) or \
           any(pattern in error_msg for pattern in ["Invalid rule name", "Rule name must"]):
            self.name_error.setText(error_msg.split('\n')[0])
            self.name_error.setVisible(True)
            self.name_error.show()
            self.name_error.repaint()
            self.name_edit.setStyleSheet("border: 1.5px solid red;")
        
        # Meta key errors
        if any(pattern in error_lower for pattern in ["meta key", "invalid meta key", "snake_case"]):
            for w in self.meta_widgets:
                key, _ = w.get_data()
                if key and key in error_msg:
                    w.set_error(error_msg.split('\n')[0])
        
        # Condition errors
        if any(word in error_lower for word in ["condition", "undefined string", "wildcard reference"]):
            self.condition_error.setText(error_msg.split('\n')[0])
            self.condition_error.setVisible(True)
            self.condition_error.show()
            self.condition_edit.setStyleSheet("border: 1.5px solid red;")
        
        # String-related errors
        if any(word in error_lower for word in ["string id", "duplicate string", "string entry", "hex pattern", "regex flags", "modifier"]):
            for w in self.string_widgets:
                string_id = w.id_edit.text()
                if (string_id and string_id in error_msg) or not string_id or "string entry" in error_lower:
                    w.set_error(error_msg.split('\n')[0])

    def show_warnings(self, warning_msg):
        # Show warnings in orange
        self.preview_edit.setHtml(f'''
        <div style="color: orange; font-family: Courier New; white-space: pre-wrap;">
        <strong>⚠️ WARNING:</strong>
        
        {warning_msg}
        
        <em>Rule may still be valid but could have performance issues.</em>
        </div>
        ''')

    def on_preview(self):
        self.clear_errors()
        self.status_bar.showMessage("Generating rule preview...")
        
        try:
            name, tags, meta, strings, condition = self.collect_rule_data()
            rule = build_yara_rule(name, tags, meta, strings, condition)
            
            # Display successful rule with syntax highlighting
            self.preview_edit.setHtml(f'''
            <div style="font-family: Courier New; white-space: pre-wrap; color: #2e7d32;">
            <strong>✅ VALID YARA RULE:</strong>
            </div>
            <pre style="font-family: Courier New; margin-top: 10px;">{rule}</pre>
            ''')
            self.status_bar.showMessage("Rule generated successfully", 3000)
            
        except RuleWarning as w:
            self.show_warnings(str(w))
            QMessageBox.warning(self, "Performance Warning", str(w))
            self.status_bar.showMessage("Rule generated with warnings", 3000)
            
        except ValueError as e:
            self.show_errors(str(e))
            self.status_bar.showMessage("Validation failed", 3000)
        
        except Exception as e:
            self.preview_edit.setHtml(f'''
            <div style="color: red; font-family: Courier New;">
            <strong>❌ UNEXPECTED ERROR:</strong><br>
            {str(e)}
            </div>
            ''')
            self.status_bar.showMessage("Unexpected error occurred", 3000)

    def on_export(self):
        self.clear_errors()
        self.status_bar.showMessage("Preparing export...")
        
        try:
            name, tags, meta, strings, condition = self.collect_rule_data()
            rule = build_yara_rule(name, tags, meta, strings, condition)
            
            suggested_name = f"{name or 'rule'}.yara"
            fname, _ = QFileDialog.getSaveFileName(
                self, 
                "Export YARA Rule", 
                suggested_name, 
                "YARA Files (*.yara);;All Files (*)"
            )
            
            if fname:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(rule)
                self.status_bar.showMessage(f"Rule exported to {fname}", 5000)
                
        except RuleWarning as w:
            self.show_warnings(str(w))
            QMessageBox.warning(self, "Performance Warning", 
                               f"Warning: {w}\n\nExport anyway?")
            
        except ValueError as e:
            self.show_errors(str(e))
            QMessageBox.critical(self, "Export Failed", 
                               f"Cannot export invalid rule:\n{e}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
            self.status_bar.showMessage("Export failed", 3000)

    def on_clear(self):
        # Clear all fields
        self.name_edit.clear()
        self.tags_edit.clear()
        self.condition_edit.clear()
        self.preview_edit.clear()
        self.clear_errors()
        
        # Reset meta widgets to one empty entry
        for w in self.meta_widgets:
            w.setParent(None)
        self.meta_widgets.clear()
        self.add_meta_entry()
        
        # Reset string widgets to one empty entry
        for w in self.string_widgets:
            w.setParent(None)
        self.string_widgets.clear()
        self.add_string_entry()
        
        self.status_bar.showMessage("All fields cleared", 2000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = YaraRuleBuilderGUI()
    window.show()
    sys.exit(app.exec_())
