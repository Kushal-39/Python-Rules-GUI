import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QFormLayout, QHBoxLayout,
    QLineEdit, QComboBox, QPushButton, QLabel, QPlainTextEdit, QTextEdit,
    QMessageBox, QFileDialog, QGroupBox, QSizePolicy, QScrollArea, QStatusBar,
    QShortcut, QStackedWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QKeySequence
from builder import build_yara_rule, RuleWarning
from sigma_builder import build_sigma_rule, RuleWarning as SigmaWarning

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

class DetectionEntryWidget(QWidget):
    """Widget for entering Sigma detection patterns with enhanced error handling."""
    
    def __init__(self, parent=None, remove_callback=None):
        super().__init__(parent)
        self.remove_callback = remove_callback
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        # Header with ID and remove button
        header_layout = QHBoxLayout()
        
        self.detection_id_edit = QLineEdit()
        self.detection_id_edit.setPlaceholderText("Detection ID (e.g., selection, cmd_exec)")
        self.detection_id_edit.setMinimumWidth(150)
        self.detection_id_edit.setToolTip("Unique identifier for this detection pattern")
        
        self.remove_btn = QPushButton("✖")
        self.remove_btn.setFixedSize(24, 24)
        self.remove_btn.setToolTip("Remove this detection entry")
        self.remove_btn.setStyleSheet("QPushButton { color: red; font-weight: bold; }")
        self.remove_btn.clicked.connect(self.remove_self)
        
        header_layout.addWidget(QLabel("ID:"))
        header_layout.addWidget(self.detection_id_edit)
        header_layout.addStretch()
        header_layout.addWidget(self.remove_btn)
        
        # Detection patterns area
        self.patterns_text = QPlainTextEdit()
        self.patterns_text.setPlaceholderText("Enter detection patterns here...\nExample:\nCommandLine|contains:\n  - cmd.exe\n  - powershell.exe")
        self.patterns_text.setMinimumHeight(100)
        self.patterns_text.setToolTip("YAML detection patterns for this detection ID")
        
        # Error label for this detection entry
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red; font-size: 10px;")
        self.error_label.setVisible(False)
        self.error_label.setWordWrap(True)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.patterns_text)
        layout.addWidget(self.error_label)
        
        self.setLayout(layout)
        
        # Add border styling
        self.setStyleSheet("""
            DetectionEntryWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                margin: 2px;
                padding: 4px;
            }
        """)
    
    def set_error(self, error_message):
        """Display error message and highlight the widget."""
        self.error_label.setText(error_message)
        self.error_label.setVisible(True)
        self.setStyleSheet("""
            DetectionEntryWidget {
                border: 2px solid red;
                border-radius: 4px;
                margin: 2px;
                padding: 4px;
            }
        """)
    
    def clear_error(self):
        """Clear error message and reset styling."""
        self.error_label.setVisible(False)
        self.error_label.clear()
        self.setStyleSheet("""
            DetectionEntryWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                margin: 2px;
                padding: 4px;
            }
        """)
    
    def get_data(self):
        """Get the detection ID and patterns."""
        detection_id = self.detection_id_edit.text().strip()
        patterns_text = self.patterns_text.toPlainText().strip()
        patterns = [line.strip() for line in patterns_text.split('\n') if line.strip()]
        return detection_id, patterns
    
    def remove_self(self):
        """Remove this detection entry widget."""
        if self.remove_callback:
            self.remove_callback(self)

class ConditionHelperWidget(QWidget):
    def __init__(self, parent=None, condition_edit=None, rule_type="YARA"):
        super().__init__(parent)
        self.condition_edit = condition_edit
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        label = QLabel("Quick Templates:")
        layout.addWidget(label)
        
        if rule_type == "YARA":
            templates = [
                ("any of them", "any of them"),
                ("all of them", "all of them"),
                ("2 of them", "2 of them"),
                ("$a and $b", "$a and $b"),
                ("filesize < 1MB", "filesize < 1MB"),
                ("at entrypoint", "at entrypoint")
            ]
        else:  # Sigma
            templates = [
                ("selection", "selection"),
                ("selection and filter", "selection and filter"),
                ("sel1 or sel2", "sel1 or sel2"),
                ("not filter", "not filter"),
                ("selection and not filter", "selection and not filter"),
                ("1 of selection*", "1 of selection*")
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

class RuleBuilderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Rule Generator - YARA & Sigma")
        self.setMinimumSize(1200, 800)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready to build rules")
        
        # Main widget with scroll area
        scroll = QScrollArea()
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(8, 8, 8, 8)

        # Rule Type Selector at the top
        mode_group = QGroupBox("Rule Type")
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(8)
        
        mode_label = QLabel("Rule Type:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["YARA Rule", "Sigma Rule"])
        self.mode_combo.setToolTip("Select between YARA and Sigma rule generation")
        self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
        
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        mode_group.setLayout(mode_layout)
        main_layout.addWidget(mode_group)

        # Create stacked widget for mode switching
        self.stacked_widget = QStackedWidget()
        
        # Create YARA form
        self.yara_widget = self.create_yara_form()
        self.stacked_widget.addWidget(self.yara_widget)
        
        # Create Sigma form
        self.sigma_widget = self.create_sigma_form()
        self.stacked_widget.addWidget(self.sigma_widget)
        
        main_layout.addWidget(self.stacked_widget)

        # Enhanced Preview Area (shared between modes)
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

        # Buttons with stretch (shared between modes)
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        self.preview_btn = QPushButton("Preview Rule")
        self.preview_btn.setToolTip("Generate and preview the rule (Ctrl+Enter)")
        self.preview_btn.clicked.connect(self.on_preview)
        self.preview_btn.setDefault(True)
        
        self.export_btn = QPushButton("Export to File")
        self.export_btn.setToolTip("Save the generated rule to a file")
        self.export_btn.clicked.connect(self.on_export)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.setToolTip("Reset all fields to default state")
        clear_btn.clicked.connect(self.on_clear)
        
        btn_layout.addWidget(self.preview_btn)
        btn_layout.addWidget(self.export_btn)
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
        
        sigma_preview_shortcut = QShortcut(QKeySequence("Ctrl+Shift+Return"), self)
        sigma_preview_shortcut.activated.connect(self.on_preview)
        
        # Initialize in YARA mode
        self.on_mode_changed(0)

    def create_yara_form(self):
        """Create the YARA rule form widget."""
        yara_widget = QWidget()
        yara_layout = QVBoxLayout()
        yara_layout.setSpacing(12)

        # Rule Header
        header_group = QGroupBox("Rule Header")
        header_layout = QFormLayout()
        header_layout.setSpacing(8)
        
        self.yara_name_edit = QLineEdit()
        self.yara_name_edit.setToolTip("Rule name must start with letter/underscore and contain only A-Z, 0-9, _")
        self.yara_name_edit.setMinimumWidth(200)
        
        self.yara_tags_edit = QLineEdit()
        self.yara_tags_edit.setPlaceholderText("tag1, tag2, ...")
        self.yara_tags_edit.setToolTip("Comma-separated tags for categorizing the rule")
        self.yara_tags_edit.setMinimumWidth(200)
        
        self.yara_name_error = QLabel()
        self.yara_name_error.setStyleSheet("color: red")
        self.yara_name_error.setVisible(False)
        
        header_layout.addRow("Rule Name:", self.yara_name_edit)
        header_layout.addRow("Tags:", self.yara_tags_edit)
        header_layout.addRow("", self.yara_name_error)
        header_group.setLayout(header_layout)
        yara_layout.addWidget(header_group)

        # Enhanced Meta Section
        meta_group = QGroupBox("Meta Fields")
        meta_vbox = QVBoxLayout()
        meta_vbox.setSpacing(8)
        
        self.yara_meta_area = QVBoxLayout()
        self.yara_meta_widgets = []
        self.add_yara_meta_entry()  # Add one by default
        
        meta_vbox.addLayout(self.yara_meta_area)
        
        add_meta_btn = QPushButton("+ Add Meta Field")
        add_meta_btn.setToolTip("Add a new metadata key-value pair")
        add_meta_btn.clicked.connect(self.add_yara_meta_entry)
        meta_vbox.addWidget(add_meta_btn)
        
        meta_group.setLayout(meta_vbox)
        yara_layout.addWidget(meta_group)

        # Enhanced Strings Section with Scroll
        strings_group = QGroupBox("String Definitions")
        strings_main_layout = QVBoxLayout()
        
        # Scroll area for strings
        self.yara_strings_scroll = QScrollArea()
        self.yara_strings_scroll.setWidgetResizable(True)
        self.yara_strings_scroll.setMinimumHeight(200)
        self.yara_strings_scroll.setMaximumHeight(400)
        
        strings_widget = QWidget()
        self.yara_strings_area = QVBoxLayout()
        self.yara_strings_area.setSpacing(8)
        self.yara_string_widgets = []
        self.add_yara_string_entry()  # Add one by default
        
        strings_widget.setLayout(self.yara_strings_area)
        self.yara_strings_scroll.setWidget(strings_widget)
        strings_main_layout.addWidget(self.yara_strings_scroll)
        
        add_string_btn = QPushButton("+ Add String")
        add_string_btn.setToolTip("Add a new string definition")
        add_string_btn.clicked.connect(self.add_yara_string_entry)
        strings_main_layout.addWidget(add_string_btn)
        
        strings_group.setLayout(strings_main_layout)
        yara_layout.addWidget(strings_group)

        # Enhanced Condition Section
        condition_group = QGroupBox("Rule Condition")
        condition_layout = QVBoxLayout()
        condition_layout.setSpacing(8)
        
        # Condition helper
        self.yara_condition_edit = QPlainTextEdit()
        self.yara_condition_edit.setPlaceholderText("Enter YARA condition here...")
        self.yara_condition_edit.setToolTip("Boolean expression using string references, operators, and YARA functions")
        self.yara_condition_edit.setMinimumHeight(80)
        
        condition_helper = ConditionHelperWidget(condition_edit=self.yara_condition_edit, rule_type="YARA")
        condition_layout.addWidget(condition_helper)
        condition_layout.addWidget(self.yara_condition_edit)
        
        self.yara_condition_error = QLabel()
        self.yara_condition_error.setStyleSheet("color: red")
        self.yara_condition_error.setVisible(False)
        condition_layout.addWidget(self.yara_condition_error)
        
        condition_group.setLayout(condition_layout)
        yara_layout.addWidget(condition_group)

        yara_widget.setLayout(yara_layout)
        return yara_widget

    def create_sigma_form(self):
        """Create the Sigma rule form widget."""
        sigma_widget = QWidget()
        sigma_layout = QVBoxLayout()
        sigma_layout.setSpacing(12)

        # Rule Info
        info_group = QGroupBox("Rule Information")
        info_layout = QFormLayout()
        info_layout.setSpacing(8)
        
        self.sigma_title_edit = QLineEdit()
        self.sigma_title_edit.setToolTip("Sigma rule title")
        self.sigma_title_edit.setMinimumWidth(200)
        
        self.sigma_description_edit = QPlainTextEdit()
        self.sigma_description_edit.setPlaceholderText("Rule description...")
        self.sigma_description_edit.setToolTip("Description of what the rule detects")
        self.sigma_description_edit.setMinimumHeight(60)
        self.sigma_description_edit.setMaximumHeight(100)
        
        # Add error label for title
        self.sigma_title_error = QLabel()
        self.sigma_title_error.setStyleSheet("color: red")
        self.sigma_title_error.setVisible(False)
        
        info_layout.addRow("Title:", self.sigma_title_edit)
        info_layout.addRow("", self.sigma_title_error)
        info_layout.addRow("Description:", self.sigma_description_edit)
        info_group.setLayout(info_layout)
        sigma_layout.addWidget(info_group)

        # Logsource
        logsource_group = QGroupBox("Log Source")
        logsource_layout = QFormLayout()
        logsource_layout.setSpacing(8)
        
        self.sigma_product_edit = QLineEdit()
        self.sigma_product_edit.setPlaceholderText("windows, linux, macos, etc.")
        self.sigma_product_edit.setToolTip("Product generating the logs")
        
        self.sigma_service_edit = QLineEdit()
        self.sigma_service_edit.setPlaceholderText("sysmon, auditd, etc.")
        self.sigma_service_edit.setToolTip("Service/component generating the logs")
        
        self.sigma_category_edit = QLineEdit()
        self.sigma_category_edit.setPlaceholderText("process_creation, network_connection, etc. (optional)")
        self.sigma_category_edit.setToolTip("Optional log category")
        
        # Add error label for logsource
        self.sigma_logsource_error = QLabel()
        self.sigma_logsource_error.setStyleSheet("color: red")
        self.sigma_logsource_error.setVisible(False)
        
        logsource_layout.addRow("Product:", self.sigma_product_edit)
        logsource_layout.addRow("Service:", self.sigma_service_edit)
        logsource_layout.addRow("Category:", self.sigma_category_edit)
        logsource_layout.addRow("", self.sigma_logsource_error)
        logsource_group.setLayout(logsource_layout)
        sigma_layout.addWidget(logsource_group)

        # Detection Patterns
        detection_group = QGroupBox("Detection Patterns")
        detection_main_layout = QVBoxLayout()
        
        # Scroll area for detection patterns
        self.sigma_detection_scroll = QScrollArea()
        self.sigma_detection_scroll.setWidgetResizable(True)
        self.sigma_detection_scroll.setMinimumHeight(200)
        self.sigma_detection_scroll.setMaximumHeight(400)
        
        detection_widget = QWidget()
        self.sigma_detection_area = QVBoxLayout()
        self.sigma_detection_area.setSpacing(8)
        self.sigma_detection_widgets = []
        self.add_sigma_detection_entry()  # Add one by default
        
        detection_widget.setLayout(self.sigma_detection_area)
        self.sigma_detection_scroll.setWidget(detection_widget)
        detection_main_layout.addWidget(self.sigma_detection_scroll)
        
        add_detection_btn = QPushButton("+ Add Detection")
        add_detection_btn.setToolTip("Add a new detection pattern")
        add_detection_btn.clicked.connect(self.add_sigma_detection_entry)
        detection_main_layout.addWidget(add_detection_btn)
        
        detection_group.setLayout(detection_main_layout)
        sigma_layout.addWidget(detection_group)

        # Condition
        condition_group = QGroupBox("Rule Condition")
        condition_layout = QVBoxLayout()
        condition_layout.setSpacing(8)
        
        self.sigma_condition_edit = QPlainTextEdit()
        self.sigma_condition_edit.setPlaceholderText("Enter Sigma condition here (e.g., selection, cmd_exec and unusual_parent)")
        self.sigma_condition_edit.setToolTip("Boolean expression using detection IDs and logical operators")
        self.sigma_condition_edit.setMinimumHeight(80)
        
        sigma_condition_helper = ConditionHelperWidget(condition_edit=self.sigma_condition_edit, rule_type="Sigma")
        condition_layout.addWidget(sigma_condition_helper)
        condition_layout.addWidget(self.sigma_condition_edit)
        
        # Add error label for condition
        self.sigma_condition_error = QLabel()
        self.sigma_condition_error.setStyleSheet("color: red")
        self.sigma_condition_error.setVisible(False)
        condition_layout.addWidget(self.sigma_condition_error)
        
        condition_group.setLayout(condition_layout)
        sigma_layout.addWidget(condition_group)

        # Fields and Additional Options
        additional_group = QGroupBox("Additional Options")
        additional_layout = QFormLayout()
        additional_layout.setSpacing(8)
        
        self.sigma_fields_edit = QLineEdit()
        self.sigma_fields_edit.setPlaceholderText("HostName, User, ProcessId (comma-separated)")
        self.sigma_fields_edit.setToolTip("Fields to include in detection output")
        
        self.sigma_tags_edit = QLineEdit()
        self.sigma_tags_edit.setPlaceholderText("attack.execution, attack.t1059 (comma-separated)")
        self.sigma_tags_edit.setToolTip("MITRE ATT&CK tags and other classification tags")
        
        self.sigma_level_combo = QComboBox()
        self.sigma_level_combo.addItems(["", "low", "medium", "high", "critical"])
        self.sigma_level_combo.setToolTip("Severity level of the detection")
        
        # Add error label for tags/level
        self.sigma_tags_error = QLabel()
        self.sigma_tags_error.setStyleSheet("color: red")
        self.sigma_tags_error.setVisible(False)
        
        additional_layout.addRow("Fields:", self.sigma_fields_edit)
        additional_layout.addRow("Tags:", self.sigma_tags_edit)
        additional_layout.addRow("Level:", self.sigma_level_combo)
        additional_layout.addRow("", self.sigma_tags_error)
        additional_group.setLayout(additional_layout)
        sigma_layout.addWidget(additional_group)

        sigma_widget.setLayout(sigma_layout)
        return sigma_widget

    def on_mode_changed(self, index):
        """Handle mode switching between YARA and Sigma."""
        if index == 0:  # YARA selected
            self.current_mode = "YARA Rule"
            self.stacked_widget.setCurrentIndex(0)
            self.preview_btn.setText("Preview YARA Rule")
            self.preview_btn.setToolTip("Generate and preview the YARA rule (Ctrl+Enter)")
            self.export_btn.setText("Export YARA")
            self.status_bar.showMessage("Switched to YARA mode", 2000)
        else:  # Sigma selected
            self.current_mode = "Sigma Rule"
            self.stacked_widget.setCurrentIndex(1)
            self.preview_btn.setText("Preview Sigma Rule")
            self.preview_btn.setToolTip("Generate and preview the Sigma rule (Ctrl+Shift+Enter or Ctrl+Enter)")
            self.export_btn.setText("Export Sigma")
            self.status_bar.showMessage("Switched to Sigma mode", 2000)

    # YARA-specific methods
    def add_yara_meta_entry(self):
        widget = MetaEntryWidget(remove_callback=self.remove_yara_meta_entry)
        self.yara_meta_area.addWidget(widget)
        self.yara_meta_widgets.append(widget)
        self.status_bar.showMessage("Meta field added", 2000)
    
    def remove_yara_meta_entry(self, widget):
        if len(self.yara_meta_widgets) > 1:  # Keep at least one
            widget.setParent(None)
            self.yara_meta_widgets.remove(widget)
            self.status_bar.showMessage("Meta field removed", 2000)

    def add_yara_string_entry(self):
        widget = StringEntryWidget(remove_callback=self.remove_yara_string_entry)
        self.yara_strings_area.addWidget(widget)
        self.yara_string_widgets.append(widget)
        
        # Auto-scroll to bottom if >5 entries
        if len(self.yara_string_widgets) > 5:
            self.yara_strings_scroll.ensureWidgetVisible(widget)
        
        self.status_bar.showMessage("String entry added", 2000)
    
    def remove_yara_string_entry(self, widget):
        if len(self.yara_string_widgets) > 1:  # Keep at least one
            widget.setParent(None)
            self.yara_string_widgets.remove(widget)
            self.status_bar.showMessage("String entry removed", 2000)

    # Sigma-specific methods
    def add_sigma_detection_entry(self):
        """Add a new detection entry with focus behavior."""
        widget = DetectionEntryWidget(remove_callback=self.remove_sigma_detection_entry)
        self.sigma_detection_area.addWidget(widget)
        self.sigma_detection_widgets.append(widget)
        
        # Auto-scroll to bottom if >5 entries
        if len(self.sigma_detection_widgets) > 5:
            self.sigma_detection_scroll.ensureWidgetVisible(widget)
        
        # Focus on the detection ID field of the newly added entry
        widget.detection_id_edit.setFocus()
        
        self.status_bar.showMessage("Detection entry added", 2000)
        
    def remove_sigma_detection_entry(self, widget):
        if len(self.sigma_detection_widgets) > 1:  # Keep at least one
            widget.setParent(None)
            self.sigma_detection_widgets.remove(widget)
            self.status_bar.showMessage("Detection entry removed", 2000)

    def collect_yara_rule_data(self):
        """Collect YARA rule data from form."""
        name = self.yara_name_edit.text().strip()
        tags = [t.strip() for t in self.yara_tags_edit.text().split(",") if t.strip()]
        
        # Collect dynamic meta fields
        meta = {}
        for w in self.yara_meta_widgets:
            key, value = w.get_data()
            if key and value:
                meta[key] = value
        
        # Collect string entries
        strings = []
        for w in self.yara_string_widgets:
            data = w.get_data()
            if data["id"] and data["value"]:
                entry = {"id": data["id"], "type": data["type"], "value": data["value"]}
                if data["modifiers"]:
                    entry["modifiers"] = data["modifiers"]
                strings.append(entry)
        
        condition = self.yara_condition_edit.toPlainText()
        return name, tags, meta, strings, condition

    def collect_sigma_rule_data(self):
        """Collect Sigma rule data from form."""
        name = self.sigma_title_edit.text().strip()
        description = self.sigma_description_edit.toPlainText().strip()
        
        # Collect logsource
        logsource = {
            "product": self.sigma_product_edit.text().strip(),
            "service": self.sigma_service_edit.text().strip()
        }
        if self.sigma_category_edit.text().strip():
            logsource["category"] = self.sigma_category_edit.text().strip()
        
        # Collect detection patterns
        detection = {}
        for w in self.sigma_detection_widgets:
            detection_id, patterns = w.get_data()
            if detection_id and patterns:
                detection[detection_id] = patterns
        
        condition = self.sigma_condition_edit.toPlainText().strip()
        
        # Collect fields
        fields_text = self.sigma_fields_edit.text().strip()
        fields = [f.strip() for f in fields_text.split(",") if f.strip()] if fields_text else []
        
        # Collect tags
        tags_text = self.sigma_tags_edit.text().strip()
        tags = [t.strip() for t in tags_text.split(",") if t.strip()] if tags_text else None
        
        # Collect level
        level = self.sigma_level_combo.currentText() if self.sigma_level_combo.currentText() else None
        
        return name, description, logsource, detection, condition, fields, tags, level

    def clear_yara_errors(self):
        """Clear YARA-specific error displays."""
        self.yara_name_error.setVisible(False)
        self.yara_name_edit.setStyleSheet("")
        self.yara_condition_error.setVisible(False)
        self.yara_condition_edit.setStyleSheet("")
        for w in self.yara_string_widgets:
            w.set_error("")
        for w in self.yara_meta_widgets:
            w.set_error("")

    def clear_sigma_errors(self):
        """Clear Sigma-specific error displays."""
        # Clear title field styling and error label
        self.sigma_title_edit.setStyleSheet("")
        self.sigma_title_error.setVisible(False)
        
        # Clear logsource field styling and error label
        self.sigma_product_edit.setStyleSheet("")
        self.sigma_service_edit.setStyleSheet("")
        self.sigma_category_edit.setStyleSheet("")
        self.sigma_logsource_error.setVisible(False)
        
        # Clear condition field styling and error label
        self.sigma_condition_edit.setStyleSheet("")
        self.sigma_condition_error.setVisible(False)
        
        # Clear detection entries styling
        for w in self.sigma_detection_widgets:
            if hasattr(w, 'set_error'):
                w.set_error("")

    def clear_errors(self):
        """Clear all error displays."""
        self.clear_yara_errors()
        self.clear_sigma_errors()

    def show_yara_errors(self, error_msg):
        """Enhanced error display for YARA rules in preview with color coding."""
        self.preview_edit.setHtml(f'''
        <div style="color: red; font-family: Courier New; white-space: pre-wrap;">
        <strong>❌ YARA VALIDATION ERROR:</strong>
        
        {error_msg}
        </div>
        ''')
        
        # Parse error message for field-specific highlighting
        error_lower = error_msg.lower()
        
        # Rule name errors
        if any(pattern in error_lower for pattern in ["rule name", "invalid rule name", "must be a string"]) or \
           any(pattern in error_msg for pattern in ["Invalid rule name", "Rule name must"]):
            self.yara_name_error.setText(error_msg.split('\n')[0])
            self.yara_name_error.setVisible(True)
            self.yara_name_error.show()
            self.yara_name_error.repaint()
            self.yara_name_edit.setStyleSheet("border: 1.5px solid red;")
        
        # Meta key errors
        if any(pattern in error_lower for pattern in ["meta key", "invalid meta key", "snake_case"]):
            for w in self.yara_meta_widgets:
                key, _ = w.get_data()
                if key and key in error_msg:
                    w.set_error(error_msg.split('\n')[0])
        
        # Condition errors
        if any(word in error_lower for word in ["condition", "undefined string", "wildcard reference"]):
            self.yara_condition_error.setText(error_msg.split('\n')[0])
            self.yara_condition_error.setVisible(True)
            self.yara_condition_error.show()
            self.yara_condition_edit.setStyleSheet("border: 1.5px solid red;")
        
        # String-related errors
        if any(word in error_lower for word in ["string id", "duplicate string", "string entry", "hex pattern", "regex flags", "modifier"]):
            for w in self.yara_string_widgets:
                string_id = w.id_edit.text()
                if (string_id and string_id in error_msg) or not string_id or "string entry" in error_lower:
                    w.set_error(error_msg.split('\n')[0])

    def show_sigma_errors(self, error_msg):
        """Enhanced error display for Sigma rules in preview with color coding."""
        self.preview_edit.setHtml(f'''
        <div style="color: red; font-family: Courier New; white-space: pre-wrap;">
        <strong>❌ SIGMA VALIDATION ERROR:</strong>
        
        {error_msg}
        </div>
        ''')
        
        # Parse error message for field-specific highlighting
        error_lower = error_msg.lower()
        
        # Rule title errors
        if any(pattern in error_lower for pattern in ["rule name", "title", "name cannot be empty"]):
            if hasattr(self, 'sigma_title_error'):
                self.sigma_title_error.setText(error_msg.split('\n')[0])
                self.sigma_title_error.setVisible(True)
                self.sigma_title_error.show()
            self.sigma_title_edit.setStyleSheet("border: 1.5px solid red;")
        
        # Logsource errors
        if any(pattern in error_lower for pattern in ["logsource", "product", "service"]):
            if hasattr(self, 'sigma_logsource_error'):
                self.sigma_logsource_error.setText(error_msg.split('\n')[0])
                self.sigma_logsource_error.setVisible(True)
                self.sigma_logsource_error.show()
            if "product" in error_lower:
                self.sigma_product_edit.setStyleSheet("border: 1.5px solid red;")
            if "service" in error_lower:
                self.sigma_service_edit.setStyleSheet("border: 1.5px solid red;")
        
        # Detection errors
        if any(pattern in error_lower for pattern in ["detection", "undefined detection", "invalid detection"]):
            for w in self.sigma_detection_widgets:
                detection_id, _ = w.get_data()
                if detection_id and detection_id in error_msg:
                    w.set_error(error_msg.split('\n')[0])
        
        # Condition errors
        if any(word in error_lower for word in ["condition", "undefined", "declared"]):
            if hasattr(self, 'sigma_condition_error'):
                self.sigma_condition_error.setText(error_msg.split('\n')[0])
                self.sigma_condition_error.setVisible(True)
                self.sigma_condition_error.show()
            self.sigma_condition_edit.setStyleSheet("border: 1.5px solid red;")
        
        # Tags/level errors
        if any(pattern in error_lower for pattern in ["tags", "level"]):
            if hasattr(self, 'sigma_tags_error'):
                self.sigma_tags_error.setText(error_msg.split('\n')[0])
                self.sigma_tags_error.setVisible(True)
                self.sigma_tags_error.show()
            if "tags" in error_lower:
                self.sigma_tags_edit.setStyleSheet("border: 1.5px solid red;")

    def show_warnings(self, warning_msg, rule_type="YARA"):
        """Show warnings in orange."""
        self.preview_edit.setHtml(f'''
        <div style="color: orange; font-family: Courier New; white-space: pre-wrap;">
        <strong>⚠️ {rule_type} WARNING:</strong>
        
        {warning_msg}
        
        <em>Rule may still be valid but could have performance issues.</em>
        </div>
        ''')

    def on_preview(self):
        """Handle preview button click for both YARA and Sigma modes."""
        self.clear_errors()
        
        current_mode = self.mode_combo.currentText()
        
        if current_mode == "YARA Rule":
            self.status_bar.showMessage("Generating YARA rule preview...")
            try:
                name, tags, meta, strings, condition = self.collect_yara_rule_data()
                rule = build_yara_rule(name, tags, meta, strings, condition)
                
                # Display successful rule with syntax highlighting
                self.preview_edit.setHtml(f'''
                <div style="font-family: Courier New; white-space: pre-wrap; color: #2e7d32;">
                <strong>✅ VALID YARA RULE:</strong>
                </div>
                <pre style="font-family: Courier New; margin-top: 10px;">{rule}</pre>
                ''')
                self.status_bar.showMessage("YARA rule generated successfully", 3000)
                
            except RuleWarning as w:
                self.show_warnings(str(w), "YARA")
                QMessageBox.warning(self, "Performance Warning", str(w))
                self.status_bar.showMessage("YARA rule generated with warnings", 3000)
                
            except ValueError as e:
                self.show_yara_errors(str(e))
                self.status_bar.showMessage("YARA validation failed", 3000)
            
            except Exception as e:
                self.preview_edit.setHtml(f'''
                <div style="color: red; font-family: Courier New;">
                <strong>❌ UNEXPECTED ERROR:</strong><br>
                {str(e)}
                </div>
                ''')
                self.status_bar.showMessage("Unexpected error occurred", 3000)
        
        else:  # Sigma Rule
            self.status_bar.showMessage("Generating Sigma rule preview...")
            try:
                name, description, logsource, detection, condition, fields, tags, level = self.collect_sigma_rule_data()
                rule = build_sigma_rule(name, description, logsource, detection, condition, fields, tags, level)
                
                # Display successful rule with syntax highlighting
                self.preview_edit.setHtml(f'''
                <div style="font-family: Courier New; white-space: pre-wrap; color: #2e7d32;">
                <strong>✅ VALID SIGMA RULE:</strong>
                </div>
                <pre style="font-family: Courier New; margin-top: 10px;">{rule}</pre>
                ''')
                self.status_bar.showMessage("Sigma rule generated successfully", 3000)
                
            except SigmaWarning as w:
                self.show_warnings(str(w), "SIGMA")
                QMessageBox.warning(self, "Performance Warning", str(w))
                self.status_bar.showMessage("Sigma rule generated with warnings", 3000)
                
            except ValueError as e:
                self.show_sigma_errors(str(e))
                self.status_bar.showMessage("Sigma validation failed", 3000)
            
            except Exception as e:
                self.preview_edit.setHtml(f'''
                <div style="color: red; font-family: Courier New;">
                <strong>❌ UNEXPECTED ERROR:</strong><br>
                {str(e)}
                </div>
                ''')
                self.status_bar.showMessage("Unexpected error occurred", 3000)

    def on_export(self):
        """Handle export button click for both YARA and Sigma modes."""
        self.clear_errors()
        
        current_mode = self.mode_combo.currentText()
        
        if current_mode == "YARA Rule":
            self.status_bar.showMessage("Preparing YARA export...")
            try:
                name, tags, meta, strings, condition = self.collect_yara_rule_data()
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
                    self.status_bar.showMessage(f"YARA rule exported to {fname}", 5000)
                    
            except RuleWarning as w:
                self.show_warnings(str(w), "YARA")
                QMessageBox.warning(self, "Performance Warning", 
                                   f"Warning: {w}\n\nExport anyway?")
                
            except ValueError as e:
                self.show_yara_errors(str(e))
                QMessageBox.critical(self, "Export Failed", 
                                   f"Cannot export invalid YARA rule:\n{e}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export YARA rule: {e}")
                self.status_bar.showMessage("YARA export failed", 3000)
        
        else:  # Sigma Rule
            self.status_bar.showMessage("Preparing Sigma export...")
            try:
                name, description, logsource, detection, condition, fields, tags, level = self.collect_sigma_rule_data()
                rule = build_sigma_rule(name, description, logsource, detection, condition, fields, tags, level)
                
                suggested_name = f"{name or 'rule'}.yml"
                fname, _ = QFileDialog.getSaveFileName(
                    self, 
                    "Export Sigma Rule", 
                    suggested_name, 
                    "YAML Files (*.yml *.yaml);;All Files (*)"
                )
                
                if fname:
                    with open(fname, "w", encoding="utf-8") as f:
                        f.write(rule)
                    self.status_bar.showMessage(f"Sigma rule exported to {fname}", 5000)
                    
            except SigmaWarning as w:
                self.show_warnings(str(w), "SIGMA")
                QMessageBox.warning(self, "Performance Warning", 
                                   f"Warning: {w}\n\nExport anyway?")
                
            except ValueError as e:
                self.show_sigma_errors(str(e))
                QMessageBox.critical(self, "Export Failed", 
                                   f"Cannot export invalid Sigma rule:\n{e}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export Sigma rule: {e}")
                self.status_bar.showMessage("Sigma export failed", 3000)

    def on_clear(self):
        """Handle clear button click for both YARA and Sigma modes."""
        current_mode = self.mode_combo.currentText()
        
        if current_mode == "YARA Rule":
            # Clear YARA fields
            self.yara_name_edit.clear()
            self.yara_tags_edit.clear()
            self.yara_condition_edit.clear()
            self.clear_yara_errors()
            
            # Reset YARA meta widgets to one empty entry
            for w in self.yara_meta_widgets:
                w.setParent(None)
            self.yara_meta_widgets.clear()
            self.add_yara_meta_entry()
            
            # Reset YARA string widgets to one empty entry
            for w in self.yara_string_widgets:
                w.setParent(None)
            self.yara_string_widgets.clear()
            self.add_yara_string_entry()
            
            self.status_bar.showMessage("YARA fields cleared", 2000)
        
        else:  # Sigma Rule
            # Clear Sigma fields
            self.sigma_title_edit.clear()
            self.sigma_description_edit.clear()
            self.sigma_product_edit.clear()
            self.sigma_service_edit.clear()
            self.sigma_category_edit.clear()
            self.sigma_condition_edit.clear()
            self.sigma_fields_edit.clear()
            self.sigma_tags_edit.clear()
            self.sigma_level_combo.setCurrentIndex(0)
            self.clear_sigma_errors()
            
            # Reset Sigma detection widgets to one empty entry
            for w in self.sigma_detection_widgets:
                w.setParent(None)
            self.sigma_detection_widgets.clear()
            self.add_sigma_detection_entry()
            
            self.status_bar.showMessage("Sigma fields cleared", 2000)
        
        # Clear preview regardless of mode
        self.preview_edit.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RuleBuilderGUI()
    window.show()
    sys.exit(app.exec_())






