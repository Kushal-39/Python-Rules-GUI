import re
from typing import List, Dict, Set
from difflib import get_close_matches


class RuleWarning(Warning):
    pass


RESERVED_WORDS = {"rule", "meta", "strings", "condition", "and", "or", "not", "true", "false", "import", "include", "private", "global", "filesize", "entrypoint", "all", "any", "them", "for", "of", "at", "in"}

VALID_MODIFIERS = {"ascii", "wide", "nocase", "private", "fullword"}
CONFLICTING_MODIFIERS = [("wide", "ascii")]


def build_yara_rule(
    name: str,
    tags: List[str],
    meta: Dict[str, str],
    strings: List[Dict[str, str]],
    condition: str
) -> str:
    _validate_input_types(name, tags, meta, strings, condition)
    _validate_reserved_words(name)
    _validate_meta_keys(meta)
    _validate_strings_comprehensive(strings)
    _validate_condition_references(condition, strings)
    
    rule_parts = []
    
    header = f"rule {name}"
    if tags:
        header += " : " + " ".join(tags)
    rule_parts.append(header)
    rule_parts.append("{")
    
    # Skip empty meta/strings blocks
    if meta:
        rule_parts.append("    meta:")
        for key in sorted(meta.keys()):
            value = meta[key]
            escaped_value = _escape_string_value(value)
            rule_parts.append(f'        {key} = "{escaped_value}"')
    
    if strings:
        rule_parts.append("    strings:")
        for string_entry in strings:
            string_line = _format_string_entry(string_entry)
            rule_parts.append(f"        {string_line}")
    
    rule_parts.append("    condition:")
    
    # Handle multiline conditions
    condition_text = condition.strip()
    if '\n' in condition_text:
        condition_lines = condition_text.split('\n')
        for line in condition_lines:
            rule_parts.append(f"        {line.strip()}")
    else:
        rule_parts.append(f"        {condition_text}")
    
    rule_parts.append("}")
    
    return "\n".join(rule_parts)


def _validate_input_types(name: str, tags: List[str], meta: Dict[str, str], strings: List[Dict[str, str]], condition: str) -> None:
    if not isinstance(name, str):
        raise ValueError("Rule name must be a string.")
    if not isinstance(tags, list):
        raise ValueError("Tags must be a list of strings.")
    if not isinstance(meta, dict):
        raise ValueError("Meta must be a dictionary with string keys and values.")
    if not isinstance(strings, list):
        raise ValueError("Strings must be a list of dictionaries.")
    if not isinstance(condition, str) or not condition.strip():
        raise ValueError("Condition must be a non-empty string expression.")


def _validate_reserved_words(name: str) -> None:
    if not _is_valid_identifier(name):
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if clean_name and clean_name[0].isdigit():
            clean_name = f"rule_{clean_name}"
        raise ValueError(
            f"Invalid rule name '{name}'. Must follow:\n"
            f"- Start with letter or underscore\n"
            f"- Contain only A-Z, 0-9, _\n"
            f"Suggested fix: '{clean_name}'"
        )
    
    if name.lower() in RESERVED_WORDS:
        suggestions = ["apt32_backdoor", "trojan_detector", "malware_scanner"]
        raise ValueError(
            f"'{name}' is a YARA reserved word. Use descriptive names like:\n"
            f"- {', '.join(suggestions)}\n"
            f"- {name}_detector\n"
            f"- custom_{name}_rule"
        )


def _validate_meta_keys(meta: Dict[str, str]) -> None:
    """Validate meta keys use snake_case format."""
    for key, value in meta.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Meta keys and values must be strings.")
        
        if not re.match(r"^[a-z][a-z0-9_]*$", key):
            snake_case = re.sub(r'([A-Z])', r'_\1', key).lower().strip('_')
            snake_case = re.sub(r'[^a-z0-9_]', '_', snake_case)
            raise ValueError(
                f"Invalid meta key '{key}'. Use snake_case format.\n"
                f"Suggested fix: '{snake_case}'\n"
                f"Examples: 'threat_level', 'malware_family', 'detection_date'"
            )


def _validate_strings_comprehensive(strings: List[Dict[str, str]]) -> None:
    declared_ids = set()
    
    for i, string_entry in enumerate(strings):
        if not isinstance(string_entry, dict):
            raise ValueError(f"String entry {i} must be a dictionary.")
        
        string_id = string_entry.get("id", "")
        if not _is_valid_string_id(string_id):
            clean_id = f"${re.sub(r'[^a-zA-Z0-9_]', '_', string_id.lstrip('$'))}"
            raise ValueError(
                f"Invalid string ID '{string_id}' at position {i}. Must follow:\n"
                f"- Start with '$' (e.g., '$payload')\n"
                f"- Contain only A-Z, 0-9, _\n"
                f"Suggested fix: '{clean_id}'"
            )
        
        if string_id in declared_ids:
            raise ValueError(f"Duplicate string ID '{string_id}' at position {i}.")
        declared_ids.add(string_id)
        
        if "value" not in string_entry:
            raise ValueError(f"String entry {i} missing required 'value' key.")
        
        if not isinstance(string_entry["value"], str):
            raise ValueError(f"String entry {i} value must be a string.")
        
        _validate_string_type_and_format(string_entry, i)
        _validate_modifiers(string_entry, i)


def _check_lazy_quantifier(entry: Dict[str, str]) -> None:
    """Check for performance-impacting lazy quantifiers."""
    value = entry["value"]
    string_id = entry["id"]
    
    if re.search(r"\.\*\?", value) and len(value) < 20:
        raise RuleWarning(f"Lazy quantifier in '{string_id}' may cause performance issues")


def _check_nested_wildcards(entry: Dict[str, str]) -> None:
    """Check for exponential backtracking patterns."""
    value = entry["value"]
    string_id = entry["id"]
    
    if re.search(r"\.\*\.\*", value):
        raise RuleWarning(f"Nested wildcards in '{string_id}' may cause exponential backtracking")


def _validate_string_type_and_format(string_entry: Dict[str, str], index: int) -> None:
    """Validate string format per YARA specs."""
    string_type = string_entry.get("type", "text")
    value = string_entry["value"]
    string_id = string_entry["id"]
    
    if string_type == "regex":
        if re.search(r"\(\?[iLmsux]*\)", value):
            raise ValueError(
                f"Unsafe regex flags in '{string_id}'. YARA doesn't support PCRE flags.\n"
                f"Remove flags like (?i), (?m), etc. Use YARA modifiers instead."
            )
        
        # Check regex patterns
        _check_lazy_quantifier(string_entry)
        _check_nested_wildcards(string_entry)
    
    elif string_type == "hex":
        if not re.match(r'^[0-9A-Fa-f\s\?\[\]\-\(\)\|]+$', value):
            raise ValueError(
                f"Invalid hex pattern in '{string_id}'. Use format:\n"
                f"- Hex bytes: '4D 5A 90 00'\n"
                f"- Wildcards: '4D 5A ?? 00'\n"
                f"- Jumps: '4D 5A [4-6] 00'\n"
                f"- Alternatives: '(4D | 5A) 90 00'"
            )


def _validate_modifiers(string_entry: Dict[str, str], index: int) -> None:
    """Validate string modifiers for conflicts."""
    modifiers_str = string_entry.get("modifiers", "")
    if not modifiers_str:
        return
    
    if isinstance(modifiers_str, list):
        modifiers = modifiers_str
    else:
        modifiers = [mod.strip() for mod in modifiers_str.split()]
    
    string_id = string_entry["id"]
    
    for mod1, mod2 in CONFLICTING_MODIFIERS:
        if mod1 in modifiers and mod2 in modifiers:
            raise ValueError(
                f"Conflicting modifiers in '{string_id}': cannot combine '{mod1}' and '{mod2}'.\n"
                f"Choose one based on your target:\n"
                f"- 'ascii' for single-byte strings\n"
                f"- 'wide' for Unicode/UTF-16 strings"
            )
    
    for modifier in modifiers:
        if modifier not in VALID_MODIFIERS and not modifier.startswith("xor"):
            raise ValueError(
                f"Invalid modifier '{modifier}' in '{string_id}'.\n"
                f"Valid modifiers: {', '.join(VALID_MODIFIERS)}\n"
                f"Or use XOR format: 'xor(0x00-0xFF)'"
            )
        
        if modifier.startswith("xor") and not re.match(r"xor\s*\(\s*0x[0-9A-Fa-f]+\s*-\s*0x[0-9A-Fa-f]+\s*\)", modifier):
            raise ValueError(
                f"Invalid XOR format in '{string_id}': '{modifier}'.\n"
                f"Use format: 'xor(0x00-0xFF)' or 'xor(0x01-0xFE)'"
            )


def _validate_condition_references(condition: str, strings: List[Dict[str, str]]) -> None:
    """Validate string references in condition."""
    declared_ids = {s["id"].lstrip('$') for s in strings}
    
    used_ids = set(re.findall(r'\$(\w+\*?)', condition))
    
    wildcard_ids = {uid for uid in used_ids if uid.endswith('*')}
    exact_ids = used_ids - wildcard_ids
    
    if undefined_exact := exact_ids - declared_ids:
        suggestions = []
        for undefined_id in undefined_exact:
            closest = get_close_matches(undefined_id, declared_ids, n=1, cutoff=0.6)
            if closest:
                suggestions.append(f"${undefined_id} → ${closest[0]}")
            else:
                suggestions.append(f"${undefined_id} → [no close match]")
        
        raise ValueError(
            f"Undefined string references in condition: {', '.join(f'${uid}' for uid in undefined_exact)}.\n"
            f"Declared strings: {', '.join(f'${did}' for did in declared_ids)}\n"
            f"Did you mean: {', '.join(suggestions)}?"
        )
    
    # Validate wildcards
    for wildcard_id in wildcard_ids:
        base_prefix = wildcard_id.rstrip('*')
        if not base_prefix:
            continue
        
        matching_strings = [did for did in declared_ids if did.startswith(base_prefix)]
        
        if not matching_strings:
            raise ValueError(
                f"Wildcard reference '${wildcard_id}' has no matching strings.\n"
                f"Declared strings: {', '.join(f'${did}' for did in declared_ids)}\n"
                f"Expected strings starting with '{base_prefix}' (e.g., ${base_prefix}1, ${base_prefix}2)"
            )


def _format_string_entry(string_entry: Dict[str, str]) -> str:
    """Format string entry for YARA syntax."""
    string_id = string_entry["id"]
    value = string_entry["value"]
    string_type = string_entry.get("type", "text")
    modifiers = string_entry.get("modifiers", "")
    
    if string_type == "hex":
        normalized_value = _normalize_hex_string(value)
        formatted_value = f"{{ {normalized_value} }}"
    elif string_type == "regex":
        escaped_value = value.replace("/", "\\/")
        
        if not (escaped_value.startswith("/") and escaped_value.endswith("/")):
            formatted_value = f"/{escaped_value}/"
        else:
            formatted_value = escaped_value
    else:
        escaped_value = _escape_string_value(value)
        formatted_value = f'"{escaped_value}"'
    
    result = f"{string_id} = {formatted_value}"
    if modifiers:
        result += f" {modifiers}"
    
    return result


def _normalize_hex_string(hex_str: str) -> str:
    """Normalize hex string with proper spacing."""
    normalized = re.sub(r'\s+', ' ', hex_str.strip())
    
    # Add spaces around operators
    normalized = re.sub(r'([0-9A-Fa-f])(\[)', r'\1 \2', normalized)
    normalized = re.sub(r'(\])([0-9A-Fa-f\?\(\[])', r'\1 \2', normalized)
    normalized = re.sub(r'([0-9A-Fa-f])(\()', r'\1 \2', normalized)
    normalized = re.sub(r'(\))([0-9A-Fa-f\?\[\]])', r'\1 \2', normalized)
    normalized = re.sub(r'([0-9A-Fa-f])(\|)', r'\1 \2', normalized)
    normalized = re.sub(r'(\|)([0-9A-Fa-f\?\(\[])', r'\1 \2', normalized)
    
    normalized = re.sub(r'(\()([0-9A-Fa-f])', r'\1 \2', normalized)
    normalized = re.sub(r'([0-9A-Fa-f])(\))', r'\1 \2', normalized)
    
    # Handle wildcards
    normalized = re.sub(r'([0-9A-Fa-f])(\?\?)', r'\1 \2', normalized)
    normalized = re.sub(r'(\?\?)([0-9A-Fa-f\[\(\|])', r'\1 \2', normalized)
    
    normalized = re.sub(r'([0-9A-Fa-f])(\?)(?!\?)', r'\1 \2', normalized)
    normalized = re.sub(r'(?<!\?)(\?)([0-9A-Fa-f\[\(\|])', r'\1 \2', normalized)
    
    # Handle dashes outside brackets
    parts = []
    inside_brackets = False
    current_part = ""
    
    i = 0
    while i < len(normalized):
        char = normalized[i]
        
        if char == '[':
            inside_brackets = True
            current_part += char
        elif char == ']':
            inside_brackets = False
            current_part += char
        elif char == '-' and not inside_brackets:
            if current_part and current_part[-1] not in ' ':
                current_part += ' '
            current_part += char
            if i + 1 < len(normalized) and normalized[i + 1] not in ' ':
                current_part += ' '
        else:
            current_part += char
        
        i += 1
    
    normalized = current_part
    
    # Separate adjacent hex pairs
    normalized = re.sub(r'([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})', r'\1 \2', normalized)
    normalized = re.sub(r'([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})', r'\1 \2', normalized)
    
    normalized = re.sub(r'\s+', ' ', normalized)
    
    return normalized


def _escape_string_value(value: str) -> str:
    """Escape special characters for YARA."""
    return (value.replace('\\', '\\\\')
                .replace('"', '\\"')
                .replace('\n', '\\n')
                .replace('\t', '\\t')
                .replace('\r', '\\r'))


def _is_valid_identifier(name: str) -> bool:
    """Check if name is valid YARA identifier."""
    if not name:
        return False
    return re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name) is not None


def _is_valid_string_id(string_id: str) -> bool:
    """Check if string ID follows YARA rules."""
    if not string_id or not string_id.startswith('$'):
        return False
    identifier_part = string_id[1:]
    return bool(identifier_part) and re.match(r'^[a-zA-Z0-9_]+$', identifier_part) is not None


if __name__ == "__main__":
    print("=== APT Detection Rule ===")
    apt_rule = build_yara_rule(
        name="APT32_Backdoor_Detection",
        tags=["apt", "backdoor", "vietnam"],
        meta={
            "author": "Threat Intel Team",
            "threat_level": "high",
            "malware_family": "apt32",
            "detection_date": "2025-06-20"
        },
        strings=[
            {"id": "$payload", "type": "hex", "value": "4D 5A ?? 50 45 00 00"},
            {"id": "$c2_domain", "type": "text", "value": "evil-command.com", "modifiers": "nocase"},
            {"id": "$mutex", "type": "text", "value": "APT32_Mutex_2025", "modifiers": "wide"}
        ],
        condition="$payload at 0 and ($c2_domain or $mutex)"
    )
    print(apt_rule)
    
    print("\n=== Ransomware Pattern ===")
    ransomware_rule = build_yara_rule(
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
            {"id": "$file_ext", "type": "regex", "value": "/\\.(locked|encrypted|crypto)$/"}
        ],
        condition="filesize > 500KB and 2 of them"
    )
    print(ransomware_rule)
