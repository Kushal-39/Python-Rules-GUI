import re
import yaml
from typing import Dict, List
from difflib import get_close_matches


class RuleWarning(Warning):
    pass


def build_sigma_rule(
    name: str,
    description: str,
    logsource: Dict[str, str],
    detection: Dict[str, List[str]],
    condition: str,
    fields: List[str],
    tags: List[str] = None,
    level: str = None
) -> str:
    """Build a valid Sigma rule as YAML string."""
    _validate_input_types(name, description, logsource, detection, condition, fields, tags, level)
    _validate_name(name)
    _validate_description(description)
    _validate_logsource(logsource)
    _validate_detection(detection)
    _validate_condition(condition, detection)
    fields = _validate_fields(fields)  # Returns normalized fields
    tags = _validate_tags(tags)
    level = _validate_level(level)
    
    rule_dict = {
        'title': name,
        'description': description,
        'logsource': _build_logsource_dict(logsource),
        'detection': detection,
        'condition': condition,
        'fields': fields
    }
    
    if tags:
        rule_dict['tags'] = tags
    if level:
        rule_dict['level'] = level
    
    return _format_yaml_output(rule_dict)


def _validate_input_types(
    name: str, 
    description: str, 
    logsource: Dict[str, str], 
    detection: Dict[str, List[str]], 
    condition: str, 
    fields: List[str],
    tags: List[str] = None,
    level: str = None
) -> None:
    """Validate all input parameter types."""
    types = [
        (name, str, "Rule name"),
        (description, str, "Description"),
        (logsource, dict, "Logsource"),
        (detection, dict, "Detection"),
        (condition, str, "Condition"),
        (fields, list, "Fields")
    ]
    
    for value, expected_type, name_str in types:
        if not isinstance(value, expected_type):
            raise ValueError(f"{name_str} must be a {expected_type.__name__}.")
    
    if tags is not None and not isinstance(tags, list):
        raise ValueError("Tags must be a list.")
    
    if level is not None and not isinstance(level, str):
        raise ValueError("Level must be a string.")


def _validate_name(name: str) -> None:
    if not name.strip():
        raise ValueError("Rule name cannot be empty.")
    
    if not re.match(r'^[A-Za-z0-9_]+$', name):
        clean_name = re.sub(r'[^A-Za-z0-9_]', '_', name)
        raise ValueError(
            f"Invalid rule name '{name}'. Must contain only letters, numbers, and underscores.\n"
            f"Suggested fix: '{clean_name}'"
        )


def _validate_description(description: str) -> None:
    if not description.strip():
        raise ValueError("Rule description cannot be empty.")


def _validate_logsource(logsource: Dict[str, str]) -> None:
    required_keys = {'product', 'service'}
    optional_keys = {'category'}
    allowed_keys = required_keys | optional_keys
    
    missing_keys = required_keys - set(logsource.keys())
    if missing_keys:
        raise ValueError(
            f"Logsource missing required keys: {', '.join(missing_keys)}.\n"
            f"Required: product, service"
        )
    
    extra_keys = set(logsource.keys()) - allowed_keys
    if extra_keys:
        raise ValueError(f"Invalid logsource keys: {', '.join(extra_keys)}")
    
    for key, value in logsource.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Logsource '{key}' must be a non-empty string.")


def _validate_detection(detection: Dict[str, List[str]]) -> None:
    """Validate detection dictionary structure and patterns."""
    if not detection:
        raise ValueError("Detection dictionary cannot be empty.")
    
    short_pattern_warnings = []
    
    for key, patterns in detection.items():
        if not _is_valid_yaml_key(key):
            snake_case = re.sub(r'([A-Z])', r'_\1', key).lower().strip('_')
            snake_case = re.sub(r'[^a-z0-9_]', '_', snake_case)
            raise ValueError(f"Invalid detection key '{key}'. Use snake_case: '{snake_case}'")
        
        if not isinstance(patterns, list) or not patterns:
            raise ValueError(f"Detection '{key}' must be a non-empty list.")
        
        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(f"Pattern {i} in '{key}' must be a non-empty string.")
            
            if len(pattern.strip()) < 3:
                short_pattern_warnings.append(f"'{pattern}' in '{key}'")
    
    if short_pattern_warnings:
        warning_list = '\n  - '.join(short_pattern_warnings)
        raise RuleWarning(f"Short patterns (< 3 chars) found:\n  - {warning_list}")


def _validate_condition(condition: str, detection: Dict[str, List[str]]) -> None:
    if not condition.strip():
        raise ValueError("Condition cannot be empty.")
    
    referenced_keys = set(re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', condition))
    logical_keywords = {'and', 'or', 'not', 'of', 'them', 'all', 'any', 'true', 'false'}
    referenced_keys -= logical_keywords
    
    declared_keys = set(detection.keys())
    undefined_keys = referenced_keys - declared_keys
    
    if undefined_keys:
        suggestions = []
        for key in undefined_keys:
            closest = get_close_matches(key, declared_keys, n=1, cutoff=0.6)
            suggestions.append(f"'{key}' → '{closest[0]}'" if closest else f"'{key}' → [no match]")
        
        raise ValueError(
            f"Undefined detection keys: {', '.join(undefined_keys)}.\n"
            f"Declared: {', '.join(declared_keys)}\n"
            f"Suggestions: {', '.join(suggestions)}"
        )


def _validate_fields(fields: List[str]) -> List[str]:
    """Validate fields list and return normalized fields."""
    if not fields:
        return ["*"]
    
    for i, field in enumerate(fields):
        if not isinstance(field, str) or not field.strip():
            raise ValueError(f"Field {i} must be a non-empty string.")
    
    return fields


def _validate_tags(tags: List[str] = None) -> List[str]:
    """Validate tags list structure."""
    if not tags:
        return []
    
    for i, tag in enumerate(tags):
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError(f"Tag {i} must be a non-empty string.")
    
    return tags


def _validate_level(level: str = None) -> str:
    """Validate severity level."""
    if not level:
        return None
    
    valid_levels = {'low', 'medium', 'high', 'critical'}
    level_lower = level.lower()
    
    if level_lower not in valid_levels:
        raise ValueError(f"Invalid level '{level}'. Must be one of: {', '.join(valid_levels)}")
    
    return level_lower


def _is_valid_yaml_key(key: str) -> bool:
    return bool(key and re.match(r'^[a-z][a-z0-9_]*$', key))


def _build_logsource_dict(logsource: Dict[str, str]) -> Dict[str, str]:
    """Build properly ordered logsource dictionary with required keys first."""
    result = {'product': logsource['product'], 'service': logsource['service']}
    if 'category' in logsource:
        result['category'] = logsource['category']
    return result


def _format_yaml_output(rule_dict: Dict) -> str:
    """Format rule dictionary as clean YAML with proper indentation."""
    yaml_output = yaml.safe_dump(
        rule_dict,
        default_flow_style=False,
        sort_keys=False,
        indent=2,
        width=float('inf')
    )
    
    lines = [line for line in yaml_output.split('\n') if line.strip()]
    return '\n'.join(lines)


if __name__ == "__main__":
    example = build_sigma_rule(
        name="SuspiciousProcessCreation",
        description="Detects unexpected processes spawning",
        logsource={"product": "windows", "service": "sysmon"},
        detection={
            "cmd_exec": ["*.exe", "powershell.exe"],
            "unusual_parent": ["cmd.exe", "wscript.exe"]
        },
        condition="cmd_exec and unusual_parent",
        fields=["HostName", "User"],
        tags=["attack.execution", "attack.t1059"],
        level="medium"
    )
    print(example)
    
    print("\n" + "="*50)
    
    advanced_example = build_sigma_rule(
        name="SuspiciousNetworkConnection",
        description="Detects connections to known malicious domains",
        logsource={"product": "windows", "service": "sysmon", "category": "network_connection"},
        detection={
            "malicious_domains": ["evil.com", "malware.net", "*.suspicious.org"],
            "high_risk_ports": ["4444", "5555", "8080"],
            "selection": ["Image|endswith: .exe", "Initiated: true"]
        },
        condition="malicious_domains and (high_risk_ports or selection)",
        fields=["DestinationIp", "DestinationPort", "ProcessId", "User"],
        tags=["attack.command_and_control", "attack.t1071"],
        level="high"
    )
    print(advanced_example)
    
    print("\n" + "="*50)
    print("Basic rule without optional fields:")
    
    basic_example = build_sigma_rule(
        name="BasicRule",
        description="Simple detection rule",
        logsource={"product": "linux", "service": "auditd"},
        detection={"selection": ["suspicious_command"]},
        condition="selection",
        fields=[]  # Will default to ["*"]
    )
    print(basic_example)
