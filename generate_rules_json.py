#!/usr/bin/env python3
import json
import gzip
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        raise ImportError("Install tomli: pip install tomli")

BASE_DIR = Path(__file__).parent

def load_toml(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    out = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == '"' and raw[i:i+3] == '"""':
            out.append('"""')
            i += 3
            while i < n:
                if raw[i:i+3] == '"""':
                    out.append('"""')
                    i += 3
                    break
                out.append(raw[i])
                i += 1
        elif ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                c = raw[i]
                if c == '\\':          # escape sequence – copy both chars
                    out.append(c)
                    i += 1
                    if i < n:
                        out.append(raw[i])
                        i += 1
                elif c == '"':         # end of string
                    out.append(c)
                    i += 1
                    break
                elif c == '\n':        # illegal bare newline → collapse to space
                    out.append(' ')
                    i += 1
                else:
                    out.append(c)
                    i += 1
        else:
            out.append(ch)
            i += 1

    return tomllib.loads("".join(out))


SCOPE_TO_TYPE = {
    "any": "Any",
    "url": "Url",
    "domain": "Domain",
    "email": "Email",
    "ip": "Ip",
    "header": "Header",
    "body": "Body",
}

def scope_to_type(scope: str) -> str:
    return SCOPE_TO_TYPE.get(scope.lower(), scope.capitalize())


def val_to_str(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def parse_expression(value) -> dict:
    if isinstance(value, list):
        matches = []
        else_value = ""
        for item in value:
            if "if" in item:
                matches.append({
                    "if": val_to_str(item["if"]),
                    "then": val_to_str(item.get("then", "")),
                })
            elif "else" in item:
                else_value = val_to_str(item["else"])
        return {"else": else_value, "match": {str(i): m for i, m in enumerate(matches)}}
    else:
        return {"else": val_to_str(value), "match": {}}


def parse_file_extensions() -> list:
    path = BASE_DIR / "lists" / "file_extensions.txt"
    result = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            ext, rest = line.split("=", 1)
            ext = ext.strip()
            parts = [p.strip() for p in rest.split(",")]

            is_bad = False
            is_nz = False
            is_archive = False
            content_types = []

            for part in parts:
                if part == "BAD":
                    is_bad = True
                elif part == "NZ":
                    is_nz = True
                elif part == "AR":
                    is_archive = True
                elif "/" in part:
                    content_types.append(part)

            result.append({
                "extension": ext,
                "contentTypes": {ct: True for ct in content_types},
                "isArchive": is_archive,
                "isBad": is_bad,
                "isNz": is_nz,
            })
    return result

def parse_scores() -> list:
    path = BASE_DIR / "lists" / "scores.txt"
    result = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            tag_name, value = line.split("=", 1)
            tag_name = tag_name.strip()
            value = value.strip()

            value_lower = value.lower()
            if value_lower == "reject":
                result.append({"@type": "Reject", "tag": tag_name})
            elif value_lower == "discard":
                result.append({"@type": "Discard", "tag": tag_name})
            else:
                try:
                    score = float(value)
                    result.append({"@type": "Score", "score": score, "tag": tag_name})
                except ValueError:
                    pass  # skip unrecognised entries
    return result

def parse_memory_lookup(filename: str, namespace: str) -> list:
    path = BASE_DIR / "lists" / filename
    result = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            result.append({
                "key": line,
                "namespace": namespace,
                "isGlobPattern": "*" in line,
            })
    return result

def parse_http_lists() -> list:
    path = BASE_DIR / "lists" / "http_lists.toml"
    data = load_toml(path)

    result = []
    for key, entry in data.get("http-list", {}).items():
        namespace = key.lower()

        fmt = entry.get("format", "list").lower()
        if fmt == "list":
            format_obj = {"@type": "List"}
        else:  # csv
            index = entry.get("index", {})
            index_value = index.get("value")
            format_obj = {
                "@type": "Csv",
                "indexKey": index.get("key", 0),
                "indexValue": index_value,
                "separator": entry.get("separator", ","),
                "skipFirst": entry.get("skip-first", False),
            }

        limits = entry.get("limits", {})

        result.append({
            "namespace": namespace,
            "url": entry.get("url", ""),
            "format": format_obj,
            "enable": entry.get("enable", True),
            "isGzipped": entry.get("gzipped", False),
            "maxSize": limits.get("size", 0),
            "maxEntries": limits.get("entries", 0),
            "maxEntrySize": limits.get("entry-size", 0),
            "refresh": entry.get("refresh", "0s"),
            "retry": entry.get("retry", "0s"),
            "timeout": entry.get("timeout", "0s"),
        })
    return result


def parse_dnsbl() -> list:
    path = BASE_DIR / "rules" / "dnsbl.toml"
    data = load_toml(path)

    result = []
    for key, entry in data.get("dnsbl", {}).items():
        scope = entry.get("scope", "any")
        result.append({
            "@type": scope_to_type(scope),
            "name": key,
            "enable": entry.get("enable", True),
            "tag": parse_expression(entry.get("tag", "")),
            "zone": parse_expression(entry.get("zone", "")),
        })
    return result


def parse_rules(filename: str) -> list:
    path = BASE_DIR / "rules" / filename
    data = load_toml(path)

    result = []
    for key, entry in data.get("rule", {}).items():
        scope = entry.get("scope", "any")
        result.append({
            "@type": scope_to_type(scope),
            "condition": parse_expression(entry.get("condition", "")),
            "name": key,
            "enable": entry.get("enable", True),
            "priority": entry.get("priority", 0),
        })
    return result


def main():
    output = {
        "SpamRule": [],
        "HttpLookup": [],
        "SpamDnsblServer": [],
        "SpamTag": [],
        "SpamFileExtension": [],
        "MemoryLookupKey": [],
    }

    output["SpamFileExtension"] = parse_file_extensions()
    output["SpamTag"] = parse_scores()

    output["MemoryLookupKey"] += parse_memory_lookup("surbl-hashbl.txt", "surbl-hashbl")
    output["MemoryLookupKey"] += parse_memory_lookup("url_redirectors.txt", "url-redirectors")
    output["MemoryLookupKey"] += parse_memory_lookup("trusted_domains.txt", "trusted-domains")

    output["HttpLookup"] = parse_http_lists()

    output["SpamDnsblServer"] = parse_dnsbl()

    rule_files = [
        "composites.toml",
        "dnsbl.toml",
        "from.toml",
        "header.toml",
        "recipient.toml",
        "subject.toml",
        "url.toml",
    ]
    for rf in rule_files:
        output["SpamRule"] += parse_rules(rf)

    json_pretty = json.dumps(output, indent=2)
    json_mini = json.dumps(output, separators=(",", ":"))

    json_path = BASE_DIR / "spam-filter-rules.json"
    json_path.write_text(json_pretty, encoding="utf-8")
    print(f"Written {json_path}  ({json_path.stat().st_size:,} bytes)")

    gz_path = BASE_DIR / "spam-filter-rules.json.gz"
    with gzip.open(gz_path, "wb") as fgz:
        fgz.write(json_mini.encode("utf-8"))
    print(f"Written {gz_path}  ({gz_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
