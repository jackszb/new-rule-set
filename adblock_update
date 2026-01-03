import os
import requests
import subprocess
import json
from urllib.parse import urlparse

# 输出文件
ADBLOCK_JSON = "rule-set/merged-domain-reject.json"
ADBLOCK_SRS = "rule-set/merged-domain-reject.srs"

DOWNLOAD_LINKS = [
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject_extra.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/domainset/reject_phishing.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/reject-no-drop.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/ip/reject.json",
    "https://raw.githubusercontent.com/jackszb/sukka-surge/main/non_ip/reject.json",
]

def download_file(url, save_path):
    print(f"Downloading {url}")
    r = requests.get(url)
    r.raise_for_status()
    with open(save_path, "wb") as f:
        f.write(r.content)

def extract_domain_from_keyword(s: str) -> str | None:
    if not isinstance(s, str):
        return None

    # 去掉前导 -
    if s.startswith("-"):
        s = s[1:]

    # 必须看起来像域名
    if "." not in s:
        return None

    # 排除明显 keyword / 噪声
    forbidden = ["*", "/", " ", "_", ".."]
    if any(ch in s for ch in forbidden):
        return None

    if s.startswith(".") or s.endswith("."):
        return None

    return s

def process_domain_keyword(merged_rules: dict):
    keywords = merged_rules.get("domain_keyword")
    if not keywords:
        return

    domain_suffix = merged_rules.setdefault("domain_suffix", set())
    migrated = 0

    for item in keywords:
        domain = extract_domain_from_keyword(item)
        if domain:
            domain_suffix.add(domain)
            migrated += 1

    # keyword 不进入最终规则
    del merged_rules["domain_keyword"]

    print(f"domain_keyword processed: migrated {migrated}, ignored {len(keywords) - migrated}")

def merge_json_files(download_links, output_file):
    merged_rules = {}
    total_before = 0

    for url in download_links:
        name = os.path.basename(urlparse(url).path)
        path = os.path.join(os.getcwd(), name)
        download_file(url, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            rules = data if isinstance(data, list) else data.get("rules", [])

            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                for key, value in rule.items():
                    if not value:
                        continue

                    merged_rules.setdefault(key, set())

                    if isinstance(value, list):
                        merged_rules[key].update(value)
                        total_before += len(value)
                    else:
                        merged_rules[key].add(value)
                        total_before += 1

    # 关键步骤：处理 domain_keyword
    process_domain_keyword(merged_rules)

    merged = {k: sorted(v) for k, v in merged_rules.items()}

    final_json = {
        "version": 3,
        "rules": [merged]
    }

    # 确保输出文件夹存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(final_json, f, ensure_ascii=False, indent=2)

    total_after = sum(len(v) for v in merged.values())
    print(f"Merged {len(download_links)} files")
    print(f"Entries before dedup: {total_before}")
    print(f"Entries after dedup: {total_after}")
    print(f"Saved {output_file}")

    return output_file

def compile_to_srs(json_path, srs_path):
    print(f"Compiling {json_path} -> {srs_path}")
    r = subprocess.run(
        ["sing-box", "rule-set", "compile", json_path, "-o", srs_path],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr)

if __name__ == "__main__":
    for f in [ADBLOCK_JSON, ADBLOCK_SRS]:
        if os.path.exists(f):
            os.remove(f)

    json_path = merge_json_files(DOWNLOAD_LINKS, ADBLOCK_JSON)
    compile_to_srs(json_path, ADBLOCK_SRS)
