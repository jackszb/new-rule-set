import os
import requests
import subprocess
import json
import tempfile
import time
import uuid

OUTPUT_DIR = "rule-set"
os.makedirs(OUTPUT_DIR, exist_ok=True)

CONFIG_FILE = "rules.json"
with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)

routing_domain = config.get("routing_domain", {})


def download_srs(url):
    """下载 .srs 文件内容到临时文件并返回路径"""
    response = requests.get(url)
    response.raise_for_status()
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(response.content)
    tmp.close()
    return tmp.name


def decompile_srs_to_dict(srs_path):
    """反编译 .srs 到 Python dict"""
    tmp_json = tempfile.NamedTemporaryFile(delete=False)
    tmp_json.close()
    result = subprocess.run(
        ["sing-box", "rule-set", "decompile", srs_path, "-o", tmp_json.name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Decompile failed: {result.stderr}")
    with open(tmp_json.name, "r", encoding="utf-8") as f:
        data = json.load(f)
    os.unlink(tmp_json.name)
    return data.get("rules", [])


def merge_rules(rules_list):
    merged = {}
    for rules in rules_list:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for key, value in rule.items():
                if not value:
                    continue
                if key not in merged:
                    merged[key] = set()
                if isinstance(value, list):
                    merged[key].update(value)
                else:
                    merged[key].add(value)
    return {k: sorted(list(v)) for k, v in merged.items()}


def compile_json_to_srs(json_path, srs_path):
    result = subprocess.run(
        ["sing-box", "rule-set", "compile", json_path, "-o", srs_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Compile failed: {result.stderr}")


def process_category(url_list, output_prefix):
    all_rules = []
    for url in url_list:
        srs_path = download_srs(url)
        rules = decompile_srs_to_dict(srs_path)
        all_rules.append(rules)
        os.unlink(srs_path)

    merged_rules = merge_rules(all_rules)
    final_json = {"version": 3, "rules": [merged_rules]}

    # 使用 UUID 保证文件名唯一
    unique_id = str(uuid.uuid4())  # 使用唯一的 UUID
    json_filename = f"merged-{output_prefix}-{unique_id}.json"
    srs_filename = f"merged-{output_prefix}-{unique_id}.srs"

    json_path = os.path.join(OUTPUT_DIR, json_filename)
    srs_path = os.path.join(OUTPUT_DIR, srs_filename)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_json, f, ensure_ascii=False, indent=2)

    compile_json_to_srs(json_path, srs_path)
    print(f"Generated {json_path} and {srs_path}")


if __name__ == "__main__":
    # 不再删除任何文件，保证其他脚本生成的文件不会被误删
    # 只清理临时文件或不必要的生成文件
    process_category(routing_domain.get("direct", []), "domain-direct")
    process_category(routing_domain.get("proxy", []), "domain-proxy")
