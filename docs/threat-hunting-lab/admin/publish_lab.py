"""Admin-only compiler: raw logs + private lab spec -> safe static lab assets."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

DOMAIN_RE = re.compile(r"(?i)\b[\w.-]+\.(?:com|net|org|io|co)\b")
PUBLIC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def scrub(value: object) -> object:
    if not isinstance(value, str):
        return value
    value = DOMAIN_RE.sub("range-enterprise.local", value)
    return PUBLIC_IP_RE.sub(lambda match: f"198.51.100.{(sum(map(int, match.group().split('.'))) % 253) + 1}", value)


def read_source(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".json", ".jsonl", ".ndjson"}:
        try:
            return pd.read_json(path)
        except ValueError:
            return pd.read_json(path, lines=True)
    if suffix == ".parquet":
        return pd.read_parquet(path)
    raise ValueError(f"Unsupported source type: {path}")


def compile_source(source: dict, destination: Path, shift_time: bool, scrub_pii: bool) -> dict:
    path = Path(source["path"])
    frame = read_source(path)
    if scrub_pii:
        frame = frame.map(scrub)
    timestamp = source.get("timestamp_column")
    if shift_time and timestamp and timestamp in frame.columns:
        times = pd.to_datetime(frame[timestamp], utc=True, errors="coerce")
        valid = times.dropna()
        if not valid.empty:
            frame[timestamp] = times + (pd.Timestamp(datetime.now(timezone.utc)) - valid.min())
    table = re.sub(r"\W+", "_", source.get("table") or path.stem).strip("_").lower()
    output = destination / f"{table}.parquet"
    frame.to_parquet(output, engine="pyarrow", compression="snappy", index=False)
    return {"name": table, "table": table, "url": f"data/labs/{destination.name}/{output.name}"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish an administrator-defined browser lab")
    parser.add_argument("spec", type=Path, help="Private JSON spec containing raw paths and plain-text answers")
    parser.add_argument("--site-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--no-scrub", action="store_true", help="Disable PII scrubbing")
    parser.add_argument("--no-time-shift", action="store_true", help="Keep original timestamps")
    args = parser.parse_args()

    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    lab_id = re.sub(r"[^a-zA-Z0-9_-]", "-", spec["id"])
    destination = args.site_root / "data" / "labs" / lab_id
    destination.mkdir(parents=True, exist_ok=True)
    published_sources = [compile_source(item, destination, not args.no_time_shift, not args.no_scrub) for item in spec.pop("sources")]

    for step in spec.get("steps", []):
        answer = step.pop("answer")
        step["solution_hash"] = hashlib.sha256(answer.strip().lower().encode()).hexdigest()
    spec["id"] = lab_id
    spec["published"] = True
    spec["parquet_sources"] = published_sources

    manifest_path = args.site_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"schema_version": 1, "labs": []}
    manifest["labs"] = [lab for lab in manifest.get("labs", []) if lab.get("id") != lab_id] + [spec]
    difficulty_order = {"Novice": 0, "Intermediate": 1, "Expert": 2}
    manifest["labs"].sort(key=lambda lab: (difficulty_order.get(lab.get("difficulty_tier"), 99), lab.get("title", "")))
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Published {lab_id}: {len(published_sources)} evidence table(s), {len(spec.get('steps', []))} challenge(s)")


if __name__ == "__main__":
    main()
