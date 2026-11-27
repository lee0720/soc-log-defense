"""架空の監視データの読み込みと集計。"""

import json
from pathlib import Path

SNAPSHOT_PATH = Path(__file__).with_name("data") / "monitoring.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def load_snapshot():
    with SNAPSHOT_PATH.open(encoding="utf-8") as source:
        return json.load(source)


def summarize(snapshot):
    alerts = snapshot["alerts"]
    return {
        "events": sum(bucket["events"] for bucket in snapshot["buckets"]),
        "open": sum(alert["status"] == "open" for alert in alerts),
        "critical": sum(
            alert["severity"] == "CRITICAL" and alert["status"] == "confirmed"
            for alert in alerts
        ),
        "resolved": sum(alert["status"] == "resolved" for alert in alerts),
        "false_positive": sum(alert["status"] == "false_positive" for alert in alerts),
    }


def severity_counts(alerts):
    return {
        severity: sum(alert["severity"] == severity for alert in alerts)
        for severity in SEVERITIES
    }
