"""デモシナリオの読み込みとサーバー側の採点。"""

import json
from pathlib import Path

MISSION_PATH = Path(__file__).with_name("data") / "demo_mission.json"


def load_mission():
    return json.loads(MISSION_PATH.read_text(encoding="utf-8"))


def grade_mission(mission, evidence, classification, severity, responses, note):
    expected_evidence = set(mission["evidence"])
    expected_responses = set(mission["responses"])
    selected_evidence = set(evidence)
    selected_responses = set(responses)
    # 無関係な選択を減点し、全選択による満点を防ぐ。
    evidence_points = 10 * max(
        0, len(selected_evidence & expected_evidence) - len(selected_evidence - expected_evidence)
    )
    response_points = sum(
        points for action, points in zip(mission["responses"], (15, 10))
        if action in selected_responses
    )
    response_points = max(0, response_points - 10 * len(selected_responses - expected_responses))
    return {
        "証拠": (evidence_points, 30),
        "判定": (20 if classification == mission["classification"] else 0, 20),
        "重大度": (15 if severity == mission["severity"] else 0, 15),
        "対応": (response_points, 25),
        "調査メモ": (10 if note.strip() else 0, 10),
    }
