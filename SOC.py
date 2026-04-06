#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Analyst Shift — セキュリティオペレーションセンター体験シミュレータ
標準ライブラリのみ。ポートフォリオ用に単一ファイルで完結。
"""

from __future__ import annotations

import random
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Set
import csv
import os

# --- 端末色（未対応端末では無視） ---
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    C = "\033[96m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(sev: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    m = {
        "CRITICAL": C.R + C.BOLD,
        "HIGH": C.R,
        "MEDIUM": C.Y,
        "LOW": C.C,
        "INFO": C.DIM,
    }
    return f"{m.get(sev, '')}{text}{C.RESET}"


class EventKind(str, Enum):
    LOGIN_OK = "login_ok"
    LOGIN_FAIL = "login_fail"
    PORT_SCAN = "port_scan"
    SQLI = "sqli"
    C2_BEACON = "c2_beacon"
    INSIDER_BULK = "insider_bulk"
    FALSE_ALARM_SCAN = "false_alarm_scan"  # 脆弱性スキャナ（社内）
    MAINTENANCE = "maintenance"


@dataclass
class LogEvent:
    log_id: int
    ts: float
    severity: str
    src_ip: str
    user: str
    message: str
    mitre: str
    kind: EventKind
    malicious: bool
    false_positive_trap: bool
    contained: bool = False


@dataclass
class GameConfig:
    shift_seconds: float = 180.0
    tick_interval: tuple[float, float] = (0.6, 1.4)
    threat_per_tick_malicious: float = 2.5
    threat_decay_per_sec: float = 0.15
    block_mitigation: float = 8.0
    win_threat_max: float = 85.0
    lose_threat: float = 100.0

# --- CSV出力設定 ---
log_file_path = os.path.join(os.path.dirname(__file__), "soc_access.csv")

def init_csv():
    if not os.path.exists(log_file_path):
        with open(log_file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Analyzerが読み込みやすいカラム名
            writer.writerow(["timestamp", "log_id", "severity", "mitre", "src_ip", "message"])

init_csv()

@dataclass
class GameState:
    cfg: GameConfig = field(default_factory=GameConfig)
    threat: float = 12.0
    score: int = 0
    reputation: int = 100
    logs: Deque[LogEvent] = field(default_factory=lambda: deque(maxlen=400))
    log_by_id: Dict[int, LogEvent] = field(default_factory=dict)
    blocked_ips: Set[str] = field(default_factory=set)
    dismissed_ids: Set[int] = field(default_factory=set)
    escalated_ids: Set[int] = field(default_factory=set)
    next_id: int = 1
    running: bool = True
    lock: threading.Lock = field(default_factory=threading.Lock)
    start_time: float = field(default_factory=time.time)
    shift_ended: bool = False
    fail_counter: Dict[str, int] = field(default_factory=dict)


USERS = ["admin", "svc_backup", "jdoe", "guest", "root", "app_runtime"]
INTERNAL_NET = "10.0.0."
DMZ_NET = "192.168.50."
EXT_NET = "203.0.113."


def _pick_ip(rng: random.Random, kind: EventKind) -> str:
    if kind in (EventKind.LOGIN_OK, EventKind.LOGIN_FAIL, EventKind.INSIDER_BULK, EventKind.MAINTENANCE):
        return f"{INTERNAL_NET}{rng.randint(2, 220)}"
    if kind in (EventKind.FALSE_ALARM_SCAN,):
        return f"{INTERNAL_NET}{rng.randint(2, 220)}"
    if kind in (EventKind.PORT_SCAN, EventKind.SQLI, EventKind.C2_BEACON):
        return f"{EXT_NET}{rng.randint(1, 254)}"
    return f"{DMZ_NET}{rng.randint(2, 200)}"


def _build_message(rng: random.Random, kind: EventKind, ip: str, user: str) -> tuple[str, str, str]:
    if kind == EventKind.LOGIN_OK:
        return "INFO", f"AUTH success user={user} src={ip} mfa=ok", "T1078"
    if kind == EventKind.LOGIN_FAIL:
        n = rng.randint(1, 3)
        return "LOW", f"AUTH failed user={user} src={ip} attempt={n}/5", "T1110"
    if kind == EventKind.PORT_SCAN:
        p = rng.sample(range(1, 1024), k=3)
        return "MEDIUM", f"IDS multiple SYN to ports {p} from {ip}", "T1046"
    if kind == EventKind.SQLI:
        return "HIGH", f"WAF block SQLi pattern in /api/search from {ip} q=' OR 1=1--", "T1190"
    if kind == EventKind.C2_BEACON:
        return "CRITICAL", f"EDR periodic beacon {ip}:443 every 60s jitter low (possible C2)", "T1071"
    if kind == EventKind.INSIDER_BULK:
        return "MEDIUM", f"DLP alert user={user} exported {rng.randint(800,5000)} files to USB", "T1567"
    if kind == EventKind.FALSE_ALARM_SCAN:
        return "MEDIUM", f"IDS scan-like traffic from {ip} tag=scheduled_vuln_scan owner=secops", "T1046"
    return "INFO", f"MAINT window: patch agent heartbeat from {ip}", "—"


def weighted_kind(rng: random.Random) -> EventKind:
    pool = (
        [(EventKind.LOGIN_OK, 22)]
        + [(EventKind.LOGIN_FAIL, 14)]
        + [(EventKind.PORT_SCAN, 10)]
        + [(EventKind.SQLI, 6)]
        + [(EventKind.C2_BEACON, 5)]
        + [(EventKind.INSIDER_BULK, 5)]
        + [(EventKind.FALSE_ALARM_SCAN, 8)]
        + [(EventKind.MAINTENANCE, 12)]
    )
    choices, weights = zip(*pool)
    return rng.choices(choices, weights=weights, k=1)[0]


def classify_event(kind: EventKind) -> tuple[bool, bool]:
    """(malicious_for_scoring, false_positive_trap)"""
    if kind in (EventKind.PORT_SCAN, EventKind.SQLI, EventKind.C2_BEACON):
        return True, False
    if kind == EventKind.INSIDER_BULK:
        return True, False
    if kind == EventKind.FALSE_ALARM_SCAN:
        return False, True
    return False, False


def spawn_event(state: GameState, rng: random.Random) -> LogEvent:
    kind = weighted_kind(rng)
    ip = _pick_ip(rng, kind)
    user = rng.choice(USERS)
    sev, msg, mitre = _build_message(rng, kind, ip, user)
    malicious, trap = classify_event(kind)

    with state.lock:
        lid = state.next_id
        state.next_id += 1

    ev = LogEvent(
        log_id=lid,
        ts=time.time(),
        severity=sev,
        src_ip=ip,
        user=user,
        message=msg,
        mitre=mitre,
        kind=kind,
        malicious=malicious,
        false_positive_trap=trap,
    )
    with state.lock:
        state.logs.append(ev)
        state.log_by_id[lid] = ev
    
        if malicious and not trap:
            state.threat = min(state.cfg.lose_threat, state.threat + state.cfg.threat_per_tick_malicious)

    #    攻撃検知処理 🔥 ここに移動！！
        if ev.kind == EventKind.LOGIN_FAIL:
            state.fail_counter[ev.src_ip] = state.fail_counter.get(ev.src_ip, 0) + 1

            if state.fail_counter[ev.src_ip] >= 3:
                print("⚠️ ブルートフォース攻撃検知:", ev.src_ip)

        if ev.kind == EventKind.LOGIN_OK:
            state.fail_counter[ev.src_ip] = 0

    return ev


def format_event_line(ev: LogEvent) -> str:
    return f"[{ev.log_id:04d}] {ev.severity:8} {ev.mitre:6} {ev.src_ip:16} | {ev.message}"


def append_event_csv(ev: LogEvent) -> None:
    with open(log_file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                f"{ev.log_id:04d}",
                ev.severity,
                ev.mitre,
                ev.src_ip,
                ev.message,
            ]
        )


def log_printer(ev: LogEvent) -> None:
    line = format_event_line(ev)
    print(colorize(ev.severity, line))
    append_event_csv(ev)


def producer_loop(state: GameState, rng: random.Random) -> None:
    while state.running and not state.shift_ended:
        with state.lock:
            if time.time() - state.start_time >= state.cfg.shift_seconds:
                state.shift_ended = True
                print(
                    colorize(
                        "HIGH",
                        "\n── シフト時間終了 ── 任意のコマンドを入力するとデブリーフします ──\n",
                    )
                )
                break
        ev = spawn_event(state, rng)
        log_printer(ev)
        lo, hi = state.cfg.tick_interval
        time.sleep(rng.uniform(lo, hi))


def threat_decay_loop(state: GameState) -> None:
    while state.running:
        time.sleep(0.5)
        with state.lock:
            if not state.shift_ended:
                state.threat = max(0.0, state.threat - state.cfg.threat_decay_per_sec * 0.5)


def cmd_help() -> None:
    print(
        f"""
{C.BOLD}コマンド{C.RESET}
  {C.G}help{C.RESET}              この一覧
  {C.G}status{C.RESET}            脅威スコア・評判・経過時間
  {C.G}tail [n]{C.RESET}          直近 n 件（既定 12）
  {C.G}inspect <id>{C.RESET}     ログ詳細
  {C.G}block <ip>{C.RESET}        IP をファイアウォール遮断（真の脅威に効く）
  {C.G}dismiss <id>{C.RESET}     フェーズ陽性としてクローズ（罰あり注意）
  {C.G}escalate <id>{C.RESET}    Tier2 へエスカレーション（HIGH/CRITICAL で加点）
  {C.G}whois <ip>{C.RESET}       ダミー WHOIS（雰囲気用）
  {C.G}investigate <ip>{C.RESET}   指定IPのログを調査
  {C.G}quit{C.RESET}             終了
"""
    )

def cmd_investigate(state, ip):
    found = False
    for ev in state.logs:
        if ip in ev.src_ip:
            print(ev.src_ip, "|", ev.message)
            found = True

    if not found:
        print("ログが見つかりません")

def cmd_status(state: GameState) -> None:
    with state.lock:
        elapsed = time.time() - state.start_time
        left = max(0.0, state.cfg.shift_seconds - elapsed)
        print(
            f"脅威メーター: {state.threat:.1f} / {state.cfg.lose_threat}  "
            f"| 評判: {state.reputation}  | スコア: {state.score}\n"
            f"シフト残り: {left:.0f}s  | 遮断IP数: {len(state.blocked_ips)}"
        )


def cmd_tail(state: GameState, n: int) -> None:
    with state.lock:
        items: List[LogEvent] = list(state.logs)[-n:]
    for ev in items:
        log_printer(ev)


def cmd_inspect(state: GameState, lid: int) -> None:
    with state.lock:
        ev = state.log_by_id.get(lid)
    if not ev:
        print("ログIDが見つかりません。")
        return
    age = time.time() - ev.ts
    print(
        f"ID {ev.log_id} | {ev.severity} | {ev.mitre}\n"
        f"src={ev.src_ip} user={ev.user}\n"
        f"{ev.message}\n"
        f"経過 {age:.1f}s | 封じ込め済み={ev.contained}"
    )


def cmd_block(state: GameState, ip: str) -> None:
    with state.lock:
        if ip in state.blocked_ips:
            print("既に遮断済みです。")
            return
        state.blocked_ips.add(ip)
        mitigated = False
        wrong_block = False
        for ev in state.log_by_id.values():
            if ev.src_ip != ip:
                continue
            if ev.false_positive_trap:
                wrong_block = True
            if ev.malicious and not ev.false_positive_trap and not ev.contained:
                ev.contained = True
                mitigated = True
        if mitigated:
            state.threat = max(0.0, state.threat - state.cfg.block_mitigation)
            state.score += 25
            print(colorize("INFO", f"遮断成功: {ip} — 脅威が下がりました (+25)"))
        if wrong_block:
            state.reputation -= 15
            state.score -= 20
            state.threat = min(state.cfg.lose_threat, state.threat + 5)
            print(colorize("HIGH", "誤遮断の可能性: スキャンは承認済みパターンでした (-評判)"))
        if not mitigated and not wrong_block:
            state.reputation -= 5
            state.score -= 5
            print(colorize("LOW", "このIPからは重大イベントが検出されていません（過剰反応）。"))


def cmd_dismiss(state: GameState, lid: int) -> None:
    with state.lock:
        ev = state.log_by_id.get(lid)
        if not ev:
            print("ログIDが見つかりません。")
            return
        if lid in state.dismissed_ids:
            print("既に dismiss 済みです。")
            return
        state.dismissed_ids.add(lid)
        if ev.malicious and not ev.false_positive_trap:
            state.reputation -= 25
            state.score -= 35
            state.threat = min(state.cfg.lose_threat, state.threat + 12)
            print(colorize("CRITICAL", "真のインシデントを見逃しました。脅威上昇。"))
        elif ev.false_positive_trap:
            state.score += 15
            state.reputation += 5
            print(colorize("INFO", "適切なトリアージ。フェーズ陽性をクローズ (+15)"))
        else:
            state.score += 3
            print(colorize("INFO", "ノイズを整理しました (+3)"))


def cmd_escalate(state: GameState, lid: int) -> None:
    with state.lock:
        ev = state.log_by_id.get(lid)
        if not ev:
            print("ログIDが見つかりません。")
            return
        if lid in state.escalated_ids:
            print("既にエスカレーション済みです。")
            return
        state.escalated_ids.add(lid)
        if ev.severity in ("HIGH", "CRITICAL") and (ev.malicious or ev.false_positive_trap):
            pts = 12 if ev.malicious else 8
            state.score += pts
            print(colorize("INFO", f"Tier2 が引き継ぎます (+{pts})"))
        else:
            state.reputation -= 3
            print(colorize("LOW", "低優先度のエスカレーションは現場の評判を下げます。"))


def cmd_whois(ip: str) -> None:
    fake = random.choice(["AS64496 Example Transit", "AS203020 Demo Hosting", "社内 RFC5737 テスト帯域"])
    print(f"{ip} → {fake}（シミュレーション）")


def briefing() -> None:
    print(
        f"""
{C.BOLD}{C.C}╔══════════════════════════════════════════════════════════╗
║  SOC Analyst Shift  —  シフト体験シミュレータ              ║
╚══════════════════════════════════════════════════════════╝{C.RESET}

あなたは Tier1 アナリスト。ログが流れ続けます。
{C.Y}脅威メーターが {C.R}100{C.Y} に達ると組織は限界 — ゲームオーバー{C.RESET}。
シフト時間内にメーターを {C.G}85{C.RESET} 未満に抑えきればクリア傾向（評判・スコアも参照）。

ヒント: メッセージに {C.DIM}scheduled_vuln_scan{C.RESET} や {C.DIM}MAINT{C.RESET} が含まれるものは
安易に遮断しない。HIGH/CRITICAL は {C.G}inspect{C.RESET} してから {C.G}escalate{C.RESET} も検討。
"""
    )


def finalize_shift(state: GameState) -> tuple[bool, str]:
    """シフト終了時点の勝敗判定（CLI / Streamlit 共通）。"""
    with state.lock:
        if state.threat >= state.cfg.lose_threat:
            return False, "シフト終了時点で脅威が飽和していた"
        if state.threat < state.cfg.win_threat_max and state.reputation >= 40:
            return True, "シフト完了（組織は持ちこたえた）"
        victory = state.reputation >= 55 and state.threat < state.cfg.lose_threat
        reason = (
            "シフト完了（評判・脅威はギリギリ）"
            if victory
            else "シフト終了も指標が基準未達"
        )
        return victory, reason


def end_screen(state: GameState, victory: bool, reason: str) -> None:
    with state.lock:
        sc, rep, th = state.score, state.reputation, state.threat
    print()
    if victory:
        print(colorize("INFO", f"★ シフト終了 — {reason}"))
        print(f"最終スコア: {sc}  評判: {rep}  脅威: {th:.1f}")
        if sc >= 120 and rep >= 85:
            print(colorize("HIGH", "採用担当向け: 「インシデント判断力: S」"))
        elif sc >= 60:
            print(colorize("MEDIUM", "安定的なトリアージ。あと一歩で傑作ポートフォリオ。"))
    else:
        print(colorize("CRITICAL", f"ゲームオーバー — {reason}"))
        print(f"スコア: {sc}  評判: {rep}")


def parse_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except ValueError:
        return None


def main() -> None:
    rng = random.Random()
    state = GameState()
    briefing()
    cmd_help()

    t_prod = threading.Thread(target=producer_loop, args=(state, rng), daemon=True)
    t_decay = threading.Thread(target=threat_decay_loop, args=(state,), daemon=True)
    t_prod.start()
    t_decay.start()

    victory = False
    end_reason = ""

    def evaluate_shift_end() -> bool:
        nonlocal victory, end_reason
        with state.lock:
            if not state.shift_ended:
                return False
        victory, end_reason = finalize_shift(state)
        return True

    try:
        while state.running:
            with state.lock:
                if state.threat >= state.cfg.lose_threat:
                    end_screen(state, False, "脅威メーターが飽和しました")
                    state.running = False
                    return

            try:
                line = input(f"{C.BOLD}> {C.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n中断しました。")
                state.running = False
                return

            if not line:
                if evaluate_shift_end():
                    state.running = False
                    break
                continue
            parts = line.split()
            cmd = parts[0].lower()

            if cmd in ("quit", "exit", "q"):
                state.running = False
                end_reason = "ユーザー終了"
                break
            elif cmd == "help":
                cmd_help()
            elif cmd == "status":
                cmd_status(state)
            elif cmd == "tail":
                n = parse_int(parts[1]) if len(parts) > 1 else 12
                cmd_tail(state, max(1, min(n or 12, 80)))
            elif cmd == "inspect":
                if len(parts) < 2:
                    print("使い方: inspect <id>")
                    continue
                lid = parse_int(parts[1])
                if lid is None:
                    print("ID は整数で指定してください。")
                    continue
                cmd_inspect(state, lid)
            elif cmd == "block":
                if len(parts) < 2:
                    print("使い方: block <ip>")
                    continue
                cmd_block(state, parts[1])
            elif cmd == "dismiss":
                if len(parts) < 2:
                    print("使い方: dismiss <id>")
                    continue
                lid = parse_int(parts[1])
                if lid is None:
                    print("ID は整数で指定してください。")
                    continue
                cmd_dismiss(state, lid)
            elif cmd == "escalate":
                if len(parts) < 2:
                    print("使い方: escalate <id>")
                    continue
                lid = parse_int(parts[1])
                if lid is None:
                    print("ID は整数で指定してください。")
                    continue
                cmd_escalate(state, lid)
            elif cmd == "whois":
                if len(parts) < 2:
                    print("使い方: whois <ip>")
                    continue
                cmd_whois(parts[1])
            elif cmd == "investigate":
                if len(parts) < 2:
                    print("使い方: investigate <ip>")
                    continue
                cmd_investigate(state, parts[1])
            else:
                print("不明なコマンド。help と入力してください。")

            with state.lock:
                if state.threat >= state.cfg.lose_threat:
                    end_screen(state, False, "脅威メーターが飽和しました")
                    state.running = False
                    return

            if evaluate_shift_end():
                state.running = False
                break

    finally:
        state.running = False
        t_prod.join(timeout=2.0)

    if end_reason == "ユーザー終了":
        print(f"\n{end_reason}")
        return

    end_screen(state, victory, end_reason)


if __name__ == "__main__":
    main()
