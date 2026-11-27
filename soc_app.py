#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SOC Analyst Shift — Streamlit UI（SOC.py のロジックを再利用）"""

from __future__ import annotations

import contextlib
import io
import random
import time

import streamlit as st

import SOC


def _capture_print(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue().strip()


def _shift_grade(score: int, reputation: int) -> str:
    if score >= 120 and reputation >= 85:
        return "S — インシデント判断力が際立っています"
    if score >= 60 and reputation >= 55:
        return "A — 安定的なトリアージ"
    if score >= 30 and reputation >= 40:
        return "B — 基礎は押さえている。誤遮断・見逃しに注意"
    return "C — もう一シフトで慣れをつけよう"


def _reset_game() -> None:
    st.session_state.game = SOC.GameState()
    st.session_state.rng = random.Random()
    st.session_state.started = False
    st.session_state.ended = False
    st.session_state.finalized = False
    st.session_state.victory = None
    st.session_state.end_reason = ""
    st.session_state.last_sim_time = time.time()
    st.session_state.feedback = ""


def _ensure_session() -> None:
    if "game" not in st.session_state:
        _reset_game()


def _simulation_step(write_csv: bool) -> None:
    state = st.session_state.game
    if not st.session_state.started or st.session_state.ended:
        return

    now = time.time()
    dt = max(0.0, now - st.session_state.last_sim_time)
    st.session_state.last_sim_time = now

    # 勝敗判定が内部でロックを取得するため、ここでは保持しない。
    if state.shift_ended and not st.session_state.finalized:
        victory, reason = SOC.finalize_shift(state)
        st.session_state.victory = victory
        st.session_state.end_reason = reason
        st.session_state.finalized = True
        st.session_state.ended = True
        return

    with state.lock:
        if state.threat >= state.cfg.lose_threat:
            st.session_state.ended = True
            st.session_state.victory = False
            st.session_state.end_reason = "脅威メーターが飽和しました"
            state.running = False
            return

        if not state.shift_ended:
            state.threat = max(0.0, state.threat - state.cfg.threat_decay_per_sec * dt)
            elapsed = now - state.start_time
            if elapsed >= state.cfg.shift_seconds:
                state.shift_ended = True
                return

    ev = SOC.spawn_event(state, st.session_state.rng)
    if write_csv:
        SOC.append_event_csv(ev)

    with state.lock:
        if state.threat >= state.cfg.lose_threat:
            st.session_state.ended = True
            st.session_state.victory = False
            st.session_state.end_reason = "脅威メーターが飽和しました"
            state.running = False


def _metrics_block() -> None:
    state = st.session_state.game
    with state.lock:
        elapsed = time.time() - state.start_time
        left = max(0.0, state.cfg.shift_seconds - elapsed)
        threat = state.threat
        score = state.score
        rep = state.reputation
        n_blocked = len(state.blocked_ips)
        lose = state.cfg.lose_threat
        win_max = state.cfg.win_threat_max

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("脅威メーター", f"{threat:.1f} / {lose}")
    c2.metric("スコア", score)
    c3.metric("評判", rep)
    c4.metric("シフト残り", f"{left:.0f} 秒" if st.session_state.started else "—")

    threat_pct = min(1.0, threat / lose)
    bar_label = "安全圏" if threat < win_max else ("注意" if threat < lose * 0.9 else "危険")
    st.progress(threat_pct, text=f"脅威 {threat:.1f} — {bar_label}（クリア目安: {win_max} 未満）")
    st.caption(f"遮断済み IP: {n_blocked} ｜ クリアライン: 脅威 < {win_max} かつ評判 ≥ 40")


def _sev_badge(sev: str) -> str:
    if sev == "CRITICAL":
        return f"🚨 :red[{sev}]"
    if sev == "HIGH":
        return f"🔥 :red[{sev}]"
    if sev == "MEDIUM":
        return f"⚠️ :orange[{sev}]"
    if sev == "LOW":
        return f"🔵 :blue[{sev}]"
    return f"⚪ {sev}"


def _log_panel() -> None:
    state = st.session_state.game
    with state.lock:
        items = list(state.logs)[-20:]
        blocked = set(state.blocked_ips)
        dismissed = set(state.dismissed_ids)
        escalated = set(state.escalated_ids)

    st.subheader("ライブログ")
    st.caption("🔍 詳細 ｜ 🚫 遮断 ｜ ✓ クローズ（誤検知向け） ｜ ⬆ Tier2 へ")

    hdr = st.columns([0.7, 1.1, 1.6, 3.2, 0.9, 0.5, 0.5, 0.5, 0.5])
    for col, label in zip(
        hdr,
        ["ID", "緊急度", "Source IP", "Message", "MITRE", "詳細", "遮断", "Close", "Esc"],
    ):
        col.markdown(f"**{label}**")
    st.divider()

    if not items:
        st.info("シフト開始後、ログが流れます。")
        return

    for ev in reversed(items):
        c1, c2, c3, c4, c5, c6, c7, c8, c9 = st.columns([0.7, 1.1, 1.6, 3.2, 0.9, 0.5, 0.5, 0.5, 0.5])

        tags = []
        if ev.log_id in dismissed:
            tags.append(":gray[dismissed]")
        if ev.log_id in escalated:
            tags.append(":blue[escalated]")
        if ev.src_ip in blocked:
            tags.append(":orange[blocked]")

        c1.write(f"{ev.log_id:04d}")
        c2.write(_sev_badge(ev.severity))
        c3.write(ev.src_ip)
        msg = ev.message
        if tags:
            msg += "  " + " ".join(tags)
        c4.write(msg)
        c5.write(f"`{ev.mitre}`")

        if c6.button("🔍", key=f"ins_{ev.log_id}", help="ログ詳細"):
            st.session_state.feedback = _capture_print(SOC.cmd_inspect, state, ev.log_id)
            st.rerun()

        ip_blocked = ev.src_ip in blocked
        if c7.button("🚫", key=f"blk_{ev.log_id}", disabled=ip_blocked, help="IP をファイアウォール遮断"):
            st.session_state.feedback = _capture_print(SOC.cmd_block, state, ev.src_ip)
            st.rerun()

        already_dismissed = ev.log_id in dismissed
        if c8.button(
            "✓",
            key=f"dis_{ev.log_id}",
            disabled=already_dismissed,
            help="フェーズ陽性としてクローズ（scheduled_vuln_scan 等）",
        ):
            st.session_state.feedback = _capture_print(SOC.cmd_dismiss, state, ev.log_id)
            st.rerun()

        already_esc = ev.log_id in escalated
        if c9.button(
            "⬆",
            key=f"esc_{ev.log_id}",
            disabled=already_esc,
            help="HIGH/CRITICAL を Tier2 へエスカレーション",
        ):
            st.session_state.feedback = _capture_print(SOC.cmd_escalate, state, ev.log_id)
            st.rerun()


@st.fragment(run_every=1.0)
def _live_dashboard(write_csv: bool) -> None:
    was_ended = st.session_state.ended
    _simulation_step(write_csv)
    if st.session_state.ended and not was_ended:
        st.rerun()
    _metrics_block()
    _log_panel()


def _portfolio_sidebar(write_csv: bool) -> None:
    with st.sidebar:
        st.header("シフト演習について")
        st.markdown(
            """
**SOC Analyst Shift** — Tier1 向けインシデントトリアージ体験。

- Python / 標準ライブラリ + Streamlit
- MITRE ATT&CK タグ付き合成ログ
- 遮断・クローズ・エスカレーションのトレードオフ
"""
        )
        if write_csv:
            st.caption("この起動方法ではログを soc_access.csv に出力します。")
        st.code("pip install -r requirements.txt\nstreamlit run soc_app.py", language="bash")
        st.markdown("CLI 版: `python SOC.py`")


def main(configure_page: bool = True, write_csv: bool = True) -> None:
    if configure_page:
        st.set_page_config(
            page_title="SOC Analyst Shift",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded",
        )
    if write_csv:
        SOC.init_csv()
    _ensure_session()
    _portfolio_sidebar(write_csv)
    state = st.session_state.game

    st.title("🛡️ SOC Analyst Shift")
    st.markdown(
        "セキュリティオペレーションセンター（SOC）の **Tier1 アナリスト** を体験する "
        "インタラクティブ・シミュレータ。ログを読み、誤検知と真の脅威を見極めてシフトを乗り切ろう。"
    )

    with st.expander("ブリーフィング / プレイのコツ", expanded=not st.session_state.started):
        st.markdown(
            """
| 操作 | いつ使うか |
|------|------------|
| **🔍 詳細** | HIGH/CRITICAL の内容確認 |
| **🚫 遮断** | 外部からの SQLi・C2 など明確な攻撃 IP |
| **✓ クローズ** | `scheduled_vuln_scan` やノイズ（安易な遮断は評判ダウン） |
| **⬆ エスカレ** | HIGH/CRITICAL の本番インシデント |

- シフト **3 分**、約 1 秒ごとにイベントが発生します。
- **脅威 100** でゲームオーバー。**85 未満** ＋ 評判でクリア傾向。
"""
        )

    col_a, col_b = st.columns([1, 2])
    with col_a:
        if st.button(
            "▶ シフト開始",
            type="primary",
            disabled=st.session_state.started and not st.session_state.ended,
            use_container_width=True,
        ):
            st.session_state.started = True
            st.session_state.ended = False
            st.session_state.finalized = False
            st.session_state.game = SOC.GameState()
            st.session_state.rng = random.Random()
            st.session_state.last_sim_time = time.time()
            st.session_state.feedback = "シフトを開始しました。ログを監視してください。"
            st.rerun()
        if st.button("リセット", use_container_width=True):
            _reset_game()
            st.session_state.feedback = "リセットしました。"
            st.rerun()

    with col_b:
        if st.session_state.feedback:
            st.info(st.session_state.feedback)

    if st.session_state.ended:
        vic = st.session_state.victory
        reason = st.session_state.end_reason
        with state.lock:
            sc, rep, th = state.score, state.reputation, state.threat
        grade = _shift_grade(sc, rep)

        if vic is True:
            st.success(f"★ シフト終了 — {reason}")
        elif vic is False:
            st.error(f"ゲームオーバー / 不十分 — {reason}")
        else:
            st.warning(reason)

        m1, m2, m3 = st.columns(3)
        m1.metric("最終スコア", sc)
        m2.metric("最終評判", rep)
        m3.metric("最終脅威", f"{th:.1f}")
        st.markdown(f"**デブリーフ評価:** {grade}")

    _live_dashboard(write_csv)


if __name__ == "__main__":
    main()
