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


def _simulation_step() -> None:
    state = st.session_state.game
    if not st.session_state.started or st.session_state.ended:
        return

    now = time.time()
    dt = max(0.0, now - st.session_state.last_sim_time)
    st.session_state.last_sim_time = now

    with state.lock:
        if state.shift_ended and not st.session_state.finalized:
            victory, reason = SOC.finalize_shift(state)
            st.session_state.victory = victory
            st.session_state.end_reason = reason
            st.session_state.finalized = True
            st.session_state.ended = True
            return

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

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("脅威メーター", f"{threat:.1f} / {state.cfg.lose_threat}")
    c2.metric("スコア", score)
    c3.metric("評判", rep)
    c4.metric("シフト残り (秒)", f"{left:.0f}" if st.session_state.started else "—")
    st.caption(f"遮断済み IP 数: {n_blocked}")


def _log_panel() -> None:
    state = st.session_state.game
    with state.lock:
        items = list(state.logs)[-50:]
    lines = [SOC.format_event_line(ev) for ev in items]
    st.subheader("ログ（直近 50 件）")
    st.text_area("logs", "\n".join(lines) if lines else "（ログなし）", height=280, disabled=True, label_visibility="collapsed")


@st.fragment(run_every=1.0)
def _live_dashboard() -> None:
    _simulation_step()
    _metrics_block()
    _log_panel()


def main() -> None:
    st.set_page_config(page_title="SOC Analyst Shift", layout="wide")
    _ensure_session()
    state = st.session_state.game

    st.title("SOC Analyst Shift")
    st.caption("Tier1 アナリスト体験シミュレータ（Streamlit）")

    with st.expander("ブリーフィング / ルール", expanded=False):
        st.markdown(
            """
- ログが自動で流れます（シフト開始後、約 1 秒ごとにイベント）。
- **脅威メーターが 100** でゲームオーバー。シフト終了時に **85 未満** かつ評判が十分ならクリア傾向。
- `scheduled_vuln_scan` やメンテ系は安易に遮断しない。HIGH/CRITICAL は **詳細** → **エスカレーション** も検討。
"""
        )

    col_a, col_b = st.columns([1, 2])
    with col_a:
        if st.button("シフト開始", disabled=st.session_state.started and not st.session_state.ended):
            st.session_state.started = True
            st.session_state.ended = False
            st.session_state.finalized = False
            st.session_state.game = SOC.GameState()
            st.session_state.rng = random.Random()
            st.session_state.last_sim_time = time.time()
            st.session_state.feedback = "シフトを開始しました。"
            st.rerun()
        if st.button("リセット（新規シフト）"):
            _reset_game()
            st.session_state.feedback = "リセットしました。"
            st.rerun()

    with col_b:
        if st.session_state.feedback:
            st.info(st.session_state.feedback)

    if st.session_state.ended:
        vic = st.session_state.victory
        reason = st.session_state.end_reason
        if vic is True:
            st.success(f"★ シフト終了 — {reason}")
        elif vic is False:
            st.error(f"ゲームオーバー / 不十分 — {reason}")
        else:
            st.warning(reason)
        with state.lock:
            st.write(f"最終: スコア **{state.score}** ／ 評判 **{state.reputation}** ／ 脅威 **{state.threat:.1f}**")

    _live_dashboard()

    st.divider()
    st.subheader("アナリストアクション")

    ac1, ac2, ac3 = st.columns(3)
    with ac1:
        st.markdown("**詳細・調査**")
        inspect_id = st.number_input("ログ ID（inspect）", min_value=1, value=1, step=1)
        if st.button("詳細を表示", key="btn_inspect"):
            st.session_state.feedback = _capture_print(SOC.cmd_inspect, state, int(inspect_id)) or "（出力なし）"
            st.rerun()
        inv_ip = st.text_input("IP（investigate）", placeholder="203.0.113.1")
        if st.button("IP で調査"):
            if not inv_ip.strip():
                st.session_state.feedback = "IP を入力してください。"
            else:
                st.session_state.feedback = _capture_print(SOC.cmd_investigate, state, inv_ip.strip()) or "（出力なし）"
            st.rerun()
        if st.button("ステータスを表示"):
            st.session_state.feedback = _capture_print(SOC.cmd_status, state) or "（出力なし）"
            st.rerun()

    with ac2:
        st.markdown("**遮断・クローズ・エスカレート**")
        block_ip = st.text_input("遮断する IP", placeholder="203.0.113.10")
        if st.button("IP を遮断 (block)"):
            if not block_ip.strip():
                st.session_state.feedback = "IP を入力してください。"
            else:
                st.session_state.feedback = _capture_print(SOC.cmd_block, state, block_ip.strip()) or "（出力なし）"
            st.rerun()
        dismiss_id = st.number_input("ログ ID（dismiss）", min_value=1, value=1, step=1, key="dismiss_n")
        if st.button("フェーズ陽性でクローズ (dismiss)"):
            st.session_state.feedback = _capture_print(SOC.cmd_dismiss, state, int(dismiss_id)) or "（出力なし）"
            st.rerun()
        esc_id = st.number_input("ログ ID（escalate）", min_value=1, value=1, step=1, key="esc_n")
        if st.button("Tier2 へエスカレーション"):
            st.session_state.feedback = _capture_print(SOC.cmd_escalate, state, int(esc_id)) or "（出力なし）"
            st.rerun()

    with ac3:
        st.markdown("**その他**")
        tail_n = st.slider("表示件数（tail 再出力）", 1, 80, 12)
        if st.button("直近ログを下に再表示"):
            with state.lock:
                items = list(state.logs)[-tail_n:]
            lines = [SOC.format_event_line(ev) for ev in items]
            st.session_state.feedback = "\n".join(lines) if lines else "（ログなし）"
            st.rerun()
        whois_ip = st.text_input("WHOIS する IP", placeholder="203.0.113.1", key="whois_ip")
        if st.button("WHOIS（ダミー）"):
            if not whois_ip.strip():
                st.session_state.feedback = "IP を入力してください。"
            else:
                st.session_state.feedback = _capture_print(SOC.cmd_whois, whois_ip.strip()) or "（出力なし）"
            st.rerun()

    with st.expander("CLI コマンド対応表"):
        st.markdown(
            """
| 元コマンド | UI |
|------------|-----|
| `status` | ステータスを表示 |
| `inspect <id>` | 詳細を表示 |
| `block <ip>` | IP を遮断 |
| `dismiss <id>` | フェーズ陽性でクローズ |
| `escalate <id>` | Tier2 へエスカレーション |
| `tail [n]` | 直近ログを再表示（フィードバック欄） |
| `whois <ip>` | WHOIS（ダミー） |
| `investigate <ip>` | IP で調査 |
"""
        )


if __name__ == "__main__":
    main()
