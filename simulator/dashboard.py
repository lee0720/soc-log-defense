"""架空の監視スナップショットを表示するダッシュボード。"""

import altair as alt
import pandas as pd
import streamlit as st

from simulator.monitoring import severity_counts, summarize
from simulator.title import show_profile

STATUS_LABELS = {
    "open": "未対応",
    "confirmed": "重大・確認済み",
    "resolved": "対応済み",
    "false_positive": "誤検知",
}
# 色だけに頼らず、英語の重大度と日本語を併記する。
SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL · 重大",
    "HIGH": "HIGH · 高",
    "MEDIUM": "MEDIUM · 中",
    "LOW": "LOW · 低",
}
SEVERITY_COLORS = ["#F87171", "#FBBF24", "#38BDF8", "#4ADE80"]


def show_trend(buckets, fields, labels, colors, unit):
    # 色と凡例に加え、点とツールチップで値を確認できるようにする。
    rows = pd.DataFrame(buckets).rename(columns=fields)
    rows = rows.melt(id_vars="time", value_vars=labels, var_name="系列", value_name="値")
    chart = alt.Chart(rows).mark_line(point=True).encode(
        x=alt.X("time:O", title="時刻 (JST)", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("値:Q", title=unit),
        color=alt.Color("系列:N", scale=alt.Scale(domain=labels, range=colors), legend=alt.Legend(orient="top")),
        strokeDash=alt.StrokeDash("系列:N", legend=None),
        tooltip=[alt.Tooltip("time:O", title="時刻 (JST)"), "系列:N", "値:Q"],
    ).properties(height=190)
    st.altair_chart(chart, width="stretch")


def show_dashboard(snapshot):
    st.title("監視ダッシュボード")
    st.caption("SOC監視コンソール / 架空の監視スナップショット · JST")
    totals = summarize(snapshot)
    metrics = [
        ("監視イベント総数", "events"),
        ("未対応アラート", "open"),
        ("重大インシデント", "critical"),
        ("対応済みインシデント", "resolved"),
        ("誤検知", "false_positive"),
    ]
    for group in (metrics[:3], metrics[3:]):
        for column, (label, key) in zip(st.columns(len(group)), group):
            column.metric(label, f"{totals[key]:,}", border=True)

    traffic, authentication = st.columns(2)
    with traffic:
        st.subheader("ネットワークトラフィック")
        show_trend(snapshot["buckets"], {"inbound": "受信", "outbound": "送信"},
                   ["受信", "送信"], ["#38BDF8", "#4ADE80"], "MB / 5分")
    with authentication:
        st.subheader("認証成功・失敗")
        show_trend(snapshot["buckets"], {"auth_ok": "成功", "auth_fail": "失敗"},
                   ["成功", "失敗"], ["#4ADE80", "#FBBF24"], "件 / 5分")

    st.subheader("アラートの重大度別件数")
    st.caption("CRITICAL 重大（赤） / HIGH 高（黄） / MEDIUM 中（青） / LOW 低（緑）。色と文字の両方で区別します。")
    counts = severity_counts(snapshot["alerts"])
    labels = [SEVERITY_LABELS[severity] for severity in counts]
    chart_data = pd.DataFrame({"重大度": labels, "件数": list(counts.values())})
    chart = alt.Chart(chart_data).mark_bar().encode(
        x=alt.X("件数:Q", axis=alt.Axis(tickMinStep=1)),
        y=alt.Y("重大度:N", sort=labels),
        color=alt.Color(
            "重大度:N",
            scale=alt.Scale(domain=labels, range=SEVERITY_COLORS),
            legend=None,
        ),
        tooltip=["重大度:N", "件数:Q"],
    ).properties(height=160)
    st.altair_chart(chart, width="stretch")

    st.subheader("最新アラート")
    st.caption("重大度は検知ルールが付けた優先度です。対応状況と合わせて確認してください。")
    alerts = sorted(snapshot["alerts"], key=lambda alert: (alert["time"], alert["id"]), reverse=True)
    rows = [
        {
            "時刻": alert["time"],
            "重大度": SEVERITY_LABELS[alert["severity"]],
            "分類": alert["category"],
            "状態": STATUS_LABELS[alert["status"]],
            "アラートID": alert["id"],
            "送信元IP": alert["source"],
            "宛先IP": alert["destination"],
        }
        for alert in alerts
    ]
    st.dataframe(rows, hide_index=True, width="stretch")
    st.subheader("プレイヤー")
    show_profile()
