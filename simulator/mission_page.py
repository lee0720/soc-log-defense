"""デモ演習のログ調査、提出、結果表示。"""

import streamlit as st

from simulator.mission import grade_mission, load_mission

CLASSIFICATIONS = ("不正ログインの疑い", "正常な業務操作", "判断を保留")
RESPONSES = (
    "追加ログだけを確認し、対応は保留する",
    "証拠を保全して上位担当に引き継ぐ",
    "セッションを失効し、アカウントを一時保護する",
    "誤検知としてクローズする",
)


def show_mission():
    mission = load_mission()
    st.title(mission["title"])
    st.caption(f'{mission["id"]} / 架空のシナリオ · JST')
    st.warning(mission["alert"])
    st.subheader("1. ログを調べる")
    log_type = st.selectbox("ログ種別", ("すべて", "認証", "アクセス監査"))
    keyword = st.text_input("IP・キーワード", max_chars=100).strip().casefold()
    rows = [
        row for row in mission["logs"]
        if (log_type == "すべて" or row["種別"] == log_type)
        and keyword in " ".join(row.values()).casefold()
    ]
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        st.info("条件に一致するログがありません。")

    st.subheader("2. 証拠と判断を提出する")
    with st.form("demo_investigation"):
        evidence = st.multiselect("根拠のログID", [row["ID"] for row in mission["logs"]])
        classification = st.selectbox("インシデント判定", CLASSIFICATIONS, index=None)
        severity = st.selectbox("重大度", ("低", "中", "高", "重大"), index=None)
        responses = st.multiselect("模擬対応", RESPONSES)
        note = st.text_area("調査メモ", max_chars=500)
        st.caption("メモは記入の有無を採点します。内容は下の解説と見比べてください。")
        submitted = st.form_submit_button("提出して結果を見る", type="primary")

    if submitted:
        st.session_state.pop("demo_result", None)
        if not all((evidence, classification, severity, responses)):
            st.error("証拠・判定・重大度・対応をすべて選んでください。")
        else:
            st.session_state.demo_result = grade_mission(
                mission, evidence, classification, severity, responses, note
            )

    result = st.session_state.get("demo_result")
    if result is not None:
        st.subheader("3. 結果と解説")
        score = sum(points for points, _ in result.values())
        st.metric("総合スコア", f"{score} / 100")
        st.table([{"項目": key, "得点": f"{points} / {maximum}"} for key, (points, maximum) in result.items()])
        st.write(f'模範判定: {mission["classification"]} / 重大度: {mission["severity"]}')
        st.write(f'根拠のログ: {", ".join(mission["evidence"])}')
        st.write(mission["explanation"])
        st.markdown("**推奨対応**")
        for action in mission["responses"]:
            st.write(f"・{action}")
        st.caption("入力を変更して再提出できます。")


show_mission()
