"""タイトル画面と初心者向けの操作案内。"""

import streamlit as st


def show_profile():
    st.markdown("**Trainee · 研修生**")
    st.progress(0, text="0 / 300 EXP · 初期ランク")
    st.caption("経験値の獲得と保存は Phase 4 で追加します。いまの表示は初期値です。")


def show_title():
    st.title("SOC Simulator 2.0")
    st.subheader("サイバー攻撃を見抜き、企業の安全を守れ。")
    st.write(
        "セキュリティオペレーションセンター（SOC）のアナリストとして、"
        "アラートを確認し、危険な活動と正常な業務を見分ける教育用シミュレーターです。"
    )
    st.subheader("プレイヤー")
    show_profile()

    new_game, continue_game = st.columns(2)
    with new_game:
        st.subheader("NEW GAME")
        st.markdown("**いま使える範囲**")
        st.write("架空の認証アラートを調査し、証拠を選んで対応を判断します。提出後に採点と解説を確認できます。")
        st.page_link(
            "simulator/mission_page.py",
            label="デモ演習を開始",
            icon=":material/play_arrow:",
        )
    with continue_game:
        st.subheader("CONTINUE")
        st.markdown("**いま使える範囲**")
        st.write(
            "続きから再開はできません。進行状況と経験値の保存機能はまだありません。"
            "Phase 4 でブラウザの localStorage に保存する予定です。"
            "そのデータはブラウザと端末ごとに分かれ、別の端末へは引き継がれません。"
        )

    training, how_to = st.columns(2)
    with training:
        st.subheader("TRAINING")
        st.write(
            "旧版の3分間シフト演習を起動します。ログの確認、模擬の遮断、"
            "クローズ、上位担当へのエスカレーションを試せます。"
            "この入口から起動した場合、共有ファイル soc_access.csv には書き込みません。"
        )
        st.page_link(
            "simulator/training_page.py",
            label="シフト演習を開始",
            icon=":material/school:",
        )
    with how_to:
        st.subheader("HOW TO PLAY")
        st.markdown(
            "1. **監視する** — ダッシュボードの未対応件数と重大度を見て、優先順位を考えます。\n"
            "2. **調査する** — TRAINING のログで「詳細」を押し、イベントの内容を確認します。\n"
            "3. **対応する** — 模擬の遮断、クローズ、エスカレーションのどれが適切かを判断します。"
        )
    st.caption(
        "CLI版は python SOC.py、旧Streamlit版の単体起動は streamlit run soc_app.py です。"
        "単体起動のときだけ soc_access.csv にログを出力します。"
    )
