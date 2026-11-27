"""SOC Simulator 2.0 の起動入口。"""

import streamlit as st

from simulator.title import show_title


def show_legacy_shift():
    # 2.0からのシフト演習では、サーバの共有ファイルに書き込まない。
    from soc_app import main as show_shift

    show_shift(configure_page=False, write_csv=False)


def main():
    st.set_page_config(
        page_title="SOC Simulator 2.0",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.navigation(
        [
            st.Page(show_title, title="ホーム", default=True),
            st.Page("simulator/mission_page.py", title="デモ演習", url_path="mission"),
            st.Page(
                "simulator/dashboard_page.py",
                title="監視ダッシュボード",
                url_path="dashboard",
            ),
            st.Page(
                "simulator/training_page.py",
                title="TRAINING",
                url_path="shift",
            ),
        ],
        position="top",
    ).run()


if __name__ == "__main__":
    main()
