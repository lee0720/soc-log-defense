from pathlib import Path

from streamlit.testing.v1 import AppTest

from simulator.mission import grade_mission, load_mission

ROOT = Path(__file__).resolve().parents[1]


def test_demo_investigation():
    app = AppTest.from_file(str(ROOT / "simulator/mission_page.py"), default_timeout=20).run()
    assert not app.exception
    assert not app.metric
    assert not any("模範判定" in item.value for item in app.markdown)

    app.button[0].click().run()
    assert app.error
    assert not app.metric
    app.selectbox[0].select("アクセス監査").run()
    app.text_input[0].set_value("192.0.2.45").run()
    assert app.dataframe[0].value["ID"].tolist() == ["L04"]

    mission = load_mission()
    app.multiselect[0].set_value(mission["evidence"])
    app.selectbox[1].select(mission["classification"])
    app.selectbox[2].select(mission["severity"])
    app.multiselect[1].set_value(mission["responses"])
    app.text_area[0].set_value("新規端末のログイン後に経理フォルダーへアクセス。")
    app.button[0].click().run()
    assert not app.exception
    assert app.metric[0].value == "100 / 100"
    assert any(mission["explanation"] in item.value for item in app.markdown)


def test_extra_choices_do_not_get_full_credit():
    mission = load_mission()
    result = grade_mission(
        mission, [row["ID"] for row in mission["logs"]], mission["classification"],
        mission["severity"], [*mission["responses"], "誤検知としてクローズする"], " ",
    )
    assert result["証拠"] == (10, 30)
    assert result["対応"] == (15, 25)
    assert result["調査メモ"] == (0, 10)
