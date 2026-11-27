import random
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from streamlit.testing.v1 import AppTest

import SOC
from simulator.monitoring import load_snapshot, severity_counts, summarize

ROOT = Path(__file__).resolve().parents[1]


def test_monitoring_snapshot():
    snapshot = load_snapshot()
    assert summarize(snapshot) == {
        "events": 1582, "open": 3, "critical": 1, "resolved": 1, "false_positive": 2,
    }
    assert severity_counts(snapshot["alerts"]) == {
        "CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 2,
    }


def test_title_and_dashboard():
    home = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    assert not home.exception
    assert home.title[0].value == "SOC Simulator 2.0"
    menu = [item.value for item in home.subheader]
    assert ["NEW GAME", "CONTINUE", "TRAINING", "HOW TO PLAY"] == [
        item for item in menu if item in {"NEW GAME", "CONTINUE", "TRAINING", "HOW TO PLAY"}
    ]
    home_text = " ".join(item.value for item in home.markdown)
    assert "いま使える範囲" in home_text
    assert "続きから再開はできません" in home_text

    dashboard = AppTest.from_file(
        str(ROOT / "simulator/dashboard_page.py"), default_timeout=20
    ).run()
    assert not dashboard.exception
    assert dashboard.title[0].value == "監視ダッシュボード"
    assert dashboard.metric[0].value == "1,582"
    assert len(dashboard.get("vega_lite_chart")) == 3
    latest = dashboard.dataframe[0].value.iloc[0]
    assert latest["アラートID"] == "ALT-007"
    assert latest["重大度"] == "LOW · 低"

    training = AppTest.from_file(
        str(ROOT / "simulator/training_page.py"), default_timeout=20
    ).run()
    assert not training.exception
    assert "SOC Analyst Shift" in training.title[0].value
    assert any("シフト開始" in button.label for button in training.button)


def test_standalone_shift_finishes(monkeypatch, tmp_path):
    csv_path = tmp_path / "shift.csv"
    monkeypatch.setattr(SOC, "log_file_path", str(csv_path))
    shift = AppTest.from_file(str(ROOT / "soc_app.py"), default_timeout=15).run()
    assert not shift.exception
    shift.button[0].click().run()
    assert not shift.exception
    assert shift.session_state.started
    shift.session_state.game.start_time = time.time() - 181
    shift.run().run()
    assert not shift.exception
    assert shift.session_state.finalized
    assert shift.success
    assert len(csv_path.read_text(encoding="utf-8").splitlines()) >= 2


def test_integrated_shift_does_not_write_csv(monkeypatch):
    import app
    import soc_app

    show_shift = Mock()
    with monkeypatch.context() as patch:
        patch.setattr(soc_app, "main", show_shift)
        app.show_legacy_shift()
    show_shift.assert_called_once_with(configure_page=False, write_csv=False)

    state = SimpleNamespace(
        game=SOC.GameState(), rng=random.Random(0), started=True, ended=False,
        last_sim_time=time.time(),
    )
    append = Mock()
    monkeypatch.setattr(soc_app, "st", SimpleNamespace(session_state=state))
    monkeypatch.setattr(SOC, "append_event_csv", append)
    soc_app._simulation_step(write_csv=False)
    assert state.game.logs
    append.assert_not_called()


def test_cli_threat_limit_releases_lock_before_results(monkeypatch, tmp_path):
    state = SOC.GameState()
    state.threat = state.cfg.lose_threat
    show_results = Mock()

    # 脅威メーターが上限に達したシフトを、スレッドなしで再現する。
    def check_result(game, victory, reason):
        assert not game.lock.locked()
        show_results(game, victory, reason)

    monkeypatch.setattr(SOC, "log_file_path", str(tmp_path / "cli.csv"))
    monkeypatch.setattr(SOC, "GameState", lambda: state)
    monkeypatch.setattr(SOC.threading, "Thread", Mock())
    monkeypatch.setattr(SOC, "end_screen", check_result)
    SOC.main()
    show_results.assert_called_once_with(state, False, "脅威メーターが飽和しました")
