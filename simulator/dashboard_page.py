"""ダッシュボードのページ入口。"""

from simulator.dashboard import show_dashboard
from simulator.monitoring import load_snapshot

show_dashboard(load_snapshot())
