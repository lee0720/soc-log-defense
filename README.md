🛡️ SOC Log Defense Game
📌 概要
セキュリティログを監視し、サイバー攻撃を検知・対応する SOC（Security Operation Center）体験ゲームです。
プレイヤーはアナリストとしてログを分析し、適切な対応を行います。

🎮 デモ内容
* リアルタイムでログが流れる
* 攻撃（SQLi / ポートスキャン / C2通信）を検知
* コマンドで対応
    * block（IP遮断）
    * dismiss（誤検知処理）
    * escalate（上位対応）

🧠 作った理由
セキュリティログ分析の理解を深めるため、 実務に近い形で学習できるようゲーム化しました。

⚙️ 技術スタック
* Python
* threading（リアルタイム処理）
* データ構造（dict / set / deque）

💡 工夫した点
* 誤検知（False Positive）を再現
* 脅威スコア・評判システム
* コマンドベースの操作
* リアルタイムログ生成

🚀 改善予定
* ブルートフォース攻撃の検知
* StreamlitによるWeb化
* グラフ可視化

📈 バージョン
* v1: シンプルなログ監視ゲーム
* v2: SOCシミュレーター（本作）

▶ 実行方法
python soc_game.py

🎯 今後の目標
セキュリティ × データ分析のスキルを活かし、 実務レベルのログ分析ができるエンジニアを目指しています。

## 📸 プレイ画面
<img width="1440" height="900" alt="スクリーンショット 2026-04-04 18 53 49" src="https://github.com/user-attachments/assets/a8f32ad0-de11-4832-aa62-64b17400e5c2" />

![game](screenshots/play.png)

## 🔍 追加機能
- investigateコマンドを実装し、特定IPのログ履歴を確認できるようにした

※ 一部ロジックはAIを活用しつつ、自身で理解・改良を行っています。
