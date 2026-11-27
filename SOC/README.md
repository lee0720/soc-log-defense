# SOC Simulator 2.0

架空の企業を監視し、SOC（Security Operations Center）の仕事を学ぶ教育用シミュレーターです。監視ダッシュボード、3分間のシフト演習、認証アラートのデモ演習を利用できます。途中再開と経験値の保存は開発予定です。

## 起動方法

検証環境は Python 3.14.2、Streamlit 1.55.0 です。プロジェクト直下で実行します。

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

- 既存Web版は `python -m streamlit run soc_app.py` で起動します。
- 既存CLI版は `python SOC.py` で起動します。
- 既存版を単体起動すると、従来どおり `soc_access.csv` にログを出力します。2.0内のシフト演習ではファイル出力を省き、別々のプレイヤーでログが混ざるのを防ぎます。

## デモ演習

ホームの「デモ演習を開始」から、架空の認証アラート（DEMO-01）を調査できます。ログを絞り込み、証拠のログID、インシデント判定、重大度、模擬対応、調査メモを入力して提出すると、100点満点の結果と解説が表示されます。

## Streamlit Community Cloud への公開設定

無料デモを公開するときは、GitHubの対象ブランチを選び、`Main file path` に `app.py`、`Advanced settings` の Python バージョンにローカルと同じ `3.14` を指定します。リポジトリ直下の `requirements.txt` から依存関係がインストールされます。`simulator/` 全体を対象ブランチに含めてください。監視データは同梱の `simulator/data/monitoring.json` から読み込むため、別途アップロードや Secrets の設定は不要です。

[Streamlit Community Cloud のデプロイ手順](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy)

## 仕組み

Streamlitで画面遷移と操作を組み立て、Altairで監視グラフを表示しています。監視データは `simulator/data/monitoring.json` にまとまっています。Python側で同じデータを使って件数とグラフを計算するので、画面上の数値を個別に変更する必要がありません。操作は架空のシフト状態に反映されます。

## テスト

```sh
python -m pip install -r requirements-dev.txt
python -m pip check
python -m pytest -q
```

## 今後の開発

- Phase 2〜3でミッション、ログ分析、対応・採点、用語集を追加します。
- Phase 4で報告書・成長・ブラウザ保存を追加します。Phase 1のランクと経験値は初期表示です。
- 無料デモの公開先は Streamlit Community Cloud です。Phase 5では Linux での動作を検証し、AWS 学習用の EC2 デプロイ手順も整備します。

### AWS公開の計画

LinuxのEC2インスタンスに、非特権ユーザーで動くStreamlitとNginxを配置する構成を検討します。NginxでHTTPSを終端し、WebSocketをループバックで待ち受けるStreamlitに転送します。実行時設定は環境変数で渡し、認証情報や証明書の秘密鍵はリポジトリに含めません。

- セキュリティグループでは公開用のHTTPSと必要なHTTPだけを許可し、Streamlit用ポートは公開しません。管理経路とIAMロールは用途に必要な権限に限定します。
- CloudWatchは稼働確認から始め、必要に応じてログ・メトリクスを追加します。公開前にEC2、ストレージ、公開IPv4、監視などを含めて見積もり、予算アラートとログ保持期間を設定します。
- 構成図、Nginx・HTTPSの設定、デプロイと復旧の手順は、Linuxでの検証後にこのREADMEへ追加します。

参考資料：[StreamlitのHTTPS構成](https://docs.streamlit.io/develop/concepts/configuration/https-support) · [CloudWatchエージェントのIAM設定](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/prerequisites.html)
