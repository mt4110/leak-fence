# Contributing

合成データだけで再現できる問題報告を歓迎します。脆弱性は[非公開報告](https://github.com/mt4110/leak-fence/security/advisories/new)へお願いします。

READMEのローカル検証を実行し、振る舞いを変えるPRには境界条件と失敗時の状態を含めてください。
機密値をテストの失敗出力・HTTPダンプ・例外・ログへ含めないでください。
認可失敗時の許可、取得枠の暗黙リセット、原文へのフォールバックは受け入れません。
実環境、実データ、外部通知や有料資源を必要とする検証は、対象と許可を確認してから実施します。

コードはMITです。必要な第三者の帰属を保持してください。
CI成功は独立セキュリティレビューや本番性能の証明ではありません。

## 依存関係の検査

GitHub Actions の `osv-dependencies` は、PR のマージ結果にある
`package-lock.json`、`Cargo.lock` と、ZT 検証が使う PostgreSQL 17 イメージを毎回検査します。
既存・新規の区別や深刻度による除外は設けず、脆弱性の検出や検査の失敗でチェックが失敗します。
`chrono` の保守終了通知 RUSTSEC-2026-0543 は、別名 ID がない間だけログに通知します。
同じ検査を main への push 時と毎日にも実行します。

ローカルでは OSV-Scanner v2、Node.js、稼働中の Docker を用意し、このリポジトリの Git フックを有効にしてください。
既存のフックがある場合は、そのフックから `.githooks/pre-commit` を呼び出してください。

```sh
git config --local core.hooksPath .githooks
```

フックはステージ済みのロックファイルとイメージ定義を検査します。GitHub 側の必須チェックはローカルフックの設定から独立しています。
PostgreSQL は同じダイジェストを CI と ZT 検証で参照し、ZT 検証では走査を通過してからコンテナを起動します。
17系の修正版を取り込むときは `scripts/zt-postgres-image.txt` のダイジェストを更新してください。
