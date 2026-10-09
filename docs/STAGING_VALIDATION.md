# Cloudflare接続検証の実行計画

2026-10-09。今回の目的は認証付きAPI → Service Binding → Rust/Wasm → Durable Objectの接続を確認すること。
合成データ用のAPIであり、既存製品の実APIへの導入実績・販売需要の証明とは区別する。

## 対象選定と現状

確認した既存Cloudflare APIのうちNaru ingestionは書き込み、Veil Vaultは一回消費の副作用を持つ。
いずれも今回の小さな読み取り専用JSON APIの検証には選ばない。
接続したい適合リポジトリが指定された場合は、その認可処理と検証環境を調べ、個別に対象を確定する。
他リポジトリのコード・本番設定は変更していない。

アカウント画面ではWorkers Paidが現在のプラン。新しいプラン契約・ドメイン購入は不要。
既存プランの含有量と利用量はアカウント全体で共有されるため、本検証の追加請求をゼロとは保証しない。

## 作成候補の資源とデータ

| 資源 | 用途・公開範囲 |
| --- | --- |
| leak-fence-validation-guard | 非公開Worker。Service Bindingからのみ呼び出す |
| guardのBUDGETS | 新規SQLite-backed Durable Object namespace。主体2つ、日・件数・バイト数だけを保存 |
| leak-fence-validation-api | 認証付き合成API。承認後のローカル生成設定だけworkers.devを有効にする |

APIは固定の2テナント・2レコードのみを使い、DB・顧客情報・既存の本番APIへ接続しない。
テストトークン2つは256bitの乱数。サーバーにはSHA-256と固定のテスト権限だけを登録する。
生トークンは無視対象.local内の0600ファイルに保存し、ターミナル・リポジトリ・要求URLへ出さない。
有効期間は準備から2時間。期限・認証設定の欠落や不正は503で停止する。
期限が切れてもWorkerと保存済みカウンターは残る。資源の削除は別の明示承認を必要とする。

既存Worker、DNS、ドメイン、他製品のDB、支払プラン、GitHubのCloudflare資格情報は変更しない。
コードと合成データ、ハッシュ化したテスト資格情報がCloudflareへ渡る。
プラットフォームの通常の実行・通信メタデータはCloudflareが処理する。独自の本文ログ・外部分析送信は行わない。

## ローカル検証

```sh
npm run test:staging
npm run test:worker
```

stagingは認証、偽ヘッダー、権限元の分離、返却バグ、障害、期限切れを試験する。
実際の2つのローカルWorkerとService Binding、Rust/Wasm、SQLiteでクラウド試験手順全体も実行し、
183要求、40個ずつの計測サンプル、取得枠境界、本文・トークンが報告に含まれないことを確認する。
この試験で得たローカル遅延を、実Cloudflareで測った値として報告しない。

## 承認後の実行

1. 宛先アカウントで同名Workerが未作成であることを確認する。同名資源があれば上書きせず設定と所有を確認する。
2. `node scripts/staging-credentials.mjs <確認済みアカウントID>`で新しい準備ディレクトリを作る。
   ここで生成された設定・秘密は公開しない。生成するだけでは外部変更は起きない。
3. guardの生成設定を`wrangler deploy --config <directory>/guard.wrangler.toml`で配置する。
4. APIの生成設定を配置する。初回は認証設定がないため503。その後、
   `wrangler secret bulk <directory>/secrets.json --config <directory>/api.wrangler.toml`で登録する。
5. 出力されたworkers.devの正確なoriginを確認し、
   `node scripts/staging-check.mjs <確認済みorigin> <directory>`を一度実行する。
6. 結果JSON、配置バージョン、設定、アカウントの使用量情報を記録する。本文やトークンを記録しない。
7. 成否にかかわらず試験後は`wrangler deploy --config <directory>/api.closed.wrangler.toml`で公開入口を閉じる。
   認証期限切れは入口を閉じる操作の代わりではない。期限後も公開URLが有効なら拒否要求の実行費用が生じ得る。

計画済み試験は183 HTTP要求。スクリプトは300要求で停止し、自動再試行しない。
追加確認もこの300要求の枠内で扱う。90並行要求の試験は同一主体の日次120件の境界を確かめる。
権限・上限を緩めて失敗を隠さない。途中終了後の再実行は同じ枠を消費済みの可能性があるため、
カウンターを削除・リセットせず、残量・日付・試験前提を確認して別途実行範囲を判断する。

## 測定と継続判断

正常データは同じ合成応答を使い、baselineとprotectedを交互に40回ずつ計測する。
クライアント側の時間はネットワークと全本文受信を含む。Server-Timingはガード呼出しの経過時間であり、CPU時間ではない。
p50/p95/p99を記録するが、40サンプルのp99はほぼ最大値で、裾の安定した推定には不十分。
コールドスタート・リージョン・時間帯の差や、実際のDB問い合わせ・権限取得費用は本試験で代表できない。
failureケースは接続関数の例外を注入する試験で、実ネットワーク障害やDurable Object永続化障害の試験ではない。

違反本文の返却、認証の迂回、上限超過の許可が一件でも確認されたら採用を止めて原因を調査する。
遅延の許容値は対象製品のSLOで判断し、この合成APIに販売用の恣意的な合格値を設定しない。
実API接続の手間と第三者の導入・支払意思は、接続試験成功後の別の判断事項。

## 費用の扱い

[Workers料金](https://developers.cloudflare.com/workers/platform/pricing/)と
[Durable Objects料金](https://developers.cloudflare.com/durable-objects/platform/pricing/)を2026-10-09に確認。
Standard料金ではService Bindingの呼出しに追加のWorkerリクエスト料金はなく、両WorkerのCPU時間は合算される。
DO要求数、稼働GB-s、SQL読み書き、保存量は別の対象。防御カウンターは請求メーターとして使わない。

含有量・請求単位の丸め・アカウントの既使用量を加味して、使用量画面またはAPIの実値から試験増分と継続原価を整理する。
要求数だけを単価に掛けて請求額を断定しない。DOでは月の含有量超過後の使用量が次の請求単位へ切り上げられるため、
小さい試験でも請求単位の境界に影響し得る。USDの費用と為替・税は分ける。
実Cloudflareの限定試験は完了し、Workersの初期使用量を取得したが、DO使用量と確定原価は未取得。
[実行結果](STAGING_RESULTS_2026-10-09.md)を参照する。
Cloudflareの予算通知は利用を強制停止しない。[月額予算の運用](OPERATIONS.md)と日次取得枠を区別する。

## 停止と復帰

期限経過でAPIは503になる。緊急時にはAPIのworkers.devを無効にして更新し、公開入口を閉じる。
guardが停止してもAPIは元の合成本文へフォールバックしない。DO namespaceを消さず、既消費量を維持する。
再開時は接続・認証・期限・残量を再確認する。自動デプロイ、Cron、継続負荷試験は設定しない。
