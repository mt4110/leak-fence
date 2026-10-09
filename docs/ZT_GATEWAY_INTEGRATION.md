# ZT Gatewayの検証イベントAPIへの接続

対象はZT Gatewayの `GET /v1/verification-events/{ingest_id}/summary` 一つ。
Go側の認証・組織境界を再利用し、Cloudflare Workerで返却直前にLeakFenceを呼ぶ。
元データ・認証・許可範囲は合成デモへ置き換えず、実製品のハンドラーとPostgreSQLを使う。
試験用のイベント・JWT・鍵だけを一時生成する。

## 接続経路

```text
利用者のJWT
  → 専用Worker（固定GETルート、クライアントの内部ヘッダーは転送しない）
  → 専用Go入口（接続用秘密＋JWT、組織を絞った実DB検索）
  ← 平坦JSONと、署名された認可結果の内部ヘッダー
  → nonce・パス・期限・HMACを検証
  → 非公開Service Binding → Rust/Wasm LeakFence → SQLite-backed DO
  ← 検査・取得枠確定後の本文だけを利用者へ返す
```

組織・主体・権限・許可IDはGoの認可結果が根拠。本文やクライアント指定ヘッダーから作らない。
Goは、検証済みJWTと `event_ingest.envelope_tenant_id` の一致をSQL・取得後の行で確認してから
`X-ZT-Read-Authority` を発行する。Go側の追加実装が必要で、既存APIのURLを設定するだけでは接続できない。

Goの `ZT_CP_SUMMARY_EDGE_ONLY=1` モードは要約ルートだけを公開し、接続用秘密を必須にする。
取り込み・管理・既存詳細APIは別の非公開インスタンスで運用する。
その別インスタンスやDBを公開すれば別の経路が残る。この接続は全APIの防御ではない。

## 認可結果の受け渡し

独立した32-byteランダム鍵を二つ使用する。

| Go側 | Worker側 | 用途 |
| --- | --- | --- |
| `ZT_CP_SUMMARY_EDGE_SECRET` | `ORIGIN_EDGE_SECRET` | 専用入口への接続認証 |
| `ZT_CP_SUMMARY_AUTHORITY_KEY` | `AUTHORITY_KEY` | 認可結果のHMAC-SHA-256 |

どちらもpaddingなしのbase64url。SSOの署名鍵を流用しない。
内部ヘッダーの形式は `base64url(JSON).base64url(HMAC)`。
MAC対象は `zt-summary-authority-v1.` とJSONのbase64url文字列を連結したUTF-8。
JSONにはversion、要求ごとの128-bit nonce、固定パス、30秒期限、contextが入る。
Workerは期限の未来側に最大5秒の時計差を許容し、期限切れは許容しない。時計を同期する。

主体は `SHA-256(issuer + NUL + subject)` のhex。issuer間のsubject衝突を避けるためで、匿名化ではない。
許可IDはSQLの認可条件を満たした一件だけ。nonceによって別要求への認可結果の使い回しを拒否する。
本文自体をHMACへ含めない。認可メタデータと本文を独立させ、本文の返却バグをLeakFenceで検査する。
Go・Worker・鍵の管理者の侵害には対抗できない。

## ローカル検証

前提：Node、Docker、Go、ビルド済みRust/Wasm、隣接するZT Gatewayの対応ブランチ。

```sh
npm run build
npm run test:zt
npm run validate:zt -- /absolute/path/to/zt-gateway
```

専用PostgreSQL 16をlocalhostのランダムポートへ作成する。既存DBは使用しない。
ZT側のopt-in fixtureが署名付きイベントを実取り込み処理へ渡し、実DBへ保存する。
専用のGo HTTP入口へworkerdから接続し、実Wasm・SQLiteで検査する。
試験中の故障注入はテストハーネスだけで行い、公開Workerのクエリやヘッダーからは選択できない。

`.local/zt-validation-*` に秘密設定、再現用状態、サニタイズされた結果JSONを保全する。
秘密ファイルや全ディレクトリをGitHubへ添付しない。DBコンテナは停止して残す。削除・枠リセットは行わない。
`test:adapter` に新しい接続の単体試験も含まれるため、既存CIで実行される。
単体試験の認証はモック。`validate:zt` は実GoのSSO・取り込み・SQLを通す。

## 一時的な実Cloudflare接続

別途許可された検証環境だけで、公式 `cloudflared` のバージョン・配布物hashを確認して準備する。
[Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) は検証用であり常設の運用基盤ではない。

```sh
CLOUDFLARE_ACCOUNT_ID=<承認済みアカウントID> \
CLOUDFLARED_BIN=/absolute/path/to/verified/cloudflared \
npm run validate:zt -- /absolute/path/to/zt-gateway --cloud
```

実行は専用Worker二つとDO namespaceを作成し、合成JWT・接続鍵・コードをCloudflareへ送る。
一時トンネルは要約専用Go入口だけへ接続する。通常のControl PlaneやDBをトンネルへ接続しない。
公開WorkerにHTTPのローカルorigin設定を使わない。設定された一つのHTTPS originだけを呼び、redirectは追わない。

明示的な試験HTTP要求は300回を上限にし、自動で失敗ケースを再試行しない。
公開経路の反映確認は、認証なしの要求だけで最大90秒待つ。Cloudflare提供のHTML 404と
Workerの401を区別し、この確認も300要求へ含める。ガード停止の反映待ちも試験結果と区別する。
管理API・配置操作、Workerからorigin/guard/DOへの内部要求は別集計。
試験用の日次30件・122880bytesは販売用の枠ではなく、アカウント月50 USDの強制上限でもない。
費用は実使用量と請求から確認する。要求数だけで原価ゼロと判断しない。

終了時はWorkerのworkers.dev・preview URLを閉じ、guardを無効にし、トンネルとGoを停止する。
Worker・DO・DB・ローカル証拠は削除しない。閉鎖確認に失敗したらエラーを明示する。
`shutdown.json` が閉鎖確認記録。中断後の再実行では、新たな枠を作って失敗を隠さない。
このタスクで作成し閉鎖済みのWorkerを再開するときは `RESUME_CLOUD_STATE=<前回の証拠ディレクトリ>` を指定し、
同じDOの枠と通算300要求の上限を引き継ぐ。途中まで枠を消費していた場合は計画の残量前提を再判断する。

## 防御の限界

- この組織内閲覧ポリシーは個人所有者ACLではない。既存のロール欠落時viewer扱いも維持する。
- `reported_result` は報告値。`event_signature_verified` は取り込み時点の署名確認記録。ファイルの安全保証ではない。
- LeakFenceは許可値の意味・マルウェア有無・個人情報を分類しない。
- origin/guardの失敗・未確認の認可情報では503。未検査本文へ戻さない。
- 常設TLS、ホスト運用、鍵更新、認証失効、実利用者の導入、製品SLO・原価は別の検証事項。

実行結果は [接続試験の証拠](ZT_GATEWAY_RESULTS_2026-10-10.md) を参照。
