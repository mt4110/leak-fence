# LeakFence

**APIが返すデータを、権限と取得量の契約で制限するOSS。**

Rust / Cloudflare Workers / SQLite-backed Durable Objects / MIT。
現在は開発中の検証用プロトタイプです。独立監査・Cloudflare実環境の負荷試験は未実施です。

既存の認証・認可結果を使って、送信直前のJSONレコードを検査します。
別テナントの行、許可していないID・項目、日次の取得枠を超える応答を停止します。
検査・ストレージ・タイムアウトの失敗時に、元のデータを返すフォールバックはありません。
「挟むだけですべての漏洩を防ぐ」製品ではありません。

## 最初に試す

Rust 1.95.0とwasm32-unknown-unknown、Node.js 26.9.0、Python 3.12以上を使用します。
Rustの対象はrust-toolchain.tomlに記載しています。

```sh
cargo install worker-build --version 0.8.7 --locked
npm ci --ignore-scripts
npm run build
npm run demo
```

合成データだけで、他テナントの応答拒否、許可された応答、取得枠超過を確認します。
Cloudflareアカウント、デプロイ、実データは不要です。
ローカル試験の状態は.local/worker-test-*に残ります。

## 守る対象

| 検査 | 振る舞い |
| --- | --- |
| テナントとオブジェクト | 信頼する認可結果の所属・許可ID集合に一致しないレコードを拒否 |
| 返却項目 | 明示した許可項目以外・入れ子を拒否 |
| JSON解釈 | 重複キー、不正UTF-8、非JSON数値、レコード以外を拒否 |
| 単一応答 | 契約した件数・バイト数を超える応答を全体拒否 |
| 累積取得 | テナント・利用者・budget_groupごとに日次件数とバイト数を送信前に確定 |
| 障害 | 設定不備・取得枠の判定不能・タイムアウトでデータを返さない |

日次枠はUTCの暦日です。連続24時間の上限ではありません。再試行・重複行も消費します。
送信成否が不明でも枠を戻さないため過大計上があり得ます。課金の集計には使えません。
上限は同一利用者単位であり、複数アカウントを合わせた取得制限ではありません。

## 組み込み方

利用者のCloudflareアカウント内に非公開のLeakFence Workerを配置し、既存APIからService Bindingで呼びます。
認証・認可は既存API側で行います。対象は読み取り専用で、小さなJSONレコードを返すAPIから始めます。

```text
既存の認証・認可 → APIの読み取り処理 → LeakFenceの内容検査
                                             ↓
                                 Durable Objectで枠を確定
                                             ↓
                                検査済み応答 または拒否
```

[契約の例](examples/contracts.json)と[TypeScript接続関数](packages/adapter/index.ts)を同梱しています。
Rust側はcrates/workerを参照してください。初期版の接続関数はnpmに公開していません。

```ts
// 自分のサーバーのルート内で使用する形。authzは既存の認可処理の結果。
return protectJson(env.LEAK_FENCE, {
  contract: 'sample.customers',
  context: {
    principal: authz.principalId,
    tenant: authz.tenantId,
    permission: 'customer:read',
    record_ids: authz.allowedCustomerIds,
  },
  response_body: JSON.stringify(rows),
});
```

Contextをクライアントのヘッダーから直接作らないでください。検査するrowsのIDをそのまま許可集合にしないでください。
権限・行の所有者・項目の設定が間違っていれば、その誤りを自動で発見できません。

## 内部API

両APIともPOST、Content-Type: application/jsonです。公開の認証なしAPIとして配置しないでください。
入力は上の例と同じcontract・context・response_body。入力エンベロープは最大1,700,000バイトです。
検査する本文は最大256KiB、最大1,000件。契約でさらに小さくできます。

- `/v1/evaluate`: 内容だけを検査し、結果と件数・バイト数を返す。本文は返さず、取得枠は判定しない。
- `/v1/protect`: 内容を検査し、枠の永続化を待って、元の検査済みJSON本文を200で返す。

未設定契約や内容違反は403、取得枠不足は429、判定不能は503です。
成功・失敗とも固定のJSON応答ヘッダーとno-storeを使い、Cookie・任意の元ヘッダーを転送しません。
HTTPストリームの中継ではありません。既存の応答をバッファリングして渡します。

wrangler.tomlはSERVICE_ENABLED=false、workers.dev無効、preview URL無効、公開ルートなしです。
稼働設定と接続経路は[導入・停止・復旧手順](docs/OPERATIONS.md)を参照してください。
GitHubのCIから本番へデプロイする機能はありません。

## 防げないもの

認可層・アプリ・ホストの侵害、DB・バックアップへの直接アクセス、許可された値の中に入った秘密、
別のAPIや検査後のヘッダー・本文改変による持ち出しは対象外です。
暗号文の意味解析、日本語PII検出、eBPF監視、全利用者の行動相関、決済は実装していません。
一回消費型GETや書き込み処理を止めても、すでに生じた副作用は取り消せません。

詳しくは[信頼境界](docs/THREAT_MODEL.md)を確認してください。
[販売と料金設計](docs/PRODUCT_AND_PRICING.md)は検証前の案であり、有償サービスや課金受付はまだありません。

## 検証

```sh
cargo fmt --all --check
cargo test --locked -p leak-fence-core
cargo clippy --locked -p leak-fence-core --all-targets -- -D warnings
cargo clippy --locked -p leak-fence-worker --target wasm32-unknown-unknown -- -D warnings
npm run check:adapter
npm run build
npm run test:worker
npm audit --audit-level=high
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

ローカルworkerdで、並行要求、再起動後の枠維持、共有枠、UTF-8バイト数、設定・binding障害を検証します。
Rustの単体試験、SQLiteの境界試験、既存Python試作の回帰試験は別々に扱います。
実クラウドの地域間動作・本番負荷・第三者の導入効果の確認を代替しません。

## 構成

- crates/core: Rustの返却契約検査と取得枠SQL
- crates/worker: 非公開WorkerとDurable Object
- packages/adapter: TypeScript側の接続関数
- tests: ローカルworkerd・SQLite・Python試験
- leakfence: 保全したPython試作。[元の説明](docs/PYTHON_PROTOTYPE.md)はRust版の仕様とは異なります

脆弱性の報告は[Security Policy](SECURITY.md)を参照してください。実データや認証情報をIssueへ貼らないでください。
