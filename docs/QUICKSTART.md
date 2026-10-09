# 自分のAPIで試す

最初の対象は、Cloudflare Workersで読み取り専用JSON APIを運用する開発者・小規模チームです。
手元で内容検査 → 永続取得枠を含むデモ → 既存APIの検証環境への接続の順で進めます。
認証・認可を新しく作る必要はありません。誰に何を返してよいかを決める処理は既存APIから接続してください。

## 1. 手元で許可・拒否を確認する

Rust/rustupが入っていれば、リポジトリのルートで次を実行できます。初回はビルド用の依存を取得します。

```sh
cargo run --locked -p leak-fence-cli -- demo
```

`demo: passed`と、正常応答の`passed`、他テナントの`tenant_mismatch`、追加項目の`unapproved_field`が表示されます。
Cloudflareへの配置・データ送信・請求は発生しません。CLIは本文を表示・保存しません。
これは内容検査の体験です。日次の取得枠や実際のAPI通信は保護しません。

次に契約と応答を検査します。ここでも顧客データの代わりに合成データを使ってください。

```sh
cargo run --locked -p leak-fence-cli -- check examples/contracts.json
cargo run --locked -p leak-fence-cli -- inspect examples/contracts.json sample.customers examples/inspection/context.json examples/inspection/allowed.json
```

同じコマンドの最後を`examples/inspection/foreign-tenant.json`や`examples/inspection/extra-field.json`へ変更すると拒否します。
CLIの終了コードは0が成功、2が内容の拒否、1が設定・ファイル・コマンドの問題です。
拒否結果は固定理由だけです。本文、認可情報、パーサーの入力抜粋を出力しません。
入力ファイルは通常のファイルを指定してください。ポリシー最大128KiB、Context最大1,700,000バイト、本文最大256KiBです。
CLIが成功しても出力の`budget_check`は`not_performed`です。

## 2. 返却契約を決める

`examples/contracts.json`を参照し、対象ルートに対して次を決めます。

| 設定 | 判断元 |
| --- | --- |
| `permission` | 既存の認可処理が確定する操作権限 |
| `fields` | 利用者へ返してよい項目の明示的な一覧 |
| `tenant_field` / `id_field` | 信頼するレコードの所属・ID項目。値は文字列 |
| `max_records` / `max_bytes` | 正常な一回の応答に必要な最大件数・UTF-8バイト数 |
| `daily_records` / `daily_bytes` | 正常な業務量に基づくUTC暦日ごとの取得枠 |
| `budget_group` | 複数ルートで枠を共有する場合の変わらない識別子 |

テナントとIDの項目も`fields`に含めます。同じグループ内の上限が異なる設定は拒否します。
デモの件数をそのまま本番の上限として使わないでください。許可項目の値に秘密が入る問題は検出しません。

## 3. ローカルで取得枠まで確認する

[READMEのWorkerデモ](../README.md#日次取得枠までローカルで体験)を実行してください。
実際のRust/Wasm、ローカルworkerdとSQLiteを使います。Cloudflareアカウントは不要です。
期待した許可・拒否が一致しなければ失敗終了します。ここでも実際のAPIの認可はまだ検証していません。

## 4. 既存APIの二つの処理を接続する

[customer-api.ts](../examples/integration/customer-api.ts)は、一つのGETルートと保護処理をまとめた型検査済みの例です。
テスト用認証、検査を通らないベンチマーク経路、故障を注入するクエリは含みません。
既存アプリ側から次の二つを渡します。

1. `authorize(request, env)`：既存セッション等を検証し、所属・操作権限・許可IDをサーバー側で確定します。
   未認証は`{ kind: 'unauthenticated' }`、権限なしは`{ kind: 'deny' }`、許可は`{ kind: 'allow', context }`を返します。
2. `readCustomers(env, authority)`：許可された所属とIDで絞り、小さいページのレコードを取得します。
   `{ id, tenant_id, name }`など契約で許可した項目だけを返します。

この例の契約名は`sample.customers`、ルートは`GET /v1/customers`です。自分の設定へ変える際は両方を対応させてください。
接続関数はリポジトリ内のソースを参照します。npmパッケージの配布はまだ行っていません。

`createProtectedHandler`を自分のルーターに直接接続することもできます。
`authorize`と`readJson`を実装し、`binding`で同じアカウント内の非公開WorkerのService Bindingを返してください。
`readJson`はJSON文字列を返し、HTTP Responseを返しません。

認可結果はデータ読み取り前にコピー・固定します。未認証・拒否・非GETでは読み取りを呼びません。
認可・読み取り・接続が例外で失敗すれば固定の503を返します。ガードが返した403・429・503もそのまま返します。
呼出元は返されたResponseをそのまま送信し、別データ・Cookie・任意のヘッダーを追加しないでください。

`X-Tenant`等のクライアントヘッダーを認可情報にしないでください。未検査の検索結果から許可IDを作らないでください。
許可されたIDの決定が間違っていれば、その誤りはLeakFenceも許可します。
この接続関数はGET専用ですが、一回消費型GETには使用しないでください。処理済みの副作用を取り消せません。

## 5. 自分の検証環境へ非公開で配置する

同じアカウントのAPI Workerに追加するBindingの形は次です。`service`は自分の非公開ガード名に合わせてください。

```toml
[[services]]
binding = "LEAK_FENCE"
service = "leak-fence"
```

ガード側の`wrangler.toml`は既定で停止しています。レビューした`POLICIES_JSON`と`SERVICE_ENABLED`を設定し、
`workers_dev=false`、`preview_urls=false`、公開routesなしを維持します。
取得枠用のDO namespaceをAPI Workerへ直接渡さないでください。
CLIの成功だけで有効化せず、[運用手順](OPERATIONS.md)に沿って配置・停止・復旧を確認してください。
配置は利用者自身のCloudflareアカウントへ行い、基盤利用料はそのアカウントへ発生します。

自分の検証環境で、未認証、同じテナントの別人ID、別テナント、余計な項目、並行取得、障害、再起動を確認します。
キャッシュ、別ルート、例外処理からデータを直接返す経路がないことも点検します。
合成の専用APIでの接続成功は、実製品の認可や適用漏れの確認を代替しません。

## 本番へ進む条件

[実用化の条件](READINESS.md)と[信頼境界](THREAT_MODEL.md)を確認し、対象APIの責任者が判断してください。
既存の認可・DTO・DB制約だけで目的を満たせる場合、その構成を優先して構いません。
ガードの運用・遅延・誤拒否が防げる事故に見合うかを、自分のAPIで確かめる段階です。
