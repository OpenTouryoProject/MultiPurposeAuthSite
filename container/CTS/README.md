# 適合性テスト（Conformance Suite）— `container\CTS\`（#350）

**OpenID Foundation の Conformance Suite（適合性テスト）を手元で起動し、MPAS（net10.0 版）を相手に回す**（`ANALYSIS-IdP.md` の **D-14**）。
**外部の基準を、最終的な正とする**（`QUALITY.md` 2 節）。E2E は、このリポジトリが書いたテストなので、書いた側と同じ読み違いを共有しうる。

- 原本：https://gitlab.com/openid/conformance-suite（ビルド済みのイメージ。`docker-compose-prebuilt.yml` を元にした）
- **版は固定する**（`release-v5.3.4`）。上げるときは、`docker-compose.yml` の server と nginx のタグを、同じ版に手で上げる
- **認定（certification）を取るためのものではない。** 手元で回して、不適合を見つけて直すためのもの

## 手順

```powershell
cd container\E2E
.\1_PublishIdP.ps1          # OP の発行物と証明書（E2E と共用。MPAS を直したら、先にこれ）

cd ..\CTS
.\2_DockerComposeUp.bat     # Conformance Suite と OP を起動する（Conformance Suite の起動には 1〜2 分かかる）
.\RunTestPlan.ps1 -Plan oidcc-basic    # プランを回す（oidcc-basic / oidcc-config）
.\3_DockerComposeDown.bat   # 止める
```

| | URL |
|---|---|
| Conformance Suite（画面） | https://localhost.emobix.co.uk:8443/ （結果の一覧・各モジュールのログ） |
| OP（issuer） | https://mpas-cts.localhost:44311 |
| Discovery | https://mpas-cts.localhost:44311/.well-known/openid-configuration |

- **メモリを使う**（Java の server・MongoDB・nginx・OP）。**要らないコンテナ（`..\E2E\`・`..\Store\`）は止めておく**
- **server は、MongoDB が応答してから起動する**（`healthcheck`）。`mongo\` は Windows のフォルダなので、MongoDB が開くのに 1 分ほどかかることがあり、server は 30 秒で諦めて終了していた
- **hosts の編集は要らない。** `localhost.emobix.co.uk` は公開の DNS が 127.0.0.1 を返し、`mpas-cts.localhost` は Edge・Chrome が 127.0.0.1 に向ける（RFC 6761）
- OP の証明書は localhost 向けの開発用のもの（E2E と共用）なので、**ブラウザで OP を開くと、名前の不一致の警告が出る**（進んでよい）

## 仕組み

### 名前とポート

**issuer は、ブラウザと Conformance Suite の両方から、同じ URL で届くこと**が要る（OIDC Discovery 1.0 §4.3。Discovery を取った URL と `iss` が一致すること）。

| 名前 | ブラウザ（手元の PC） | Conformance Suite（コンテナ） |
|---|---|---|
| `localhost.emobix.co.uk`（Conformance Suite） | 公開の DNS が 127.0.0.1 を返す | nginx のネットワークの別名 |
| `mpas-cts.localhost`（OP） | Edge・Chrome が `*.localhost` を 127.0.0.1 に向ける | op のネットワークの別名（Java の名前解決で、OP のコンテナに届くことを確かめた） |

- **E2E の upstream（`https://localhost:44301`）は使えない** — Conformance Suite のコンテナから見ると、`localhost` は自分自身を指す
- **ポートは、中と外で同じにする**（44311）。違うと、issuer の URL がどちらかで届かない
- **`IssuerId` を、Discovery の URL と同じ値にしてある**（雛形の `IssuerId` は論理名で、URL と違う。そのままだと Discovery の検査で落ちる）
- `curl` は `*.localhost` を自分で 127.0.0.1 に向ける（DNS に問わない）ので、**コンテナの中から `curl` で確かめるときは `--resolve` を付ける**

### 登録と、テスト利用者

| | 置き場所 |
|---|---|
| クライアント（`client`・`client2`。`client_secret_basic`） | `docker-compose.yml` の OP の環境変数（**適合性テスト専用の値**。E2E の `docker-compose.yml` と同じ扱い） |
| クライアント（`client_secret_post`。`oidcc-server-client-secret-post` が使う） | 同上（3 つ目。設定の `"client_secret_post"`。静的な登録では、認証の方式ごとにクライアントを分けて渡す作り） |
| 折り返し先 | `https://localhost.emobix.co.uk:8443/test/a/mpas-cts/callback`（`alias` は設定の `"alias"` と同じ） |
| テスト利用者 | OP の種データが作る一般の利用者（`tanaka` ＋ `TestUserSuffix`）。**パスワードは手元の `appsettings.json` の `TestUserPWD`** |

### 設定（`config\*.json`）と、ブラウザの自動操作

**サインインと同意は、Conformance Suite の server がブラウザを自動で操作して行う**（設定の `"browser"`。原本の試験用の設定と同じ書き方）。

| 画面 | 操作 |
|---|---|
| サインイン（`/Account/Login`） | `Email`・`Password` の欄を埋め、`normal_signin` を押す |
| 同意（`/authorize`） | `submit.Grant` を押す（**同意を記録した後は出ない**ので、任意の手順にしてある） |
| 折り返し（`/test/*/callback`） | Conformance Suite の完了の印（`submission_complete`）を待つ |

- **テスト利用者の名前とパスワードは、雛形では差し込み口**（`@TEST_USER@`・`@TEST_PASSWORD@`）である。
  `RunTestPlan.ps1` が手元の `appsettings.json` から埋めて、**`out\<プラン>.json` に書く**（`out\` は Git の管理外）
- 画面から回すときは、`out\<プラン>.json` を貼る

**画面の写し（REVIEW）を求めるモジュールは、モジュールごとの `"override"` で、そのときの画面を写しの代わりにする**（原本の CI の設定 `.gitlab-ci/local-provider-oidcc-conformance-config.json` と同じ書き方）。
`wait` のコマンドの末尾に `update-image-placeholder`（無くてもよいなら `-optional`）を付けると、待った画面で写しの欄が埋まる。
**埋まらないと、モジュールは `WAITING` のまま止まり、`RunTestPlan.ps1` が時間切れにする**（次のモジュールが同じ `alias` を取るので、打ち切られる）。

| モジュール | 待つ画面（文言） |
|---|---|
| `oidcc-prompt-login`・`oidcc-max-age-1` | 2 回目の認可のサインイン（`Use a local account to sign in.`） |
| `oidcc-ensure-registered-redirect-uri` | 登録の無い `redirect_uri` のエラー画面（`Invalid redirect_uri`） |

- **REVIEW は、写しを人が見て合否を付ける項目である。** 自動では、待った画面が出たことまでしか確かめていない

### `RunTestPlan.ps1`

**原本の `scripts\run-test-plan.py` と同じ REST の API を、PowerShell で呼ぶ**（Python と追加のパッケージを要らなくした）。
Conformance Suite は dev の構成なので、**API は認証なしで呼べる**。

| 段 | API |
|---|---|
| プランを作る | `POST api/plan?planName=…&variant=…`（本文は設定の JSON） |
| モジュールを起動する | `POST api/runner?test=…&plan=…`（**本文が無くても `Content-Type: application/json` が要る**。無いと 415） |
| 待つ・結果を読む | `GET api/info/{id}`（`status` が `FINISHED`・`INTERRUPTED` になるまで。**上限は `-ModuleTimeoutSec`**。ブラウザの自動操作が合わないと `WAITING` のまま止まる） |
| 報告書 | `GET api/plan/exporthtml/{id}`（zip。**`api/plan/{id}/exporthtml` は 404**。release-v5.3.4 で確かめた） |

- 終了コード：0（FAILED・INTERRUPTED・時間切れが無い）／1（どれかがある）／2（前提の誤り）
- **WARNING・REVIEW は失敗に数えない**（Conformance Suite の判定のまま、結果に出す）
- PowerShell 5.1・7 の両方で動く（自己署名の証明書の扱いを分けている。`root\CODING.md` 5 節）

## 生成物（Git の管理外）

| フォルダ | 中身 |
|---|---|
| `mongo\` | Conformance Suite の結果（MongoDB のデータ）。**消すと、画面の一覧も消える** |
| `keys\`・`logs\` | OP の DataProtection の鍵とログ |
| `out\` | 実行用の設定（**テスト利用者のパスワードを埋めたもの**）と、結果の JSON・報告書の zip |
