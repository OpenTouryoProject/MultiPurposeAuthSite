# MPAS スタブ（テスト用の IdP コンテナ）

**Open棟梁 や、その他のクライアントのテストから、MPAS を IdP のスタブとして起動する**ためのもの（#294）。
OAuth2 / OIDC / SAML2 の IdP として動く（**中身は net10.0 版の MPAS そのもの**で、応答を偽装するスタブではない）。

**E2E 用の `..\E2E\` とは別のもの**である。プロジェクト名（`mpas-stub`）・ポート（既定 44310）・鍵の置き場を分けてあり、
**同じホストで E2E のコンテナと同時に動かせる。**

## 1. 使い方

**前提** : Docker（compose v2）、.NET 10 SDK、`root\Readme.ja.md` の手順で用意したリソース（`C:\root\files\resource`）、
OpenTouryo のアセンブリ（`root\1_BuildAll.ps1` が取得する）。

```powershell
cd Container\Stub
.\1_PublishStub.ps1                                    # publish と証明書（最初と、MPAS を更新したとき）
copy .env.sample my-stub.env                           # パラメタを写して直す（下の 2 節・3 節）
docker compose --env-file my-stub.env up -d --build    # 起動
docker compose --env-file my-stub.env down             # 止めて消す（状態は残らない）
```

**起動の確認** : `https://localhost:44310/.well-known/openid-configuration` が 200 を返せばよい。

**このディレクトリに置く自分のファイルは `my-` で始める**（`my-stub.env`・`my-stub.json` など）。
**`.gitignore` 済みなので、テスト用の秘密を書いてもコミットされない。** 他の名前にすると追跡の対象になる。

## 2. パラメタ（`.env`）

**`docker compose --env-file <ファイル>` で渡す。** 書いていないキーは `docker-compose.yml` の既定値になる。
**相対パスは `Container\Stub\`（`docker-compose.yml` の在る所）から見たもの。**

| キー | 既定 | 意味 |
|---|---|---|
| `STUB_PORT` | `44310` | ホストに公開するポート |
| `STUB_PUBLIC_URL` | `https://localhost:44310` | **公開 URL**（Discovery の各口がこれで書かれる）。**ポートを変えたら、ここも変える** |
| `STUB_ISSUER` | `https://localhost:44310` | **名乗る `iss`**。**RP の期待する issuer と揃える** |
| `STUB_SETTINGS` | `./appsettings.Stub.sample.json` | **アプリの設定の JSON**（3 節） |
| `STUB_ADMIN_UID` / `STUB_ADMIN_PWD` | テスト用の値 | 管理者 |
| `STUB_TEST_USER_PWD` | テスト用の値 | **テスト利用者**（`super_tanaka@example.com` / `tanaka@example.com`）のパスワード |
| `STUB_LOCKDOWN_TEST_ENDPOINTS` | `false` | テスト用の口（自己テストの画面など）を閉じるなら `true` |
| `STUB_CERT_DIR` / `STUB_CERT_ENV_FILE` | `./cert` / `./cert/cert.env` | HTTPS の証明書（4 節） |
| `STUB_RESOURCE_DIR` | `C:/root/files/resource` | 署名鍵などのリソース |

**値はテスト専用にすること。** 管理者・テスト利用者・`client_secret` は、テストのためだけに使う値を書く。

## 3. アプリの設定（JSON）

**`appsettings.json` と同じ書き方**の JSON を、`STUB_SETTINGS` で指す（コンテナに `appsettings.Stub.json` として渡る）。
**雛形（`_appsettings.json`）の値に重ねて効き、書いたキーだけが変わる。** 例は `appsettings.Stub.sample.json`。

**テストする RP / SP のクライアントは、ここで登録する**（`OAuth2ClientsInformation`。キーは 32 桁の 16 進の client_id）。

| 項目 | 意味 |
|---|---|
| `client_secret` | 秘密 |
| `redirect_uri_code` | 認可コード フローの戻り先。**登録値と 1 文字も違ってはならない** |
| `redirect_uri_token` | Implicit の戻り先（使わなければ `-`） |
| `redirect_uri_saml` | SAML2 の ACS（使わなければ省く） |
| `client_name` | 名前 |

ほかの項目と、機能の切り替え（`EnableDynamicClientRegistration` など）は `root\CONFIGURATION.md` を参照。

**既存の `appsettings.json` を丸ごと渡してもよい**（`STUB_SETTINGS` にそのパスを書く）。
**雛形のキーはすべて上書きされる**（雛形に配列は無いので、要素が残ることもない）。**イメージには入らない**（起動時にマウントするだけ）。
ただし、**次の値は環境変数が勝つので、そこに書いても変わらない。**

| 値 | 決めているもの |
|---|---|
| 公開 URL・`IssuerId`・管理者・`TestUserPWD`・テスト用の口 | `.env` の `STUB_*` |
| `UserStoreType` | **常に `mem`** |
| リソースのパス（19 件）と log4net の構成 | `..\Common\mpas-common.env`（`C:/root/files/...` をコンテナの `/resource` へ振り替える） |
| `DataProtectionKeyPath` | `/keys` |

**この 19 件のほかに Windows のパスを書いた設定があると、その機能はコンテナの中では動かない。**

> **`docker-compose.yml` の `environment` に在るキー（公開 URL・`iss`・管理者など）は、JSON では変えられない**
> （環境変数の方が強い）。**それらは `.env` で変える。**

## 4. 証明書

**既定は、ホストの開発用証明書**（`dotnet dev-certs`）を `1_PublishStub.ps1` が書き出したもの。
**同じホストで動くテストなら、警告なしで信頼できる**（作り直すなら `.\1_PublishStub.ps1 -NewCertificate`）。

**自分の証明書を使う**なら、`aspnetapp.pfx` を置いたディレクトリを `STUB_CERT_DIR` に、
`Kestrel__Certificates__Default__Password=<パスワード>` の 1 行を書いたファイルを `STUB_CERT_ENV_FILE` に指定する。

## 5. 他のリポジトリから使う

**`-f` で `docker-compose.yml` を指せば、どこからでも起動できる。** パラメタのファイルは、使う側のリポジトリに置いてよい。

```powershell
docker compose -f C:\MultiPurposeAuthSite\Container\Stub\docker-compose.yml --env-file .\mpas-stub.env up -d --build
```

**`--env-file` の中の相対パスは `Container\Stub\` から見たもの**なので、使う側のファイル（`STUB_SETTINGS` など）は**絶対パス**で書く。
**同じホストで 2 つ以上動かす**なら、`-p <プロジェクト名>` と `STUB_PORT` を分ける（鍵の置き場 `keys\` は共有になる）。

## 6. 知っておくこと

| 項目 | 内容 |
|---|---|
| **状態は残らない** | `UserStoreType=mem`。**再起動で、利用者・同意・セッション・管理画面で足した登録が消える**（テストのたびにまっさらで始まる） |
| **net10.0 版だけ** | net48 版に固有の振る舞いは再現しない |
| **コンテナ間** | **別のコンテナで動く RP からは `localhost:44310` に届かない**（証明書の名前も合わない）。`..\E2E\docker-compose.yml` の上流・下流のように、宛先と公開 URL を分ける工夫が要る |
| **異常系** | 本物の IdP なので、任意のエラー応答は返せない（同意の拒否・`prompt=none`・期限切れなど、自然に出るものは出せる） |
| **イメージの中身** | **`appsettings.json` は雛形**（開発者の手元の設定は入らない）。署名鍵などはマウントで渡し、イメージに焼かない |
