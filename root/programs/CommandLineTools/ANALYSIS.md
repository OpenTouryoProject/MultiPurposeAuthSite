# ANALYSIS.md — 汎用認証サイト ツール部（CommandLineTools）コード分析

対象: `root/programs/CommandLineTools`（**net10.0 / net48 の 2 系統**） / ブランチ: `develop`
最終更新: 2026-09-07

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。

関連: [`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md)、
[`../MultiPurposeAuthSiteCore/ANALYSIS.md`](../MultiPurposeAuthSiteCore/ANALYSIS.md)、
[`../MultiPurposeAuthSite/ANALYSIS.md`](../MultiPurposeAuthSite/ANALYSIS.md)。

---

## 1. これは何か

**汎用認証サイトの設定値を「手で書くのは無理な形式」で作るための、使い捨てのコンソール ツール 3 本。**
いずれも `Main` に処理がベタ書きで、引数を取らず、標準出力かファイルに結果を出して終わる。

- 本体（Web アプリ）からは参照されない。**開発者が単発で叩くもの。**
- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**

規模の目安: `Program.cs` 3 本で合計 352 行。

---

## 2. 3 本のツール

| ツール | 何を作るか | 出力先 | 参照する設定キー |
|---|---|---|---|
| **`CreateClientsIdentity`** | OAuth2 クライアント定義（`client_id` / `client_secret` / `redirect_uri_*` / `client_name`）の雛形を **5 件**生成 | 標準出力（JSON、Indented） | なし（`appsettings.json` は `"xxx": "xxx"` のダミー） |
| **`CreateJwkSetJson`** | X.509 証明書（`.cer`）から **JWK Set（`/jwkcerts` が返す `JwkSet.json`）** を生成・追記 | `JwkSetFilePath` のファイル | `SpRp_RsaCerFilePath` `SpRp_EcdsaCerFilePath` `JwkSetFilePath` |
| **`CreateJwtBearerTokenFlowAssertion`** | **JWT Bearer Token Flow 用の JWK 鍵と Jwt Assertion** を生成し、その場で検証して表示 | 標準出力 | `SpRp_RsaPfxFilePath` / `SpRp_RsaPfxPassword` / `SpRp_EcdsaPfxFilePath` / `SpRp_EcdsaPfxPassword` / `SpRp_Isser` / `OAuth2AndOidcAudience` |

### 2.1 `CreateClientsIdentity`

`Guid.NewGuid().ToString("N")` を client_id、
Open棟梁の `GetPassword.Base64UrlSecret(32)` を client_secret にして 5 件ぶんの JSON を吐く。
**出力をそのまま `appSettings:OAuth2ClientsInformation` に貼る**のが使い方。

```json
{ "<guid>": { "client_secret": "...", "redirect_uri_code": "http://hogehoge0/aaa",
              "redirect_uri_token": "http://hogehoge0/bbb", "client_name": "hogehoge0" }, ... }
```

`redirect_uri_*` と `client_name` は `hogehoge{i}` の固定値なので、**貼った後に手で直す。**
`subject_types` / `oauth2_oidc_mode` / `jwk_*_publickey` / `tls_client_auth_subject_dn` は
生成されないので、必要なら手で足す
（[`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) 7.3 節）。

### 2.2 `CreateJwkSetJson`

```
SHA256RSA_Server.cer   ──RsaPublicKeyConverter.X509CerToJwk──┐
                                                             ├→ JwkSet.json（既存があれば kid で重複確認して追記）
SHA256ECDSA_Server.cer ──EccPublicKeyConverter.X509CerToJwk──┘
```

- ファイルが無ければ `File.Create` で新規、あれば `JwkSet.LoadJwkSet` → `AddJwkToJwkSet` → `SaveJwkSet`。
- **署名用の証明書を差し替えたら、必ずこれを流し直す。**
  流し忘れると `/jwkcerts` が古い鍵を返し、RP 側でトークン検証が通らなくなる。
- 既定の出力先は `C:/root/files/resource/MultiPurposeAuthSite/JwkSet.json`
  （本リポジトリにコミット済み）。

### 2.3 `CreateJwtBearerTokenFlowAssertion`

`.pfx`（クライアント証明書）から RS256 / ES256 の JWK 秘密鍵・公開鍵と Jwt Assertion を作り、
**その場で `JwtAssertion.Verify` して iss / aud が一致することを確かめてから表示する。**

> **ES256 の秘密鍵 JWK は出力されない。**
> `ECDsa.ExportParameters(true)` が動かないため該当ブロックはコメント アウトされており、
> ES256 側は `JwtAssertion.CreateByECDsa` に `.pfx` を直接渡す形に切り替えてある。
> RS256 側だけ秘密鍵 JWK が出る、という非対称はこの制約による。

---

## 3. プロジェクト構成（1 つのソースを 2 系統でビルド）

```
CommandLineTools/
├─ CommandLineTools.sln          … net48 の 3 プロジェクト（旧形式 csproj）
├─ CommandLineToolsCore.sln      … net10.0 の 3 プロジェクト（SDK 形式）
├─ CreateClientsIdentity/
│   ├─ Program.cs                ← ★実体はここ 1 本
│   ├─ net/     CreateClientsIdentity.csproj + App.config + Properties/AssemblyInfo.cs
│   └─ netcore/ CreateClientsIdentity.csproj + appsettings.json
├─ CreateJwkSetJson/             （同じ形）
└─ CreateJwtBearerTokenFlowAssertion/（同じ形）
```

**`Program.cs` は親ディレクトリに 1 本だけ置き、両方の csproj から取り込む。**

```xml
<!-- netcore（SDK 形式） -->
<Compile Include="..\Program.cs" Link="Program.cs" />
<!-- net（旧形式） -->
<Compile Include="..\Program.cs" />
```

`../CommonLibrary` の「同じディレクトリを 2 つの csproj で舐める」方式とは別で、
**こちらは「1 ファイルを 2 プロジェクトが共有する」方式**である。

### 3.1 条件シンボルが `../CommonLibrary` と違う（要注意）

| | net48 | net10.0 |
|---|---|---|
| `DefineConstants` | `TRACE;DEBUG;NET` / `TRACE;NET` | `TRACE;DEBUG;NETCORE` / `TRACE;NETCORE` |
| `Program.cs` の分岐 | — | `#if NETCORE` … `GetConfigParameter.InitConfiguration("appsettings.json")` |

- **net48 側は `NETFX` ではなく `NET` を定義する。**
  `../CommonLibrary` は `NETFX` / `NETCORE` なので、**シンボル体系が揃っていない。**
  `Program.cs` を `../CommonLibrary` から流用するときは `#if NETFX` が効かないので注意。
- `#if NETCORE` の中身は `GetConfigParameter.InitConfiguration("appsettings.json")` の 1 行だけ。
  net48 は `App.config` の `<appSettings>` を `System.Configuration` が自動で読むため不要。

### 3.2 設定ファイル

| | net48 | net10.0 |
|---|---|---|
| ファイル | `net/App.config` | `netcore/appsettings.json`（`CopyToOutputDirectory=Always`） |
| セクション | `<appSettings>` | `"appSettings"` |
| パス区切り | `\`（`C:\root\files\...`） | `/`（`C:/root/files/...`） |

**キー名は共通なので、設定を足すときは 2 ファイルとも直す。**
なお、この設定ファイル群は `.gitignore` の対象外（＝git 管理下）であり、
入っているのはテスト用証明書のパスとパスワード `test` だけである。

### 3.3 依存

| | net48 | net10.0 |
|---|---|---|
| Open棟梁 | `../OpenTouryoAssemblies/Build_net48/*.dll`（`HintPath`） | `../OpenTouryoAssemblies/Build_netcore100/net10.0/*.dll`（`HintPath`） |
| JSON | `Newtonsoft.Json`（**`Build_net48` から `HintPath`**） | `Newtonsoft.Json` 13.0.4（`PackageReference`） |
| 構成 | `System.Configuration` | `Microsoft.Extensions.Configuration.{Abstractions,FileExtensions,Json}` 10.0.1 |
| 暗号 | — | `BouncyCastle.NetCore` 2.2.1（`CreateJwkSetJson` / `CreateJwtBearerTokenFlowAssertion`） |

**`OpenTouryoAssemblies/` は `.gitignore` 対象。** 先に用意すること
（[`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) 11.1 節）。

---

## 4. ビルドと実行

```
# net10.0
dotnet build CommandLineToolsCore.sln
dotnet run --project CreateJwkSetJson/netcore/CreateJwkSetJson.csproj

# net48（MSBuild が要る）
../10_MultiPurposeAuthSite.bat        ← nuget restore → MSBuild で CommandLineTools.sln
```

`../10_MultiPurposeAuthSiteCore.bat` は `dotnet restore` → `dotnet msbuild` で
`CommandLineToolsCore.sln` をビルドする（Web アプリのビルドの前段）。

### 4.1 現状のビルド結果（実測 2026-09-07）

`dotnet build CommandLineToolsCore.sln` … **0 エラー / 0 警告**（3 プロジェクトとも）。

---

## 5. 落とし穴 / 既知の不整合

1. **条件シンボルが `NET` で、`../CommonLibrary` の `NETFX` と揃っていない**（3.1 節）。
2. **`net/App.config` の `bindingRedirect` が古い。**
   3 本とも `Newtonsoft.Json` を `newVersion="11.0.0.0"` にリダイレクトしているが、
   csproj の `<Reference>` は `Version=13.0.0.0` を指している（`SpecificVersion=False`）。
   net48 側で `Newtonsoft.Json` の型解決に失敗したらここを疑う。
3. **どのツールも `Console.ReadLine()` で入力待ちに入る**（`CreateJwkSetJson` を除く）。
   CI やスクリプトから無人で回すと止まる。**エージェントが起動する場合は標準入力を与えること。**
4. **`CreateClientsIdentity` の出力は雛形にすぎない。** `redirect_uri_*` は `hogehoge{i}` 固定、
   FAPI / CIBA / Device 用のキーは出ない（2.1 節）。
5. **`CreateJwkSetJson` は追記型。** 既存の `JwkSet.json` に `kid` 重複確認のうえ足す。
   鍵をローテーションすると古い `kid` も残るので、消したいときは手で編集する。
6. **`CreateJwtBearerTokenFlowAssertion` は ES256 の秘密鍵 JWK を出さない**（2.3 節）。
7. **`.vs/` `bin/` `obj/` が作業ツリーに残る。** `.gitignore` 済み。

---

## 6. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] `Program.cs` は 1 本を 2 系統が共有している。**片方だけを想定した変更をしない**
- [ ] 条件コンパイルは `#if NETCORE`（`NETFX` は定義されていない）
- [ ] 設定を足したら **`net/App.config`（`\` 区切り）と `netcore/appsettings.json`（`/` 区切り）の両方**
- [ ] net48 側でファイルを増やしたら `net/*.csproj` に `<Compile Include>` を追記する
- [ ] 新規 `.cs` にはヘッダ コメント（Apache License ＋ クラス名・日本語名・更新履歴）を付与。
      既存 `.cs` の変更時は更新履歴に 1 行追記
- [ ] ビルド確認: `dotnet build CommandLineToolsCore.sln`（**0 警告を維持する**）
- [ ] 証明書まわりを触ったら、`CreateJwkSetJson` を流し直す必要があるかを報告する
