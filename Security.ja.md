# セキュリティ ポリシー

このファイルの英語版は[こちら](SECURITY.md)から。

## 本リポジトリの位置付け

**汎用認証サイトは IdP / STS のリファレンス実装であり、テンプレートである。**
読み、動かし、カスタマイズして使うことを前提にしている
（[`license/LicenseForTemplates.ja.txt`](license/LicenseForTemplates.ja.txt)）。

**既定の設定は評価用であり、本番用ではない。** 初期状態では、
ユーザ ストアがインメモリで、テスト ユーザを作成し、Implicit と ROPC のグラント種別が有効で、
リダイレクト URI に予約値を使うテスト用クライアントが登録されている。
**本リポジトリから派生させた環境の堅牢化は、構築者の責任である。**

「配布時の既定設定が本番向けに堅くない」という趣旨の報告は既知である
（[既知であり、意図的なもの](#既知であり意図的なもの)を参照）。
**コードそのものに対して具体的な攻撃が成立することを示す報告**は歓迎する。

## 対象バージョン

**セキュリティ修正は、`develop` と最新のリリース系統にのみ適用する。**

| バージョン | 対象 |
|---|---|
| `develop` | :white_check_mark: |
| `02-00` | :white_check_mark: |
| `01-99` 以前 | :x: |

## 脆弱性の報告

**セキュリティに関する問題を、公開の Issue に書かないでください。**

**[Private vulnerability reporting](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/security/advisories/new)**
を使ってください。修正が公開されるまで非公開のまま扱われ、やり取りも同じ場所で行えます。

報告には次を含めてください。

- **どの構成要素か**（[対象範囲](#対象範囲)の表の区分）
- **どのターゲット フレームワークか**（`net48` / `net10.0`）。
  両者は共通ライブラリを使う**別のアプリケーション**であり、
  **片方にしか存在しない問題**があり得る
- **どの設定でか**（関係する場合）。`UserStoreType`、有効にしたグラント種別、
  クライアントの `subject_types` など
- 再現手順、または問題があると考えるコード パス
- **攻撃者が何を得られるか。** どのトークンか、誰のアカウントか、前提条件は何か

少人数で開発しているため、**受領と対応方針は連絡しますが、期限の確約はできません。**

## 対象範囲

| パス | 範囲 |
|---|---|
| `root/programs/CommonLibrary/` | **対象。** 実装の大半はここに在る（ASP.NET Identity のストア、OAuth 2.0 / OIDC / SAML2 のプロトコル実装）。**2 つのアプリが共有する** |
| `root/programs/MultiPurposeAuthSiteCore/` | **対象。** 主要部（ASP.NET Core MVC / net10.0） |
| `root/programs/MultiPurposeAuthSite/` | **対象。** 下位互換版（ASP.NET MVC5 + OWIN / net48） |
| `root/programs/CommandLineTools/` | **対象。** クライアント資格情報と JWK Set を生成する |
| `root/programs/authentication_device/` | サンプル（Flutter）。**報告は歓迎する**が、CIBA とプッシュ 2FA の相手方として用意したテスト用であり、配布物ではない |
| `root/files/resource/X509/` | **対象外。** **テスト専用**の自己署名証明書と秘密鍵。パスフレーズが `test` なのは意図的 |
| `_appsettings.json` / `_app.config` | **対象外。** これらはテンプレートであり、含まれる `client_id` / `client_secret` / JWK は**サンプル値**。実ファイル（`appsettings.json` / `app.config`）は `.gitignore` 対象 |
| `store/` | **対象外。** 開発用 DB を立てる `docker-compose` 一式。パスワードは固定値 |

本サイトが土台にしているフレームワークは別リポジトリである。
`OpenTouryo.*` の問題は、そちらへ報告してください。
**https://github.com/OpenTouryoProject/OpenTouryo/security/advisories/new**

## 既知であり、意図的なもの

**IdP 実装のプロトコル適合性については調査を実施し、結果を記録済みである。**
報告の前に、次を確認してください。

- **[`root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md`](root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md)**
  … ファイルと行番号を伴う一覧
- Issue **[#182](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/182)** 〜
  **[#189](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/189)**
  … 起票済みのもの

次は既知であり、意図的なものである。

- **`_appsettings.json` のテスト用クライアントは、予約値
  `test_self_code` / `test_self_token` をリダイレクト URI に使う。**
  サイトが自分自身のクライアントとして動作するために用意している。
  `IsLockedDownRedirectEndpoint` で閉じられる
- **`IsDebug: true` は、`/Account/Login` への初回アクセス時にテスト ユーザを作成する。**
  開発用の設定である
- **Implicit と ROPC が既定で有効**（`EnableImplicitGrantType` /
  `EnableResourceOwnerPasswordCredentialsGrantType`）。
  既定値を OAuth 2.1 に合わせる件は、別途で扱う
- **FIDO / WebAuthn は現在ビルド対象外である。**
  `CommonLibrary/Extensions/FIDO/**` は両プロジェクトから除外され、呼び出し側もコメント アウト済み。
  設定キーと View は残っているが、機能しない

**上記について具体的な攻撃が成立することを示す報告**は、引き続き歓迎する。

## 本リポジトリでの取り組み

| | |
|---|---|
| Private vulnerability reporting | 有効 |
| Dependabot alerts / security updates | 有効 |
| Secret scanning ＋ Push protection | 未設定 |
| Code scanning（CodeQL） | 未設定 |
| ブランチ保護（`master`） | レビュー 1 名必須 |
| ブランチ保護（`develop`） | force push と削除を禁止 |

設定の実体は GitHub 側にあり、**リポジトリのファイルからは見えない**ため、ここに記録する。
