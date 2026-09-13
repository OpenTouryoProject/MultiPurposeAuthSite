# チートシート（認証デバイス）

**設定ファイルと起動の手順だけを並べたもの。** 理由・詳細は、各項のリンク先が一次情報。

- 設定すべきファイルの案内 → [`README.md`](README.md)
- 構成と落とし穴の背景 → [`ANALYSIS.md`](ANALYSIS.md)
- 認証サイト（MPAS）の起動 → [`../../CHEATSHEET.md`](../../CHEATSHEET.md) 4 節

> ここは**意図的に二重管理**している。手順は「思い出すため」に転記し、
> **判断が要ることは書かない。** 迷ったらリンク先を読むこと。

---

## 1. 設定ファイルの一覧

| ファイル | 中身 | git |
|---|---|---|
| `firebase_web.json` | Firebase の web 構成 ＋ VAPID キー | **`.gitignore` 済み。コミットしない** |
| `firebase_web.sample.json` | 上の項目名だけ（値は空） | コミットする |
| `mpas.core.json` | 接続先 `https://localhost:44300`（net10.0 版） | コミットする |
| `mpas.netfx.json` | 接続先 `https://localhost:44302`（net48 版） | コミットする |
| `android/app/google-services.json` | Android 用の Firebase 構成（**web 版では使わない**） | **追跡中のプレースホルダ。実物で上書きしない** |

サーバ側（参考）:

| ファイル | 中身 | git |
|---|---|---|
| `C:\root\files\resource\MultiPurposeAuthSite\FirebaseServiceAccountKey.json` | サーバが通知を送る鍵（サービス アカウントの秘密鍵）。取得 → 6 節 | リポジトリの外 |

**値は、この会話・Issue・コミットのどこにも貼らない。**

## 2. `firebase_web.json` を作る

```powershell
cd root\programs\authentication_device
Copy-Item firebase_web.sample.json firebase_web.json
```

値は Firebase コンソール（https://console.firebase.google.com/）から転記する。

| キー | コンソールでの場所 |
|---|---|
| `FIREBASE_API_KEY` | プロジェクトの概要 → アプリを追加（Web） → ニックネーム付与し登録 → Firebase SDK の追加の firebaseConfig  → `apiKey` |
| `FIREBASE_APP_ID` | 同 `appId`（**`…:web:…` の方。Android 用の `…:android:…` ではない**） |
| `FIREBASE_MESSAGING_SENDER_ID` | 同 `messagingSenderId` |
| `FIREBASE_PROJECT_ID` | 同 `projectId` |
| `FIREBASE_AUTH_DOMAIN` | 同 `authDomain` |
| `FIREBASE_STORAGE_BUCKET` | 同 `storageBucket` |
| `FIREBASE_MEASUREMENT_ID` | 同 `measurementId`（**無ければ `""` のまま**） |
| `FIREBASE_VAPID_KEY` | 1. Firebase コンソール → 歯車アイコン →「プロジェクトの設定」 2. 「Cloud Messaging」タブ 3. 下の方の「ウェブの構成」→「ウェブプッシュ証明書」4. 「鍵ペアを生成」を押す 5. 表示された「鍵ペア」の文字列（B で始まる長い文字列）をコピー |

※ 既存のアプリの場合：プロジェクトの概要 → アプリを選択（Web） → 歯車ボタンを押下 → マイアプリのSDK の設定と構成の firebaseConfig

```json
{
  "FIREBASE_API_KEY": "<apiKey>",
  "FIREBASE_APP_ID": "<appId>",
  "FIREBASE_MESSAGING_SENDER_ID": "<messagingSenderId>",
  "FIREBASE_PROJECT_ID": "<projectId>",
  "FIREBASE_AUTH_DOMAIN": "<authDomain>",
  "FIREBASE_STORAGE_BUCKET": "<storageBucket>",
  "FIREBASE_MEASUREMENT_ID": "",
  "FIREBASE_VAPID_KEY": "<鍵ペア>"
}
```

**必須は上の 4 項目**（`API_KEY` / `APP_ID` / `MESSAGING_SENDER_ID` / `PROJECT_ID`）。
欠けていると、web では Firebase を初期化せずに起動する（プッシュ無し）。

## 3. 接続先（`mpas.*.json`）

**認証サイトが実際に待ち受けている URL を書く。** 構成ファイルのルート URI とは限らない。

| 起動方法 | 接続先 | 渡すファイル |
|---|---|---|
| `test.ps1 -Launch` / Kestrel（ルート URI を環境変数で揃える） | `https://localhost:44300` | `mpas.core.json` |
| `test.ps1 -Launch` の net48 版（IIS Express） | `https://localhost:44302` | `mpas.netfx.json` |
| Visual Studio（IIS Express） | `https://localhost:44300/MultiPurposeAuthSite`（`../../CHEATSHEET.md` 4 節の既定値。**実測していない**） | 自分用のファイルを作る |
| ファイルを渡さない | `https://localhost:44300` | — |

実測（Kestrel、ルート URI を `https://localhost:44300` に揃えた場合）:

```
GET https://localhost:44300/.well-known/openid-configuration                        → 200
GET https://localhost:44300/MultiPurposeAuthSite/.well-known/openid-configuration   → 404
```

自分用のファイル（例）:

```json
{
  "MPAS_BASE_URL": "https://localhost:44300/MultiPurposeAuthSite"
}
```

**Android の実機からは `localhost` に届かない。** 実機から届く URL を書いたファイルを渡す。

## 4. サーバ側で対応している設定

| 設定 | 値 | 場所 | 設定要否 |
|---|---|---|
| web 版のクライアント | `client_name` = `AuthenticationDevice_Web`、`client_id` = `aad529f7f9b6428a84c59ac15aef0cdb`、`redirect_uri_code` = `http://localhost:5610/`、`client_secret` なし | `OAuth2ClientsInformation`（`_appsettings.json` / `_app.config` と、実際に読まれる `appsettings.json` / `app.config`） | 不要（埋込・設定済） |
| Android 版のクライアント | `client_name` = `Native_Application`、`redirect_uri` = `com.opentouryo:/oauthredirect`（アプリ側） | 同上 | 不要（埋込・設定済） |
| 通知を送る鍵 | `FirebaseServiceAccountKey` | 同上。既定のパスはリポジトリ外 `C:\root\files\resource\MultiPurposeAuthSite\` | 要設定 |

E2E テストは送信箱（`FcmOutboxDirectory`）を使うので、本物の FCM には送らない。

### 通知を送る鍵（`FirebaseServiceAccountKey.json`）を取得して置く

**CIBA の通知を確かめる直前に置く。** サインインの確認には使わない。

1. Firebase コンソール → 歯車アイコン →「プロジェクトの設定」
2. 「サービス アカウント」タブ
3. 「Firebase Admin SDK」の「新しい秘密鍵を生成」→ 確認ダイアログで「キーを生成」
   （コード例の言語はどれを選んでもよい。ダウンロードされる JSON は同じ）
4. ダウンロードされた `<プロジェクト名>-firebase-adminsdk-…json` を、名前を変えて上書きする

```powershell
Copy-Item <ダウンロードした JSON> C:\root\files\resource\MultiPurposeAuthSite\FirebaseServiceAccountKey.json
```

- **設定の変更は要らない。** net10.0 版・net48 版とも、実際に読まれる設定が既にこのパスを指している
- 認証サイトが起動中なら、置いた後に再起動する
- **プロジェクトの管理者権限に相当する秘密鍵。** リポジトリ・Issue・会話のどこにも置かない、貼らない
- 「新しい秘密鍵を生成」は、押すたびに**別の鍵を追加で発行する。**
  不要な鍵・漏れた疑いのある鍵は、Google Cloud コンソール → IAM と管理 → サービス アカウント →（対象）→ キー で削除する

## 5. 起動する

### 認証サイト（net10.0 版、PowerShell）

```powershell
cd root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:OAuth2AuthorizationServerEndpointsRootURI = 'https://localhost:44300'
$env:OAuth2ClientEndpointsRootURI = 'https://localhost:44300'
$exe = Get-ChildItem -Recurse bin\Debug -Filter MultiPurposeAuthSite.exe | Select-Object -First 1
& $exe.FullName --urls https://localhost:44300
```

**構成のルート URI と待ち受け URL を揃えること。** 理由 → [`../../CONFIGURATION.md`](../../CONFIGURATION.md) 5 節

### 認証デバイス

```powershell
cd root\programs\authentication_device

# web（サインイン ＋ プッシュ）
flutter run -d chrome --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

# web のビルド
flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

# Android（Android SDK が要る）
flutter build apk --debug --dart-define-from-file=<実機から届く接続先>.json
```

- **`--web-port 5610` は必須。** 認証サイトは `redirect_uri` を登録値（`http://localhost:5610/`）と完全一致で照合する
- **`--dart-define-from-file` の値は、ホット リロードでは変わらない。** ファイルを変えたら `flutter run` をやり直す
- **認可画面へ移ると、`flutter run` のターミナルとの接続が切れる。** 戻った後のログは Chrome の DevTools（F12 → Console）で見る

## 6. 組み合わせ早見表

| やりたいこと | 渡すファイル |
|---|---|
| 画面だけ動かす（プッシュ無し） | `mpas.core.json` |
| web でサインイン ＋ プッシュ（net10.0 版） | `firebase_web.json` ＋ `mpas.core.json` |
| web でサインイン ＋ プッシュ（net48 版） | `firebase_web.json` ＋ `mpas.netfx.json` |

## 7. よく踏む落とし穴

| 症状 | 原因 | 対処 |
|---|---|---|
| 「Firebase の web 構成が渡されていないため…」と出る | `firebase_web.json` を渡していない、または必須 4 項目が欠けている | 2 節 |
| `FCM Token` が出ない | VAPID キーが無い / 通知を拒否した / 古い service worker が残っている | 2 節 / 下の行 |
| 古い service worker が残る | 以前の `index.html` が `flutter_service_worker.js` を登録した | DevTools → Application → Service workers → Unregister |
| サインイン後、戻らずにエラー画面 | `--web-port 5610` で起動していない（`redirect_uri` の不一致） | 4 節 |
| 「トークン要求に接続できません」 | 接続先の誤り（`/MultiPurposeAuthSite` の有無）/ 証明書 / サイトが止まっている | 3 節 |
| 「トークン要求が失敗しました（HTTP 401）… invalid_client」 | PKCE での交換が拒否された（`code` の使用済みを含む） | サインインからやり直す |
| 認証サイトの URL が 404 | 起動方法と接続先ファイルが合っていない | 3 節 |
| 「16 packages have newer versions…」 | `firebase_core_web` を 3.10.x に固定している（#209） | 想定どおり。`pubspec.yaml` のコメント |
| Android から認証サイトに届かない | 接続先を渡していない（既定は `localhost`） | 3 節 |
