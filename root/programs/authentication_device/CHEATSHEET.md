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
| `C:\root\files\resource\MultiPurposeAuthSite\FirebaseServiceAccountKey.json` | サーバが通知を送る鍵（サービス アカウントの秘密鍵）。取得 → 4 節 | リポジトリの外 |

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
| IIS Express で起動した net48 版（5 節の手順） | `https://localhost:44302` | `mpas.netfx.json` |
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
|---|---|---|---|
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

### 認証サイト（net48 版、IIS Express、PowerShell）

`test.ps1 -Launch` と同じ形で起動する（サイトの直下に置き、`https://localhost:44302` で待ち受ける）。
**`test.ps1 -Launch` はテストが終わるとサイトを止めるので、手動の確認には使えない。**

```powershell
cd root\programs\MultiPurposeAuthSite\MultiPurposeAuthSite

# IIS Express の設定を、テンプレートから作る
$tmpl = Join-Path $env:ProgramFiles 'IIS Express\config\templates\PersonalWebServer\applicationhost.config'
$cfg  = Join-Path $env:TEMP 'mpas48.applicationhost.config'
[xml]$doc = Get-Content $tmpl -Raw
$site = $doc.configuration.'system.applicationHost'.sites.site | Where-Object { $_.name -eq 'WebSite1' }
$site.name = 'MPAS48'
$site.application.virtualDirectory.physicalPath = (Get-Location).Path
$site.bindings.binding.protocol = 'https'
$site.bindings.binding.bindingInformation = '*:44302:localhost'
$doc.Save($cfg)

# 構成のルート URI を、待ち受け URL に揃える
$env:OAuth2AuthorizationServerEndpointsRootURI = 'https://localhost:44302'
$env:OAuth2ClientEndpointsRootURI = 'https://localhost:44302'

& (Join-Path $env:ProgramFiles 'IIS Express\iisexpress.exe') "/config:$cfg" /site:MPAS48
```

- 先に net48 版をビルドしておく（`root\1_BuildAll.ps1`）
- 止めるときは、このターミナルで `Q` を押す
- Visual Studio でデバッグ実行すると `https://localhost:44300/MultiPurposeAuthSite/` になる（`MultiPurposeAuthSite.csproj` の `IISUrl`）。
  **net10.0 版（Kestrel）と同じポート**で、接続先も `mpas.netfx.json` とは違う（3 節の「自分用のファイル」）

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
| サインイン後、戻らずにエラー画面 | `--web-port 5610` で起動していない（`redirect_uri` の不一致） | 5 節 |
| 「トークン要求に接続できません」 | 接続先の誤り（`/MultiPurposeAuthSite` の有無）/ 証明書 / サイトが止まっている | 3 節 |
| 「トークン要求が失敗しました（HTTP 401）… invalid_client」 | PKCE での交換が拒否された（`code` の使用済みを含む） | サインインからやり直す |
| 認証サイトの URL が 404 | 起動方法と接続先ファイルが合っていない | 3 節 |
| 「16 packages have newer versions…」 | `firebase_core_web` を 3.10.x に固定している（#209） | 想定どおり。`pubspec.yaml` のコメント |
| Android から認証サイトに届かない | 接続先を渡していない（既定は `localhost`） | 3 節 |
| 自己テストが `JsonReaderException: Unexpected character … S` | 宛先（`tanaka@gmail.com`）に端末が登録されていない。`/ciba_authz` が例外の平文を返した | 8 節の前提 |
| OS の通知が出て、Message Stream に届かない | 通知が届いたとき、Flutter のタブが見えていなかった（重なっていた / 最小化していた） | 想定どおり。OS の通知をクリックする（8 節「バックグラウンドで確かめる」）か、8 節の手順 2 |
| OS の通知をクリックしても何も起きない | `flutter run -d chrome` が起動する Chrome（一時プロファイル）では、クリックの処理が呼ばれない | 8 節「バックグラウンドで確かめる」（普段の Chrome で開く） |
| Allow / Deny で `/ciba_result` が 400 | 要求の期限切れ、または宛先と違うユーザで応答した | 認証サイトでサインアウトし、`tanaka@gmail.com` でサインインし直す |
| Installability に「`name` が無い」「`display` が不正」「アイコンが無い」がまとめて出る | `flutter run` は manifest を生成しない（`manifest.json` は正しい） | 8 節「PWA としてインストールして確かめる」 |

## 8. CIBA を確かめる（web）

**前提**

- 認証サイトを 5 節の手順で起動してある（送信箱 `FcmOutboxDirectory` を指定しない＝本物の FCM に送る）
- 通知を送る鍵を置いてある（4 節）
- **自己テストの宛先は `tanaka@gmail.com` に固定。** 認証デバイスも `tanaka@gmail.com` でサインインする
  （パスワードは、実際に読まれる設定の `TestUserPWD`）
- **ユーザ ストアが `mem` のときは、認証サイトを起動し直すと、ユーザも端末の登録も消える。** 起動し直したら、サインインからやり直す

**手順**

1. 認証デバイスを起動し（5 節）、`tanaka@gmail.com` でサインインする →「Flutter My Page」
2. Flutter のウィンドウと、認証サイトのウィンドウを**重ならないように並べる**（Flutter のタブが見えている状態にする）
3. 認証サイト側で `https://localhost:44300/Home/Saml2OAuth2Starters` を開く（net48 版は `https://localhost:44302/…`。認証デバイスには `mpas.netfx.json` を渡す）
4. ClientType で **`fapi_ciba`** を選び、「**Test FAPI CIBA Profile (FAPI2)**」を押す（応答があるまで、読み込み中のまま待つ）
5. Flutter 側の Message Stream に「CIBA」が届いたらタップし、**Allow** または **Deny** を押す
6. 認証サイト側の画面が移る

| 押したもの | 移る先（net10.0 版） | 移る先（net48 版） |
|---|---|---|
| Allow | `…?ret=OK_NORMAL_END` | `…?ret=OK: 正常終了` |
| Deny | `…?ret=OK_ABNORMAL_END` | `…?ret=OK: 異常終了` |

- net48 版で実測したのは Allow（フォアグラウンド / バックグラウンド）。Deny の表記は、net48 版の `HomeController.cs` から

- 要求の期限は 600 秒（`CibaExpireTimeSpanFromSeconds`）。自己テストは期限まで `/token` を問い合わせ続け、**タブを閉じても止まらない**
- ログは Flutter のタブで F12 → Console（「ログを保持」にチェック）。フォアグラウンドで届くと「ローカル通知で擬似的に通知メッセージを表示」が出る

### バックグラウンドで確かめる（OS の通知のクリック）

**普段の Chrome で開く。** `flutter run -d chrome` が起動する Chrome（一時プロファイル）では、OS の通知をクリックしても何も起きない。

```powershell
cd root\programs\authentication_device
flutter run -d web-server --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
```

1. 普段の Chrome の**新しいウィンドウ**で `http://localhost:5610/` を開き、通知を許可して `tanaka@gmail.com` でサインインする
   （ブラウザが変わると、保存されたサインインは無い。端末の登録も、この Chrome のものに置き換わる）
2. アプリのウィンドウを最小化する
3. 別のウィンドウで、上の手順 3・4 のとおり自己テストを押す
4. OS の通知（CIBA）をクリックする → アプリが前面に出て、詳細画面が開く
5. Allow / Deny を押す → 自己テストの画面が移る（上の表）

- service worker を変えたときは、DevTools → Application → Service workers で「Update on reload」にチェックを入れて再読み込みする（古い版のまま動くことがある）

### PWA としてインストールして確かめる

**`flutter run` では確かめられない。** manifest を生成しないため、DevTools の Installability が
「`name` が無い」「`display` が不正」「アイコンが無い」とまとめてエラーになる（`manifest.json` 自体は正しい）。
**ビルドした出力（`build/web`）を配信する。**

```powershell
cd root\programs\authentication_device
flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
cd build\web
python -m http.server 5610
```

1. 普段の Chrome で `http://localhost:5610/` を開く（`redirect_uri` は同じなので、サインインもそのまま試せる）
2. アドレスバー右端のインストールのアイコン（または ⋮ →「キャスト、保存、共有」）からインストールする
3. アプリのウィンドウで、サインインと CIBA を試す（手順は上と同じ）

- **通知の経路は、アプリのウィンドウが見えているかどうかで決まる**（PWA でも同じ）。
  見えていれば Message Stream、最小化 / 隠れていれば OS の通知になる
- 通知をクリックすると、ブラウザのタブではなく**アプリのウィンドウ**が開く
- `python -m http.server` は更新の扱いが素朴なので、service worker が古いまま残ることがある（上の行）
- Installability に残る「Richer PWA Install UI …（screenshot を足すように）」は案内で、エラーではない

## 9. 2FA のプッシュ承認を確かめる（web、net10.0 版のみ）

**net48 版には `MobileApp` の 2FA プロバイダが無い**ので、確かめられるのは net10.0 版だけ（#213）。

**前提**

- 8 節と同じ（認証サイトを起動、通知の鍵を置く、`tanaka@gmail.com` で揃える）
- **2FA を有効にしてある。** 既定は無効（`TwoFactorEnabled` の既定が `"false"`）。
  認証サイトにサインインし、`/Manage/Index`（ユーザ情報の管理）の 2 要素認証の行で有効にする
  （`Config.CanEdit2FA` が true のときだけ出る）
- **認証デバイスで、同じ利用者のサインインを済ませてある**（`/SetDeviceToken` で端末が登録されている）。
  **端末が登録されていないと、プロバイダの選択肢に `MobileApp` が出ない**

**手順**

1. 認証サイトからサインアウトし、`tanaka@gmail.com` でサインインし直す
2. コードの送り先を選ぶ画面で **`MobileApp`** を選び、送信する
3. コードの入力画面（`VerifyCode`）が出る。**この画面のまま待つ**
   （画面は 2 秒ごとに `/Account/TwoFactorPushStatus` を見ている。手で入力して完了させることもできる）
4. 認証デバイスに「2FA」の通知が届く。開いて **Approve** を押す
5. ブラウザ側が承認を拾い、サインインが完了して戻り先へ移る

- **サインインを完了させるのはブラウザ側。** 2FA のセッションはブラウザの Cookie にあり、端末からは触れない。
  端末は「このコードを承認した」と送るだけ（`POST /2fa_result`）
- 承認はメモリに置き、**5 分で期限切れ**。1 回拾うと消える
- 待ち受けは **3 分で止まる**（そのあとは手入力で完了させる）
- 合わないコードは記録されない（`/2fa_result` は保存の前に検証する）。E2E : `RT-213.1`

> **この通しは実測済み**（2026-09-16、net10.0 版 ＋ PWA としてインストールした認証デバイス）。
> コードの入力画面が待ち受け、[Approve] を押すとサインインが完了した。
> E2E で測っているのは、サーバ側の失敗（401 / 400）だけ（`RT-213.1`）。
