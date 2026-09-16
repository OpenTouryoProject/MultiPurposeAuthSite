# ANALYSIS.md — 汎用認証サイト 認証デバイス部（authentication_device / Flutter）コード分析

対象: `root/programs/authentication_device`（**Flutter / Dart**） / ブランチ: `develop`
最終更新: 2026-09-14

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。

関連: [`../MultiPurposeAuthSiteCore/ANALYSIS.md`](../MultiPurposeAuthSiteCore/ANALYSIS.md)、
[`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md)。
使い方（設定の埋め方）は本ディレクトリの [`README.md`](README.md) が一次情報。

---

## 1. これは何か

**汎用認証サイトの「認証デバイス」として振る舞う Flutter アプリ。**
本リポジトリで唯一の非 .NET 資産であり、次の 2 つを担う。

1. **プッシュ通知の宛先になる。** Android のネイティブ アプリ、または web（PWA。#205）として OAuth2 認可コード グラント（PKCE）で
   サインインし、取得したアクセス トークンで FCM のデバイス トークンを認証サイトへ登録する。
2. **CIBA（Client Initiated Backchannel Authentication）の承認端末になる。**
   認証サイトから届くプッシュに「Allow / Deny」で応答する。

> **位置付けはサンプル / テスト用。** `../MultiPurposeAuthSiteCore` の CIBA・プッシュ 2FA を
> 実機で確かめるための相手方であり、製品ではない。

- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**

規模の目安: `lib/` の `.dart` 20 ファイル / 約 1280 行。

---

## 2. 認証サイト側との対応

| このアプリが叩くもの | 認証サイト側 | 定義箇所 |
|---|---|---|
| `.well-known/openid-configuration`（discovery） | `OAuth2EndpointController.OpenIDConfig` | 固定パス |
| `/authorize` → `/token` | `Account.OAuth2Authorize` / `OAuth2Endpoint.OAuth2Token` | `Config.OAuth2AuthorizeEndpoint` / `OAuth2TokenEndpoint` |
| `POST /SetDeviceToken` | `OAuth2Endpoint.SetDeviceToken` | `Config.SetDeviceTokenWebAPI` |
| `POST /ciba_result` | `OAuth2Endpoint.CibaPushResult` | `Config.CibaPushResultEndpoint` |
| `POST /2fa_result` | `OAuth2Endpoint.TwoFactorPushResult` | `Config.TwoFactorPushResultEndpoint`（#213 / net48 版は #216） |
| （宣言のみ・未使用）`/userinfo` | `OAuth2Endpoint.GetUserClaims` | `Config.OAuth2UserInfoEndpoint` |

- **URL は `AppConfig.mpasBaseUrl`（`MPAS_BASE_URL`）＋ 上のパスで組み立てる（#205）。**
  Android / iOS の `/authorize` と `/token` は、AppAuth が discovery から解決する。
  web は自前の実装（`web_sign_in.dart`）が直接組み立てる。
- 登録したデバイス トークンは `Users.DeviceToken` 列に入り、
  `../CommonLibrary/Notifications/FcmService` がここへプッシュする。
- **`client_id` は認証サイトの `OAuth2ClientsInformation` に定義されている。** `lib/configs/app_auth.dart` に直書きしてある。

| 版 | `client_id` | `client_name` | `redirect_uri` |
|---|---|---|---|
| Android / iOS | `40319c0100f94ff3aab3004c8bdb5e52` | `Native_Application` | `com.opentouryo:/oauthredirect` |
| web（#205） | `aad529f7f9b6428a84c59ac15aef0cdb` | `AuthenticationDevice_Web`（パブリック クライアント。`client_secret` なし、PKCE で交換） | `http://localhost:5610/` |

- **`redirect_uri` は両側で一致させる必要がある**（認証サイトは完全一致で照合する）。
  アプリ側は `com.opentouryo:/oauthredirect`（`app_auth.dart` ＋ `AndroidManifest.xml` ＋
  `build.gradle.kts` の `appAuthRedirectScheme`）。
  認証サイト側のテンプレート `_appsettings.json` は `http://opentouryo.com/` になっている
  （＝ App Links 用）ので、**Private-Use URI Scheme で試すならサイト側の設定を直す。**
  web は `flutter run` を `--web-port 5610` で起動する（サイト側のテンプレートと実際の設定に登録済み。#205）。

---

## 3. 構成

```
authentication_device/
├─ README.md          … 設定すべきファイルの案内（一次情報）
├─ CHEATSHEET.md      … 設定ファイルと起動の手順（#205）
├─ pubspec.yaml / pubspec.lock
├─ firebase_web.sample.json          … web の Firebase 構成の項目名（実物の firebase_web.json は gitignore）
├─ mpas.core.json / mpas.netfx.json  … 接続先（ローカル用）
├─ lib/
│   ├─ main.dart                         81 行  Firebase 初期化（web は構成があるときだけ）、バックグラウンド ハンドラ、通知チャネル
│   ├─ components/
│   │   ├─ importer.dart                      ★共通 export（各ファイルはこれ 1 本を import する）
│   │   ├─ app.dart                      28 行  ルート定義（/ , /mypage , /message）
│   │   ├─ appauth_page.dart            267 行  ★サインイン と デバイス トークン登録
│   │   ├─ web_sign_in.dart             154 行  ★web のサインイン（認可コード + PKCE を自前で実装。#205）
│   │   ├─ message_view.dart            169 行  ★通知詳細。2FA の code 表示・Approve / CIBA の Allow・Deny
│   │   └─ fcm_page/{fcm_page,message_list,permissions,token_checker}.dart
│   ├─ configs/
│   │   ├─ app_config.dart               17 行  ★接続先（`MPAS_BASE_URL`）
│   │   ├─ app_auth.dart                 53 行  ★client_id / redirect_uri / 各エンドポイント / トークン永続化
│   │   ├─ app_fcm.dart                  29 行  ★通知チャネル定義 / VAPID キー / Firebase 初期化済みフラグ
│   │   └─ app_firebase_web.dart         60 行  ★web の Firebase 構成（`FIREBASE_*`）/ service worker のパス（#205）
│   ├─ common/                                MetaCard / MyDrawer / MyDropdownButton /
│   │                                         MyElevatedButton / SpaceBox
│   └─ models/message_arguments.dart
├─ android/          … ★設定の実体（Manifest / build.gradle.kts / google-services.json / 証明書）
├─ ios/              … 雛形のまま（7 節）
├─ web/              … index.html（現行の雛形）/ flutter_bootstrap.js（Flutter の service worker を登録しない）/
│                      firebase-messaging-sw.js（Web Push の受信）/ manifest.json（#205）
└─ test/widget_test.dart
```

`lib/components/importer.dart` が `dart:*` / `flutter/*` / 自前の主要クラスをまとめて `export` し、
各ファイルは `import 'importer.dart';` の 1 行で済ませる方式。**新しい共通部品はここに足す。**

---

## 4. 画面と処理の流れ

```
/  (AppAuthPage)
   initState:
     ├ AppFcm.enabled のときだけ（web で Firebase の構成が無ければ飛ばす。#205）
     │   ├ FirebaseMessaging.instance.getInitialMessage()   … terminated から通知起動 → /message
     │   ├ FirebaseMessaging.onMessage.listen(...)          … foreground はローカル通知で代替表示（Android）
     │   ├ FirebaseMessaging.onMessageOpenedApp.listen(...) … background から通知起動 → /message
     │   └ _getFcmToken() / onTokenRefresh                  … FCM トークンを AppFcm.token へ（web は service worker を指定）
     ├ web : WebSignIn.completeIfReturned(Uri.base)         … 認可応答での戻りなら state を照合し、/token で交換して保存（#205）
     └ 保存済み access_token があれば _registerFcmTokenApi()
   [SignIn Button]
     ├ Android / iOS
     │   → FlutterAppAuth.authorize()  （discoveryUrl から /authorize を解決、PKCE）
     │   → FlutterAppAuth.token()      （code + code_verifier → access_token）
     │   → SharedPreferences に access_token 保存 → _registerFcmTokenApi()
     └ web（#205）
         → WebSignIn.start()           （state / code_verifier を保存し、同じタブで /authorize へ）
         → 戻った後は、initState の completeIfReturned が続きを行う
   _registerFcmTokenApi():
     → Firebase が無い / FCM トークンが取れないときは、登録を省略する
     → POST /SetDeviceToken  (Bearer, device_token=...)
        レスポンス本文が "OK"（JSON 文字列）なら AppConfig.initialized = true → /mypage

/mypage (FcmPage)     … 通知の権限状態 と 受信メッセージ一覧
/message (MessageView)
   notification.title == "2FA"  → data["code"] を表示し、
                                  [Approve] → POST /2fa_result (code)   ← #213
   notification.title == "CIBA" → data["binding_message"] / data["auth_req_id"] を表示し、
                                  [Allow] / [Deny] → POST /ciba_result (auth_req_id, result)
```

- **判定キーは通知の `title` 文字列（`"2FA"` / `"CIBA"`）。**
  認証サイト側（`../CommonLibrary/Notifications/FcmService` と
  `Extensions/Sts/CibaProvider`）が送るタイトルと一致していないと画面が出ない。
- **`/SetDeviceToken` の成功判定は `response.body == "\"OK\""`**（コード中のコメントに
  「AuthZ(N)の仕様による」とある）。サーバ側の戻り値を変えるとアプリが壊れる。
- **2FA で送られるのは、SMS / メールと同じ確認コード。** 画面に手で入力して完了させることもできるが、
  **[Approve] を押すと、そのコードを `/2fa_result` に送り返して完了させられる（#213）。**
  **サインインを完了させるのは、待っているブラウザ側である。** 2FA のセッションはブラウザの Cookie にあり、
  この端末からは触れない。サーバは「誰がどのコードを承認したか」をメモリに記録するだけで、
  認証サイトの `VerifyCode` 画面が 2 秒ごとに `/Account/TwoFactorPushStatus` を見て、サインインを終わらせる。
  なお、返答を受ける口としてルートだけがあった `/TwoFactorAuthPushResult` は、アクションが無かったため削除してある（#203）。

---

## 5. 設定すべき箇所（README の要約）

手順だけを並べたものは [`CHEATSHEET.md`](CHEATSHEET.md)。

| ファイル | 何を入れるか | 現状 |
|---|---|---|
| `mpas.core.json` / `mpas.netfx.json` | `MPAS_BASE_URL` … 認証サイトが実際に待ち受ける URL | ローカル用をコミット済み。渡さないときは `https://localhost:44300`（#205） |
| `firebase_web.json` | web の Firebase 構成（`FIREBASE_*`）と VAPID キー | **各自で作る**（`firebase_web.sample.json` から。gitignore 済み）（#205） |
| `lib/configs/app_auth.dart` | `clientId` / `redirectUrl`（Android）、`webClientId` / `webRedirectUrl`（web） | 直書き（認証サイト側の登録と対応させる） |
| `android/app/google-services.json` | Firebase の構成（Android） | **プレースホルダ（中身は「置き換える。」の 1 行）**。web では使わない |
| `android/app/src/main/AndroidManifest.xml` | Deep Links（`opentouryo://hoge`）/ App Links（`http://opentouryo.com`） | 設定済み |
| `android/app/build.gradle.kts` | `appAuthRedirectScheme` | `com.opentouryo` |
| `android/app/src/debug/res/raw/my_ca.cer` | 自己署名 CA（デバッグ ビルドのみ信頼） | **未コミット。各自で用意する** |

- `android/app/src/debug/res/xml/network_security_config.xml` が `@raw/my_ca` を
  `<debug-overrides>` の trust-anchor にしている。**このファイルが無いとデバッグ ビルドが通らない。**
  ブラウザのアドレス バーから DER 形式の CER として書き出して置く（README）。
- `android/app/src/main/res/xml/network_security_config.xml` は**空**（＝リリースは既定の信頼のみ）。
- サーバ側の設定（web 版のクライアント登録、通知を送る鍵 `FirebaseServiceAccountKey.json`）の手順は [`CHEATSHEET.md`](CHEATSHEET.md) 4 節。

---

## 6. 依存とツールチェーン

**#209 で、現行の Flutter に合わせて更新した。**

| | 値 |
|---|---|
| Dart SDK | `^3.11.0`（`pubspec.lock` は `>=3.11.0 <4.0.0`、Flutter `>=3.38.1`） |
| 確認した Flutter | 3.41.9（stable）/ Dart 3.11.5 |
| `compileSdk` / `targetSdk` / `minSdk` | Flutter の既定に従う（3.41 では 36 / 36 / 24）。`minSdk` 24 はプラグインの要求でもある |
| Android のビルド | Kotlin DSL（`*.gradle.kts`）/ AGP 8.11.1 / Kotlin 2.2.20 / Gradle 8.14 / Java 17 / core library desugaring |
| 主な依存 | `firebase_core` 4.13.0 / `firebase_core_web` 3.10.0 / `firebase_messaging` 16.5.0 / `flutter_local_notifications` 22.3.0 / `flutter_appauth` 12.1.0 / `http` 1.6.0 / `shared_preferences` 2.5.5 / `url_launcher` 6.3.2 / `english_words` 4.0.0 |

> **`firebase_core_web` は 3.10.x に留めている。**
> 3.11.0 は、Dart 3.12 未満（Flutter 3.44 未満）では web のコンパイルに失敗する（firebase/flutterfire#18611）。
> 修正は上流でマージ済みだが、3.11.0 より新しい版は出ていない（2026-09-13 時点）。
> それに合わせて `firebase_core` / `firebase_messaging` も 1 つ前の版に留めている。外し方は `pubspec.yaml` のコメントにある。

> **Android のビルドは確かめていない。** #209 は Android SDK の無い環境で作業した。
> Gradle の設定は、同じ Flutter 版で `flutter create` した雛形に合わせ、各プラグインの要求
> （README / `build.gradle`）を足したもの。最初に `flutter build apk --debug` を通すときに、差が出る可能性がある。
>
> **依存の版は、まとめて上げる。** `flutter_local_notifications` の引数の変更など、
> 破壊的変更を踏む箇所が複数ある。部分的な版上げは避けること。

- `AppFcm.channel` は `AndroidNotificationChannel('high_importance_channel', ...)` で、
  `AndroidManifest.xml` の FCM 既定チャネルを上書きしてヘッドアップ通知を出す狙い。
- **`android/app/build.gradle.kts` の release 署名は debug キーのまま**（Flutter テンプレートの TODO が残っている）。
  配布用のビルドはできない。

---

## 7. iOS / Web

- `ios/Runner/Info.plist` に **`CFBundleURLTypes`（カスタム URL スキーム）の定義が無い。**
  このままでは AppAuth のリダイレクトが戻ってこない。
- iOS 側の Firebase 構成ファイル（`GoogleService-Info.plist`）も無い。
- **web は #205 で対応中。** net10.0 版に対して確認できていること（2026-09-14）:
  - Firebase の web 構成（`firebase_web.json`）での初期化と、FCM トークンの取得
  - サインイン（認可コード ＋ PKCE を自前で実装。`web_sign_in.dart`。`client_secret` なしで交換できた）
  - `/SetDeviceToken` での端末の登録と、`/mypage` への遷移
  - **CIBA : 本物の FCM からの通知の受信と、`/ciba_result` での応答。** 認証サイトの自己テスト（`/Home/Saml2OAuth2Starters`）で、
    Allow → `?ret=OK_NORMAL_END`、Deny → `?ret=OK_ABNORMAL_END` になった（アプリのタブが見えている＝フォアグラウンドで受けた場合）
  - **CIBA（バックグラウンド）: OS の通知のクリック → アプリが前面に出て詳細画面 → Allow → `?ret=OK_NORMAL_END`。**
    普段の Chrome（`flutter run -d web-server` で配信）で確認した。`flutter run -d chrome` の Chrome では、クリックが届かなかった（8 節 16）
  - **net48 版（`https://localhost:44302`、`mpas.netfx.json`）でも、サインイン・端末の登録・CIBA（フォアグラウンド / バックグラウンドの Allow）を確認した。**
    自己テストの移る先の表記は net48 版だけ違い、`?ret=OK: 正常終了`（それ以外は `OK: 異常終了`）。net10.0 版は `OK_NORMAL_END` / `OK_ABNORMAL_END`
  - **PWA としてインストールした状態でも、サインイン・CIBA（フォアグラウンド / バックグラウンド）が動いた**（`build/web` を配信して確認）。
    サインインは同じウィンドウ内で認証サイトの画面が開き、戻ってきた。通知のクリックでは、ブラウザのタブではなく**アプリのウィンドウ**が開いた
  - **2FA のプッシュ承認（#213。2026-09-16）: `MobileApp` を選ぶ → コードの入力画面が待ち受ける → 認証デバイスの [Approve] で、手で入力せずにサインインが完了した。**
    **PWA としてインストールした状態で確認した**（手順は `CHEATSHEET.md` 9 節）。サーバ側の `/2fa_result` の失敗（401 / 400）は E2E で測っている（`RT-213.1`）
- **web でまだ確かめていないこと:** HTTPS での配信（#211。スマートフォンから使うために要る。
  `http://localhost` は安全なコンテキスト扱いなので、PC でのインストールと Web Push はこれ無しで動いている）
- `firebase_web.json` を渡さないときは、Firebase を初期化せずに起動する（プッシュは使えない）。

**Android の実機での動作は、#209 以降は確認していない**（6 節）。

---

## 8. 落とし穴 / 既知の不整合

1. **`google-services.json` はプレースホルダ。** そのままでは Android で Firebase 初期化に失敗する（5 節）。web は `firebase_web.json` を使う。
2. **`my_ca.cer` が無いとデバッグ ビルドが通らない**（5 節）。README のとおり各自で用意する。
3. **`redirect_uri` が複数箇所に散っている**（2 節）。1 つでもズレると認可レスポンスが戻らない。
   Android : `app_auth.dart` ＋ `AndroidManifest.xml` ＋ `build.gradle.kts` ＋ サーバ側。
   web : `app_auth.dart` の `webRedirectUrl` ＋ サーバ側（`AuthenticationDevice_Web`、ポート 5610）。
4. **接続先には、認証サイトが実際に待ち受けている URL を渡す**（`MPAS_BASE_URL`。#205 で `serverFqdn` と `http://` の直書きをやめた）。
   構成ファイルのルート URI（`…/MultiPurposeAuthSite`）とは限らない。Kestrel で起動し、ルート URI を環境変数で揃えた場合は、
   `https://localhost:44300/.well-known/openid-configuration` が 200、`/MultiPurposeAuthSite` 付きは 404 だった（実測）。
   既定は `https://localhost:44300` なので、Android の実機では、届く URL を書いたファイルを渡す。
5. **通知の種別判定が `title` の文字列一致**（4 節）。サーバ側の文言を変えると黙って壊れる。
6. **`/SetDeviceToken` の成功判定が `"\"OK\""` の完全一致**（4 節）。
7. **2FA の [Approve] は、両方の版で動く**（4 節）。**コードを検証するプロバイダの名前だけが版で違う**（net10.0 : `Email`、net48 : `MobileApp`）。アプリから見た振る舞い（`POST /2fa_result` に `code` を送る）は同じ（#213 / #216）。
8. **`AppAuth.userinfoEndpoint` は宣言されているが呼ばれていない。**
9. **`TokenChecker` は使われていない。** `fcm_page.dart` で `MetaCard('FCM Token', ...)` ごと
   コメント アウトされている。
10. **依存の版は、まとめて上げる**（6 節）。部分的な版上げをしない。**`firebase_core_web` は 3.10.x に留めている**ことにも注意する。
11. **`android/app/build.gradle.kts` の release 署名が debug キー**（6 節）。
12. `test/widget_test.dart` は `flutter create` の雛形のままで、
    このアプリの画面構成に合っていない可能性が高い。
13. **web では Flutter 自身の service worker を登録しない**（`web/flutter_bootstrap.js`）。
    `firebase-messaging-sw.js` と scope `/` が同じで、後から登録した方に置き換わるため。
    `flutter_bootstrap.js` を消すと、Web Push を受ける service worker が置き換わる可能性がある（実測はしていない）。
14. **`--dart-define-from-file` の値はコンパイル時の定数。** ファイルを変えたら `flutter run` をやり直す（ホット リロードでは変わらない）。
15. **web で認可画面へ移ると、`flutter run` とアプリの接続が切れる。** 戻った後のログは、Chrome の DevTools の Console で見る。
16. **web の通知は、アプリの画面が「見えている」ときだけ画面に届く**（Message Stream に並ぶ）。見えていなければ OS の通知になる。
    判定は Firebase の SDK（service worker）が `visibilityState === 'visible'` で行う（フォーカスは関係ない。重なって隠れている / 最小化は見えていない扱い）。**インストールした PWA のウィンドウでも同じ**（実測）。
    **OS の通知のクリックは、`web/firebase-messaging-sw.js` が自前で受け、通知の中身を URL のクエリに載せてアプリを開く**（#205 増分 3。`web_push_click.dart`）。
    SDK の `notificationclick` は、開く先（`fcmOptions.link` / `click_action`）が無い通知では閉じるだけで、`stopImmediatePropagation()` も呼ぶ。
    そのため、自前の処理は `firebase.messaging()` より**前に**登録している（後にすると、SDK の処理に止められる）。`firebase_messaging_web` に `onMessageOpenedApp` の実装は無い。
    **`flutter run -d chrome` が起動する Chrome（一時プロファイル）では、クリックの処理が呼ばれなかった。** バックグラウンドの経路は、普段の Chrome（`-d web-server`）で確かめる。
17. **CIBA の自己テストは、宛先が `tanaka@gmail.com` に固定**（認証サイトの `HomeController.AssembleFAPICibaProfileStarterAsync`）。
    認証デバイスも `tanaka@gmail.com` でサインインして端末を登録しておく。登録が無いと `/ciba_authz` が HTTP 500（例外の平文）を返し、
    自己テストは `JsonReaderException` で落ちる。ユーザ ストアが `mem` だと、認証サイトの再起動でユーザも端末の登録も消える。
18. **web のサインインは、ブラウザに残った認証サイトのサインイン状態で、サインイン画面を出さずに前のユーザのまま通る可能性がある**（実測はしていない）。
    ユーザを切り替えるときは、先に認証サイトでサインアウトする。宛先と違うユーザで応答すると、`/ciba_result` は 400 を返す。
19. **`flutter run` は manifest を生成しない。** 配信される `/manifest.json` は `{"info":"manifest not generated in run mode."}` で、
    `index.html` の `<base>` も `$FLUTTER_BASE_HREF` のまま。この状態で DevTools の Installability を見ると、
    `name` が無い・`display` が不正・アイコンが無い、と**まとめてエラーになる**（manifest 自体は正しい）。
    **PWA としての確認は、`flutter build web` の出力（`build/web`）を配信して行う。**

---

## 9. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] 設定値を触る前に [`README.md`](README.md) を読む（設定すべきファイルの一次情報）
- [ ] エンドポイントや `client_id` / `redirect_uri` を変えたら、
      **認証サイト側（`../CommonLibrary/Co/Config.cs` と `_appsettings.json` /
      `_app.config` の `OAuth2ClientsInformation`）との整合を確認する**
- [ ] web 版の `redirect_uri`（ポート 5610）を変えたら、認証サイト側の `AuthenticationDevice_Web` の `redirect_uri_code` も変える
      （テンプレートと、実際に読まれる `appsettings.json` / `app.config` の両方）
- [ ] 通知の `title` / `data` のキー名を変えるときは、
      **`../CommonLibrary/Notifications/FcmService` と `Extensions/Sts/CibaProvider` を同時に見る**
- [ ] 依存の版を上げるときは、**`pubspec.yaml` / `pubspec.lock` / `build.gradle.kts` の
      compileSdk・targetSdk・コード側の破壊的変更をまとめて**扱う（部分更新をしない）
- [ ] 共通で使う部品は `lib/components/importer.dart` に `export` を足す
- [ ] `google-services.json` / `my_ca.cer` / `firebase_web.json` / `FirebaseServiceAccountKey.json` に**実物をコミットしない**（[`CHEATSHEET.md`](CHEATSHEET.md) 1 節）
- [ ] ビルド確認: `flutter pub get` → `flutter analyze` → `flutter build web`
      （Android は `flutter build apk --debug`。**Android SDK が要る**。6 節）
- [ ] web の動作確認: `flutter run -d chrome --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json`
      （認証サイトの起動も含めて [`CHEATSHEET.md`](CHEATSHEET.md) 5 節）
