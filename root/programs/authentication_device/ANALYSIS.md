# ANALYSIS.md — 汎用認証サイト 認証デバイス部（authentication_device / Flutter）コード分析

対象: `root/programs/authentication_device`（**Flutter / Dart**） / ブランチ: `develop`
最終更新: 2026-09-07

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。

関連: [`../MultiPurposeAuthSiteCore/ANALYSIS.md`](../MultiPurposeAuthSiteCore/ANALYSIS.md)、
[`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md)。
使い方（設定の埋め方）は本ディレクトリの [`README.md`](README.md) が一次情報。

---

## 1. これは何か

**汎用認証サイトの「認証デバイス」として振る舞う Flutter アプリ。**
本リポジトリで唯一の非 .NET 資産であり、次の 2 つを担う。

1. **プッシュ通知の宛先になる。** ネイティブ アプリとして OAuth2 認可コード グラント（PKCE）で
   サインインし、取得したアクセス トークンで FCM のデバイス トークンを認証サイトへ登録する。
2. **CIBA（Client Initiated Backchannel Authentication）の承認端末になる。**
   認証サイトから届くプッシュに「Allow / Deny」で応答する。

> **位置付けはサンプル / テスト用。** `../MultiPurposeAuthSiteCore` の CIBA・プッシュ 2FA を
> 実機で確かめるための相手方であり、製品ではない。

- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**

規模の目安: `lib/` の `.dart` 19 ファイル / 約 960 行。

---

## 2. 認証サイト側との対応

| このアプリが叩くもの | 認証サイト側 | 定義箇所 |
|---|---|---|
| `.well-known/openid-configuration`（discovery） | `OAuth2EndpointController.OpenIDConfig` | 固定パス |
| `/authorize` → `/token`（AppAuth が discovery から解決） | `Account.OAuth2Authorize` / `OAuth2Endpoint.OAuth2Token` | `Config.OAuth2AuthorizeEndpoint` / `OAuth2TokenEndpoint` |
| `POST /MultiPurposeAuthSite/SetDeviceToken` | `OAuth2Endpoint.SetDeviceToken` | `Config.SetDeviceTokenWebAPI` |
| `POST /MultiPurposeAuthSite/ciba_result` | `OAuth2Endpoint.CibaPushResult` | `Config.CibaPushResultEndpoint` |
| （宣言のみ・未使用）`/MultiPurposeAuthSite/userinfo` | `OAuth2Endpoint.GetUserClaims` | `Config.OAuth2UserInfoEndpoint` |

- 登録したデバイス トークンは `Users.DeviceToken` 列に入り、
  `../CommonLibrary/Notifications/FcmService` がここへプッシュする。
- **`client_id` は認証サイトの `OAuth2ClientsInformation` に定義されている
  `40319c0100f94ff3aab3004c8bdb5e52`（`client_name: Native_Application`）。**
  `lib/configs/app_auth.dart` に直書きしてある。
- **`redirect_uri` は両側で一致させる必要がある。**
  アプリ側は `com.opentouryo:/oauthredirect`（`app_auth.dart` ＋ `AndroidManifest.xml` ＋
  `build.gradle` の `appAuthRedirectScheme`）。
  認証サイト側のテンプレート `_appsettings.json` は `http://opentouryo.com/` になっている
  （＝ App Links 用）ので、**Private-Use URI Scheme で試すならサイト側の設定を直す。**

---

## 3. 構成

```
authentication_device/
├─ README.md          … 設定すべき 5 ファイルの案内（一次情報）
├─ pubspec.yaml / pubspec.lock
├─ lib/
│   ├─ main.dart                       64 行  Firebase 初期化、バックグラウンド ハンドラ、通知チャネル
│   ├─ components/
│   │   ├─ importer.dart                      ★共通 export（各ファイルはこれ 1 本を import する）
│   │   ├─ app.dart                     27 行  ルート定義（/ , /mypage , /message）
│   │   ├─ appauth_page.dart           211 行  ★サインイン と デバイス トークン登録
│   │   ├─ message_view.dart           131 行  ★通知詳細。2FA の code 表示 / CIBA の Allow・Deny
│   │   └─ fcm_page/{fcm_page,message_list,permissions,token_checker}.dart
│   ├─ configs/
│   │   ├─ app_config.dart              3 行  ★接続先 FQDN（`serverFqdn`）
│   │   ├─ app_auth.dart               41 行  ★client_id / redirect_uri / 各エンドポイント / トークン永続化
│   │   └─ app_fcm.dart                21 行  ★通知チャネル定義 / VAPID キー
│   ├─ common/                                MetaCard / MyDrawer / MyDropdownButton /
│   │                                         MyElevatedButton / SpaceBox
│   └─ models/message_arguments.dart
├─ android/          … ★設定の実体（Manifest / build.gradle / google-services.json / 証明書）
├─ ios/              … 雛形のまま（4 節）
├─ web/              … 雛形のまま
└─ test/widget_test.dart
```

`lib/components/importer.dart` が `dart:*` / `flutter/*` / 自前の主要クラスをまとめて `export` し、
各ファイルは `import 'importer.dart';` の 1 行で済ませる方式。**新しい共通部品はここに足す。**

---

## 4. 画面と処理の流れ

```
/  (AppAuthPage)
   initState:
     ├ FirebaseMessaging.instance.getInitialMessage()   … terminated から通知起動 → /message
     ├ FirebaseMessaging.onMessage.listen(...)          … foreground はローカル通知で代替表示
     ├ FirebaseMessaging.onMessageOpenedApp.listen(...) … background から通知起動 → /message
     ├ getToken(vapidKey) / onTokenRefresh              … FCM トークンを AppFcm.token へ
     └ 保存済み access_token があれば _registerFcmTokenApi()
   [SignIn Button]
     → FlutterAppAuth.authorize()  （discoveryUrl から /authorize を解決、PKCE）
     → FlutterAppAuth.token()      （code + code_verifier → access_token）
     → SharedPreferences に access_token 保存
     → POST /SetDeviceToken  (Bearer, device_token=...)
        レスポンス本文が "OK"（JSON 文字列）なら AppConfig.initialized = true → /mypage

/mypage (FcmPage)     … 通知の権限状態 と 受信メッセージ一覧
/message (MessageView)
   notification.title == "2FA"  → data["code"] を表示するだけ
   notification.title == "CIBA" → data["binding_message"] / data["auth_req_id"] を表示し、
                                  [Allow] / [Deny] → POST /ciba_result (auth_req_id, result)
```

- **判定キーは通知の `title` 文字列（`"2FA"` / `"CIBA"`）。**
  認証サイト側（`../CommonLibrary/Notifications/FcmService` と
  `Extensions/Sts/CibaProvider`）が送るタイトルと一致していないと画面が出ない。
- **`/SetDeviceToken` の成功判定は `response.body == "\"OK\""`**（コード中のコメントに
  「AuthZ(N)の仕様による」とある）。サーバ側の戻り値を変えるとアプリが壊れる。
- **2FA は「表示するだけ」で、`/TwoFactorAuthPushResult` は叩いていない。**
  認証サイト側にエンドポイントはあるが、このアプリからは未実装。

---

## 5. 設定すべき箇所（README の要約）

| ファイル | 何を入れるか | 現状 |
|---|---|---|
| `lib/configs/app_config.dart` | `serverFqdn` … 認証サイトの FQDN | `mpos-opentouryo.ddo.jp` が直書き |
| `lib/configs/app_auth.dart` | `clientId` / `redirectUrl` / 各エンドポイント | `40319c...` が直書き |
| `lib/configs/app_fcm.dart` | `vapidKey` | `<YOUR_PUBLIC_VAPID_KEY_HERE>` のまま（Web 用） |
| `android/app/google-services.json` | Firebase の構成 | **プレースホルダ（中身は「置き換える。」の 1 行）** |
| `android/app/src/main/AndroidManifest.xml` | Deep Links（`opentouryo://hoge`）/ App Links（`http://opentouryo.com`） | 設定済み |
| `android/app/build.gradle` | `appAuthRedirectScheme` | `com.opentouryo` |
| `android/app/src/debug/res/raw/my_ca.cer` | 自己署名 CA（デバッグ ビルドのみ信頼） | **未コミット。各自で用意する** |

- `android/app/src/debug/res/xml/network_security_config.xml` が `@raw/my_ca` を
  `<debug-overrides>` の trust-anchor にしている。**このファイルが無いとデバッグ ビルドが通らない。**
  ブラウザのアドレス バーから DER 形式の CER として書き出して置く（README）。
- `android/app/src/main/res/xml/network_security_config.xml` は**空**（＝リリースは既定の信頼のみ）。

---

## 6. 依存とツールチェーン（**かなり古い**）

| | 値 |
|---|---|
| Dart SDK | `>=2.12.0 <3.0.0`（`pubspec.lock` は `>=2.13.0 <3.0.0`） |
| Flutter | `>=2.2.0` |
| `compileSdkVersion` / `targetSdkVersion` | **30**（Android 11） |
| `minSdkVersion` | 23 |
| 主な依存 | `flutter_appauth` ^1.0.0 / `firebase_messaging` 10.0.1 / `flutter_local_notifications`（版指定なし） / `shared_preferences` ^2.0.6 / `http` ^0.13.3 / `url_launcher` ^6.0.4 / `english_words` ^4.0.0 |

> **Dart 3 以前（null safety 導入直後）のコードである。**
> 現行の Flutter SDK では `pub get` の時点で解決できない可能性が高い。
> 動かすには **当時の Flutter 2.x を用意する**か、**依存とコードをまとめて更新する**かのどちらか。
> 後者は `flutter_local_notifications` の `AndroidNotificationDetails` の
> 位置引数（`AppFcm.channel.description` を第 3 引数に渡している）など、
> **破壊的変更を踏む箇所が複数ある。** 部分的な版上げは避けること。

- `AppFcm.channel` は `AndroidNotificationChannel('high_importance_channel', ...)` で、
  `AndroidManifest.xml` の FCM 既定チャネルを上書きしてヘッドアップ通知を出す狙い。
- **`android/app/build.gradle` の release 署名は debug キーのまま**（Flutter テンプレートの TODO が残っている）。
  配布用のビルドはできない。

---

## 7. iOS / Web は未整備

- `ios/Runner/Info.plist` に **`CFBundleURLTypes`（カスタム URL スキーム）の定義が無い。**
  このままでは AppAuth のリダイレクトが戻ってこない。
- iOS 側の Firebase 構成ファイル（`GoogleService-Info.plist`）も無い。
- `web/` は `flutter create` の雛形のまま。`app_fcm.dart` の `vapidKey` も未設定。

**動作確認できるのは Android のみ**と考えてよい。

---

## 8. 落とし穴 / 既知の不整合

1. **`google-services.json` はプレースホルダ。** そのままでは Firebase 初期化に失敗する（5 節）。
2. **`my_ca.cer` が無いとデバッグ ビルドが通らない**（5 節）。README のとおり各自で用意する。
3. **`redirect_uri` が 3 箇所＋サーバ側の計 4 箇所に散っている**（2 節）。
   1 つでもズレると認可レスポンスが戻らない。
4. **`serverFqdn` が `app_config.dart` に直書き**で、`userinfo` / `SetDeviceToken` /
   `ciba_result` は **`http://`（平文）** を組み立てている
   （`discoveryUrl` だけ `https://`）。コード中のコメントは「テストなので、HTTP」。
   **本番相当の確認をするなら 3 つとも `https://` に直す。**
5. **通知の種別判定が `title` の文字列一致**（4 節）。サーバ側の文言を変えると黙って壊れる。
6. **`/SetDeviceToken` の成功判定が `"\"OK\""` の完全一致**（4 節）。
7. **2FA のプッシュ結果を返す実装が無い**（4 節）。`/TwoFactorAuthPushResult` は未使用。
8. **`AppAuth.userinfoEndpoint` は宣言されているが呼ばれていない。**
9. **`TokenChecker` は使われていない。** `fcm_page.dart` で `MetaCard('FCM Token', ...)` ごと
   コメント アウトされている。
10. **ツールチェーンが古い**（6 節）。安易な単発の版上げをしない。
11. **`android/app/build.gradle` の release 署名が debug キー**（6 節）。
12. `test/widget_test.dart` は `flutter create` の雛形のままで、
    このアプリの画面構成に合っていない可能性が高い。

---

## 9. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] 設定値を触る前に [`README.md`](README.md) を読む（設定すべきファイルの一次情報）
- [ ] エンドポイントや `client_id` / `redirect_uri` を変えたら、
      **認証サイト側（`../CommonLibrary/Co/Config.cs` と `_appsettings.json` /
      `_app.config` の `OAuth2ClientsInformation`）との整合を確認する**
- [ ] 通知の `title` / `data` のキー名を変えるときは、
      **`../CommonLibrary/Notifications/FcmService` と `Extensions/Sts/CibaProvider` を同時に見る**
- [ ] 依存の版を上げるときは、**`pubspec.yaml` / `pubspec.lock` / `build.gradle` の
      compileSdk・targetSdk・コード側の破壊的変更をまとめて**扱う（部分更新をしない）
- [ ] 共通で使う部品は `lib/components/importer.dart` に `export` を足す
- [ ] `google-services.json` や `my_ca.cer` に**実物をコミットしない**
- [ ] ビルド確認: `flutter pub get` → `flutter build apk --debug`
      （**動作確認できるのは Android のみ**。iOS / Web は未整備）
