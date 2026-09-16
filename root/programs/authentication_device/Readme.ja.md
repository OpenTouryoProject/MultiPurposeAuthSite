このファイルの英語版は[こちら](README.md)から。

# 使い方
手順（設定ファイル、サイトの起動、CIBA と 2FA のプッシュ承認の確かめ方）は [CHEATSHEET.md](CHEATSHEET.md) にまとめてあります。

## 設定
環境によって変わる値は、ソースに書かず、`--dart-define-from-file` で渡します。

| 何を | どこに |
|---|---|
| 接続先（サーバの URL） | `mpas.core.json` / `mpas.netfx.json`（`MPAS_BASE_URL`）。「接続先」の節 |
| web 用の Firebase と VAPID キー | `firebase_web.json`（`FIREBASE_*`）。「Web（PWA）」の節 |
| Android 用の Firebase | /android/app/google-services.json |

クライアントの設定は、/lib/configs/app_auth.dart に書いてあります。  
サーバ側のクライアントの登録（`OAuth2ClientsInformation`）と一致させる必要があります。

- Android / iOS : `clientId`、`redirectUrl`
- Web : `webClientId`、`webRedirectUrl`（`MPAS_WEB_REDIRECT_URI` で上書きできる）

サーバ側の設定（クライアントの登録と、通知を送る鍵）は、CHEATSHEET.md の 4 節にあります。

## Android
Private-Use URI Scheme Redirection と Claimed Https Scheme URI Redirection の設定は、  
次のファイルで行います。

- /android/app/src/main/AndroidManifest.xml
- /android/app/build.gradle.kts

認証サーバが自己署名証明書を使っている場合は、  
自己署名証明書を許可するため、次の場所に証明書を置きます（デバッグ ビルドのみ）。  
このファイルは、ブラウザのアドレスバーから DER 形式の CER として書き出せます。

- /android/app/src/debug/res/raw/my_ca.cer

# 接続先（サーバの URL）
MultiPurposeAuthSite が実際に待ち受けているルート URL を、`--dart-define-from-file` で渡します。  
サーバの構成ファイルのルート URI（`…/MultiPurposeAuthSite`）とは限りません。  
次のファイルは、CHEATSHEET.md の 5 節の手順で起動したローカルのサイト用です（エンドポイントはルート直下にあります）。

- mpas.core.json : net10.0（https://localhost:44300）
- mpas.netfx.json : IIS Express で起動した net48（https://localhost:44302）

ファイルを渡さないときは、`https://localhost:44300` を使います。  
net48 を Visual Studio から起動した場合、プロジェクトの設定（`IISUrl`）は `https://localhost:44300/MultiPurposeAuthSite/` です。  
その場合は、末尾の `/` を除いた URL を自分用のファイルに書いてください（実測していません）。  
Android の実機からは `localhost` に届きません。実機から届く URL を書いたファイルを渡してください。

# Web（PWA）
Web Push には、Firebase の Web アプリの構成と VAPID キーが必要です。  
`firebase_web.sample.json` を `firebase_web.json` にコピーし、  
Firebase コンソールの値を入れてください。`firebase_web.json` は git に無視されます。

- プロジェクトの設定 > 全般 > マイアプリ >（Web アプリ） : `FIREBASE_*`
- プロジェクトの設定 > Cloud Messaging > ウェブプッシュ証明書 : `FIREBASE_VAPID_KEY`

Web でのサインインには、クライアント `AuthenticationDevice_Web`（PKCE を使うパブリック クライアント）を使います。  
その `redirect_uri` は `http://localhost:5610/` なので、このポートでアプリを起動してください。

    flutter run -d chrome --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
    flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

`firebase_web.json` が無いときは、プッシュ通知なしで起動します。

バックグラウンドの通知（OS の通知のクリック）を試すときは、普段お使いの Chrome でアプリを開いてください。  
`flutter run -d chrome` が起動する Chrome（一時プロファイル）では、クリックがアプリに届きませんでした。

    flutter run -d web-server --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

## PWA としてインストールする
`flutter run` は manifest を生成しないため、その状態ではインストールの確認ができません  
（DevTools が「`name` が無い」「`display` が不正」「アイコンが無い」とまとめて報告します。`manifest.json` 自体は正しいです）。  
ビルドした出力を配信してください。

    flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
    cd build/web
    python -m http.server 5610

普段お使いの Chrome で `http://localhost:5610/` を開き、アドレスバーからインストールします。  
`redirect_uri` は同じなので、サインインもそのまま試せます。

通知が画面（Message Stream）に届くか OS の通知になるかは、  
アプリのウィンドウが見えているかどうかで決まります。インストールした PWA でも同じです。  
通知をクリックすると、ブラウザのタブではなく、アプリのウィンドウが開きます。

## 他の端末から使う（HTTPS）
同じ PC では、`localhost` は安全な接続として扱われるので、HTTPS は要りません。  
他の端末（スマートフォンなど）から PWA を使うには、次がすべて必要です。

1. 端末が信頼する証明書の HTTPS で、PWA を配信する。
2. 端末が信頼する証明書の HTTPS で、MultiPurposeAuthSite を動かす  
   （ASP.NET Core の開発用証明書は、端末では信頼されない）。
3. PWA の URL を、サーバ側の `AuthenticationDevice_Web` の `redirect_uri` として登録し、  
   同じ URL を `MPAS_WEB_REDIRECT_URI` でアプリにも渡す。
4. iOS では、ホーム画面に追加した PWA にだけ Web Push が届く（Safari 16.4 以降）。
