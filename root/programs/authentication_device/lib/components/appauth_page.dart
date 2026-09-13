import 'importer.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

// AppAuth呼出
import 'package:flutter_appauth/flutter_appauth.dart';

// プッシュ通知
export 'package:flutter/foundation.dart';
export 'package:firebase_core/firebase_core.dart';
export 'package:firebase_messaging/firebase_messaging.dart';
export 'package:flutter_local_notifications/flutter_local_notifications.dart';

class AppAuthPage extends StatefulWidget {
  AppAuthPage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _AppAuthPageState createState() => _AppAuthPageState();
}

class _AppAuthPageState extends State<AppAuthPage> {
  String _display = "hoge";

  // FlutterAppAuth
  final FlutterAppAuth _appAuth = FlutterAppAuth();

  String? _codeVerifier;
  String? _authorizationCode;
  String? _accessToken;

  final List<String> _scopes = <String>[
    'openid',
    'email'
  ];

  @override
  void initState() {
    super.initState();

    // Firebase を初期化していない（web で構成が無い）ときは、FirebaseMessaging を使わない（#205）
    if (AppFcm.enabled) {
      // ターミネーテッド状態でプッシュ通知からアプリを起動した時のアクションを実装
      FirebaseMessaging.instance
        .getInitialMessage()
        .then((RemoteMessage? message) {
          if (message != null) {
            // メッセージ詳細画面へ遷移
            Navigator.pushNamed(context, '/message',
              arguments: MessageArguments(message, true));
          }
        });

      // Android のフォアグラウンドプッシュ通知受信時アクションを設定
      //   (iOSと異なり、)Androidではアプリがフォアグラウンド状態で
      //   画面上部にプッシュ通知メッセージを表示することができない為、
      //   ローカル通知で擬似的に通知メッセージを表示する。
      FirebaseMessaging.onMessage.listen((RemoteMessage? message) {
        print("ローカル通知で擬似的に通知メッセージを表示");
        RemoteNotification? notification = message?.notification;
        AndroidNotification? android = message?.notification?.android;
        if (AppFcm.flutterLocalNotificationsPlugin != null
            && notification != null && android != null && !kIsWeb) {

          AppFcm.flutterLocalNotificationsPlugin?.show(
            id: notification.hashCode,
            title: notification.title,
            body: notification.body,
            notificationDetails: NotificationDetails(
              android: AndroidNotificationDetails(
                AppFcm.channel.id,
                AppFcm.channel.name,
                channelDescription: AppFcm.channel.description,
                // TODO add a proper drawable resource to android, for now using
                //      one that already exists in example app.
                icon: 'notification_icon',
              ),
            )
          );
        }
      });

      // バックグラウンド状態でプッシュ通知からアプリを起動した時のアクションを実装する
      FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
        print('A new onMessageOpenedApp event was published!');
        // メッセージ詳細画面へ遷移
        Navigator.pushNamed(context, '/message',
          arguments: MessageArguments(message, true));
      });

      // FCMトークンの取得
      this._getFcmToken();

      // FCMトークンの更新
      AppFcm.tokenStream = FirebaseMessaging.instance.onTokenRefresh;
      AppFcm.tokenStream?.listen(setToken);
    }

    // Accessトークンの確認と処理
    Future(() async {
      // web : 認証サイトから認可応答で戻ってきたのなら、トークンに交換して保存する（#205）
      if (kIsWeb) {
        final String? token = await WebSignIn.completeIfReturned(Uri.base);
        if (token != null) {
          await AppAuth.setTokenValue(token);
          print('サインインしました（アクセス トークンを保存しました）。');
        }
      }

      this._accessToken = await AppAuth.getTokenValue();
      // getTokenValue() はトークンが無いと "" を返す（null にならない）。
      // != null で判定すると、未サインインでも起動のたびに登録を呼んでしまう。
      if(this._accessToken?.isNotEmpty ?? false)
      {
        await this._registerFcmTokenApi();
      }
    });
  }

  // FCMトークンの設定
  void setToken(String? token) {
    print('FCM Token: $token');
    AppFcm.token = token;
  }

  // FCMトークンの取得
  //   web では、Web Push を受ける service worker を指定する（Android / iOS では無視される）。
  Future<String?> _getFcmToken() async {
    try {
      final String? token = await FirebaseMessaging.instance.getToken(
          vapidKey: AppFcm.vapidKey.isEmpty ? null : AppFcm.vapidKey,
          serviceWorkerScriptPath: kIsWeb ? AppFirebaseWeb.serviceWorkerPath : null);
      this.setToken(token);
      return token;
    } catch (e) {
      print('FCM のトークンを取得できません: $e');
      return null;
    }
  }

  Future<void> _signInWithNoCodeExchange() async {
    // web は flutter_appauth が使えないので、自前の実装で認可要求を始める（#205）。
    // 認証サイトから戻ってきた後の続きは、initState の WebSignIn.completeIfReturned。
    if (kIsWeb) {
      await WebSignIn.start();
      return;
    }

    try {
      final AuthorizationResponse? result
        = await this._appAuth.authorize(AuthorizationRequest(
          AppAuth.clientId, AppAuth.redirectUrl,
          discoveryUrl: AppAuth.discoveryUrl, scopes: this._scopes),
        );

      if (result != null) {
        print("AuthorizationRequest was returned the response.");
        print("authorizationCode: " + result.authorizationCode!.toString());
        this._codeVerifier = result.codeVerifier;
        this._authorizationCode = result.authorizationCode!;
        await this._exchangeCode();
      }
      else {
        print("AuthorizationResponse is null");
      }
    } catch (e) {
      print(e);
    }
  }

  Future<void> _exchangeCode() async {
    try {
      final TokenResponse? result = await this._appAuth.token(
        TokenRequest(
          AppAuth.clientId, AppAuth.redirectUrl,
          authorizationCode: this._authorizationCode,
          discoveryUrl: AppAuth.discoveryUrl,
          codeVerifier: this._codeVerifier,
          scopes: this._scopes
        )
      );
      if (result != null) {
        this._accessToken = result.accessToken;
        await AppAuth.setTokenValue(this._accessToken);
        await this._registerFcmTokenApi();
      }
      else {
        print("TokenResponse is null");
      }
    } catch (e) {
      print(e);
    }
  }

  Future<void> _registerFcmTokenApi() async {
    String? accessToken = await AppAuth.getTokenValue();

    // 端末のトークン（FCM）。Firebase を初期化していなければ、登録するものが無い（#205）。
    if (!AppFcm.enabled) {
      print('Firebase を初期化していないため、端末の登録（/SetDeviceToken）を省略します。');
      return;
    }

    // 起動直後は、initState の getToken が終わる前に呼ばれることがある。ここで取得を待つ。
    String? deviceToken = await this._getFcmToken();
    if (deviceToken == null || deviceToken.isEmpty) {
      print('FCM のトークンを取得できないため、端末の登録（/SetDeviceToken）を省略します。');
      return;
    }

    http.Response response;
    try {
      response = await http.post(
        Uri.parse(AppAuth.setDeviceTokenEndpoint),
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "Bearer ${accessToken}",
        },
        body: {
          "device_token" : deviceToken,
        });
    } catch (e) {
      // 接続できない（接続先の誤り、CORS、サーバの停止など）。起動を止めず、記録だけする。
      print('Request failed: $e');
      return;
    }
    if (response.statusCode == 200) {
      if(response.body == "\"OK\"") // AuthZ(N)の仕様による
      {
        // 初期化完了
        AppConfig.initialized = true;
        // 画面遷移
        while (Navigator.of(context).canPop()) {
          Navigator.of(context).pop();
        }
        Navigator.of(context).pushNamed("/mypage");
      }
      else {
        print('Request failed with body: ${response.body}.');
      }
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: SizedBox.expand(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: <Widget>[
            MyElevatedButton('SignIn Button', this._signInWithNoCodeExchange),
          ],
        ),
      ),
      drawer: MyDrawer(),
    );
  }
}