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
      if (AppFcm.channel != null && AppFcm.flutterLocalNotificationsPlugin != null
          && notification != null && android != null && !kIsWeb) {

        AppFcm.flutterLocalNotificationsPlugin?.show(
          notification.hashCode,
          notification.title,
          notification.body,
          NotificationDetails(
            android: AndroidNotificationDetails(
              AppFcm.channel.id,
              AppFcm.channel.name,
              AppFcm.channel.description,
              // TODO add a proper drawable resource to android, for now using
              //      one that already exists in example app.
              icon: 'notification_icon',
            ),
          ));
      }
    });

    // バックグラウンド状態でプッシュ通知からアプリを起動した時のアクションを実装する
    FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
      print('A new onMessageOpenedApp event was published!');
      // メッセージ詳細画面へ遷移
      Navigator.pushNamed(context, '/message',
        arguments: MessageArguments(message, true));
    });

    // トークンの取得
    FirebaseMessaging.instance
      .getToken(vapidKey: AppFcm.vapidKey)
      .then(setToken);

    // トークンの更新
    AppFcm.tokenStream = FirebaseMessaging.instance.onTokenRefresh;
    AppFcm.tokenStream?.listen(setToken);
  }

  // トークンの設定
  void setToken(String? token) {
    print('FCM Token: $token');
    AppFcm.token = token;
  }

  Future<void> _signInWithNoCodeExchange() async {
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
        AppAuth.accessToken = this._accessToken;
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
    var response = await http.post(
      Uri.parse(AppAuth.setDeviceTokenEndpoint),
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer ${AppAuth.accessToken}",
      },
      body: {
        "device_token" : AppFcm.token,
      });
    if (response.statusCode == 200) {
      // 画面遷移
      while(Navigator.of(context).canPop()){
        Navigator.of(context).pop();
      }
      Navigator.of(context).pushNamed("/mypage");
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