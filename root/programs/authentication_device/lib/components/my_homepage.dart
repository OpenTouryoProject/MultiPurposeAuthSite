import 'importer.dart';

// パッケージ
import 'package:english_words/english_words.dart';
import 'package:url_launcher/url_launcher.dart';

// Platform呼出
import 'package:flutter/services.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

// プッシュ通知
export 'package:flutter/foundation.dart';
export 'package:firebase_core/firebase_core.dart';
export 'package:firebase_messaging/firebase_messaging.dart';
export 'package:flutter_local_notifications/flutter_local_notifications.dart';

class MyHomePage extends StatefulWidget {
  MyHomePage({Key? key, required this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;
  String _display = "hoge";

  // Platform呼出
  static const platform = const MethodChannel('authentication_device.opentouryo.com/battery');

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
    /*setState(() {
      this._token = token;
    });*/
  }

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      this._display = (this._counter++).toString();
    });
  }

  void _englishWords() {
    setState(() {
      this._display = WordPair.random().asPascalCase;
    });
  }

  void _urlLauncher() async {
    const url = "https://www.osscons.jp/jo5v2ne7n-537/";
    if (await canLaunch(url)) {
      await launch(url);
    } else {
      throw 'Could not Launch $url';
    }
  }

  Future<void> _getBatteryLevel() async {
    String batteryLevel;
    try {
      final int result = await platform.invokeMethod('getBatteryLevel');
      batteryLevel = 'Battery level at $result % .';
    } on PlatformException catch (e) {
      batteryLevel = "Failed to get battery level: '${e.message}'.";
    }
    setState(() {
      this._display = batteryLevel;
    });
  }

  Future<void> _getBooks() async {
    var url =
      Uri.https('www.googleapis.com', '/books/v1/volumes', {'q': '{http}'});

    // Await the http get response, then decode the json-formatted response.
    var response = await http.get(url);
    if (response.statusCode == 200) {
      var jsonResponse =
        jsonDecode(response.body) as Map<String, dynamic>;
      var itemCount = jsonResponse['totalItems'];
      setState(() {
        this._display = itemCount.toString();
      });
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: <Widget>[
            Column(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: <Widget>[
                Text(
                  'You have pushed the button this many times:',
                ),
                Text(
                  '$_display',
                  style: Theme.of(context).textTheme.headline4,
                ),
              ],
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('NextPage Button',() {
                    Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (context) {
                          return MyHomePage(title: 'Flutter Demo Home Page');
                        },
                      ),
                    );
                  }),
                ]
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('EnglishWords Button', this._englishWords),
                  MyElevatedButton('UrlLauncher Button', this._urlLauncher),
                ]
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('BatteryLevel Button', this._getBatteryLevel),
                  MyElevatedButton('GetBooks Button', this._getBooks),
                ]
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: this._incrementCounter,
        tooltip: 'Increment',
        child: Icon(Icons.add),
      ),
      // This trailing comma makes auto-formatting nicer for build methods.
      drawer: MyDrawer(),
    );
  }
}