import '../importer.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

// プッシュ通知
import 'package:firebase_messaging/firebase_messaging.dart';

// ...
import 'package:authentication_device/components/fcm_page/permissions.dart';
import 'package:authentication_device/components/fcm_page/token_checker.dart';
import 'package:authentication_device/components/fcm_page/message_list.dart';

class FcmPage extends StatefulWidget {
  FcmPage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _FcmPageState createState() => _FcmPageState();
}

class _FcmPageState extends State<FcmPage> {
  String _display = "hoge";
  String _token = "";

  @override
  void initState() {
    super.initState();
  }

  Future<void> _onActionSelected(String value) async {
    switch (value) {
      case 'subscribe':
        {
          print('FlutterFire Messaging Example: Subscribing to topic "fcm_test".');
          await FirebaseMessaging.instance.subscribeToTopic('fcm_test');
          print('FlutterFire Messaging Example: Subscribing to topic "fcm_test" successful.');
        }
        break;
      case 'unsubscribe':
        {
          print('FlutterFire Messaging Example: Unsubscribing from topic "fcm_test".');
          await FirebaseMessaging.instance.unsubscribeFromTopic('fcm_test');
          print('FlutterFire Messaging Example: Unsubscribing from topic "fcm_test" successful.');
        }
        break;
      case 'get_apns_token':
        {
          if (defaultTargetPlatform == TargetPlatform.iOS ||
              defaultTargetPlatform == TargetPlatform.macOS) {
            print('FlutterFire Messaging Example: Getting APNs token...');
            String? token = await FirebaseMessaging.instance.getAPNSToken();
            print('FlutterFire Messaging Example: Got APNs token: $token');
          } else {
            print('FlutterFire Messaging Example: Getting an APNs token is only supported on iOS and macOS platforms.');
          }
        }
        break;
      default:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        actions: <Widget>[
          PopupMenuButton(
            onSelected: this._onActionSelected,
            itemBuilder: (BuildContext context) {
              return [
                const PopupMenuItem(
                  value: 'subscribe',
                  child: Text('Subscribe to topic'),
                ),
                const PopupMenuItem(
                  value: 'unsubscribe',
                  child: Text('Unsubscribe to topic'),
                ),
                const PopupMenuItem(
                  value: 'get_apns_token',
                  child: Text('Get APNs token (Apple only)'),
                ),
              ];
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: <Widget>[
            Column(children: [
              MetaCard('Permissions', Permissions()),
              MetaCard('FCM Token', TokenChecker((token) {
                _token = token;
                return token == null
                    ? const CircularProgressIndicator()
                    : Text(token, style: const TextStyle(fontSize: 12));
              })),
              MetaCard('Message Stream', MessageList()),
            ])
          ],
        ),
      ),
      drawer: MyDrawer(),
    );
  }
}