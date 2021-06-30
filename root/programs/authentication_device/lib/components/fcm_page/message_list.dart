/// FCMテスト画面の通知リスト

import '../importer.dart';

// プッシュ通知
import 'package:firebase_messaging/firebase_messaging.dart';

// ...
import 'package:authentication_device/models/message_arguments.dart';

/// Listens for incoming foreground messages and displays them in a list.
class MessageList extends StatefulWidget {
  @override
  State<StatefulWidget> createState() => _MessageList();
}

class _MessageList extends State<MessageList> {
  List<RemoteMessage> _messages = [];

  @override
  void initState() {
    super.initState();

    // ターミネーテッド状態でプッシュ通知からアプリを起動した時のアクションを実装
    FirebaseMessaging.instance
      .getInitialMessage()
      .then((RemoteMessage? message) {
        if (message != null) {
          setState(() {
            this._messages = [...this._messages, message];
          });
        }
    });

    // Android のフォアグラウンドプッシュ通知受信時アクションを設定
    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      setState(() {
        this._messages = [...this._messages, message];
      });
    });

    // バックグラウンド状態でプッシュ通知からアプリを起動した時のアクションを実装する
    FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
      setState(() {
        this._messages = [...this._messages, message];
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    if (this._messages.isEmpty) {
      return const Text('No messages received');
    }

    return ListView.builder(
        shrinkWrap: true,
        itemCount: this._messages.length,
        itemBuilder: (context, index) {
          RemoteMessage message = this._messages[index];

          return ListTile(
            title: Text(
              message.notification?.title ?? 'no title'),
            subtitle:
              Text(message.sentTime?.toString() ?? DateTime.now().toString()),
            onTap: () => Navigator.pushNamed(context, '/message',
              arguments: MessageArguments(message, false)),
          );
        });
  }
}