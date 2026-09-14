// web 版で、通知のクリックから開かれたときの処理（#205 増分 3）。
//
// バックグラウンドで届いた通知は、OS の通知として表示される。
// そのクリックは、service worker（web/firebase-messaging-sw.js）が受け取り、
// 通知の中身を URL のクエリに載せてアプリを開く（または、開いているタブを移す）。
//
//   push_title      : 通知のタイトル（"CIBA" / "2FA"）
//   push_body       : 通知の本文
//   push_data_<キー> : 通知のデータ（例 : push_data_auth_req_id / push_data_binding_message）
//
// firebase_messaging_web には onMessageOpenedApp の実装が無く、getInitialMessage() も常に null を返すため、
// この方法で受け渡す。

import 'package:firebase_messaging/firebase_messaging.dart';

class WebPushClick {
  static const String _keyTitle = 'push_title';
  static const String _keyBody = 'push_body';
  static const String _prefixData = 'push_data_';

  /// URL に通知の中身が載っていれば、RemoteMessage を組み立てて返す。載っていなければ null。
  ///
  /// [uri] には、web では Uri.base を渡す。
  static RemoteMessage? fromUri(Uri uri) {
    final Map<String, String> q = uri.queryParameters;

    if (!q.containsKey(_keyTitle)) {
      return null;
    }

    final Map<String, dynamic> data = <String, dynamic>{};
    q.forEach((String key, String value) {
      if (key.startsWith(_prefixData)) {
        data[key.substring(_prefixData.length)] = value;
      }
    });

    return RemoteMessage(
      data: data,
      notification: RemoteNotification(
        title: q[_keyTitle],
        body: q[_keyBody],
      ),
    );
  }
}
