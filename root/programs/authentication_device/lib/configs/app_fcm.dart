// プッシュ通知
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class AppFcm {

  /// Create a [AndroidNotificationChannel] for heads up notifications
  /// ヘッドアップ通知用の[AndroidNotificationChannel]の作成
  static const AndroidNotificationChannel channel = AndroidNotificationChannel(
    'high_importance_channel', // id
    'High Importance Notifications', // title
    'This channel is used for important notifications.', // description
    importance: Importance.high,
  );

  /// Initialize the [FlutterLocalNotificationsPlugin] package.
  /// FlutterLocalNotificationsPlugin]パッケージを初期化します。
  static FlutterLocalNotificationsPlugin? flutterLocalNotificationsPlugin;

  static const vapidKey = '<YOUR_PUBLIC_VAPID_KEY_HERE>';
  static String? token = "hoge";
  static Stream<String>? tokenStream;
}