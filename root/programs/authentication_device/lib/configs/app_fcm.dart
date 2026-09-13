// プッシュ通知
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:authentication_device/configs/app_firebase_web.dart';

class AppFcm {

  /// Create a [AndroidNotificationChannel] for heads up notifications
  /// ヘッドアップ通知用の[AndroidNotificationChannel]の作成
  static const AndroidNotificationChannel channel = AndroidNotificationChannel(
    'high_importance_channel', // id
    'High Importance Notifications', // title
    description: 'This channel is used for important notifications.',
    importance: Importance.high,
  );

  /// Initialize the [FlutterLocalNotificationsPlugin] package.
  /// FlutterLocalNotificationsPlugin]パッケージを初期化します。
  static FlutterLocalNotificationsPlugin? flutterLocalNotificationsPlugin;

  /// Web Push 用の VAPID 公開鍵。web では firebase_web.json から渡す（app_firebase_web.dart）。
  /// Android / iOS では使われない。
  static const vapidKey = AppFirebaseWeb.vapidKey;

  /// Firebase を初期化したか（main.dart で設定）。
  /// web で構成が渡されていないときは false。false のときに FirebaseMessaging を呼ぶと例外になる。
  static bool enabled = false;
  static String? token = "hoge";
  static Stream<String>? tokenStream;
}