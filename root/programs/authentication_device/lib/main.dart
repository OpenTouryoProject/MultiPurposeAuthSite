// dart
import 'dart:async';
// package
import 'package:flutter/material.dart';

// プッシュ通知
import 'package:flutter/foundation.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

// ...
import 'configs/app_fcm.dart';
import 'components/app.dart';

/// Define a top-level named handler which background/terminated messages will call.
/// バックグラウンド / ターミネーテッド・メッセージが呼び出すトップレベルの名前付きハンドラーを定義。
/// To verify things are working, check out the native platform logs.
/// 動作を確認するには、ネイティブプラットフォームのログを確認します。
Future<void> _firebaseMessagingBackgroundHandler(
RemoteMessage message) async {
// If you're going to use other Firebase services in the background, such as Firestore,
// make sure you call `initializeApp` before using other Firebase services.
// Firestoreなど、他のFirebaseサービスをバックグラウンドで使用する場合
// 他のFirebaseサービスを使用する前に、必ず`initializeApp`を呼び出す。
  await Firebase.initializeApp();
  print('Handling a background message ${message.messageId}');
}

Future<void> main() async {
  // Flutter Engine を使う準備の呪文
  WidgetsFlutterBinding.ensureInitialized();
  // Firebase を初期化
  await Firebase.initializeApp();

  // Set the background messaging handler early on, as a named top-level function
  // バックグラウンド・メッセージング・ハンドラを早い段階で、名前付きのトップレベル関数として設定。
  FirebaseMessaging.onBackgroundMessage(_firebaseMessagingBackgroundHandler);

  if (!kIsWeb) {
    AppFcm.flutterLocalNotificationsPlugin = FlutterLocalNotificationsPlugin();

    /// Create an Android Notification Channel.
    /// We use this channel in the `AndroidManifest.xml` file
    /// to override the default FCM channel to enable heads up notifications.
    /// Android Notification Channelを作成します。
    /// このチャンネルを `AndroidManifest.xml` ファイルで使用して、
    /// デフォルトの FCM チャンネルをオーバーライドし、ヘッドアップ通知を有効化。
    await AppFcm.flutterLocalNotificationsPlugin
        ?.resolvePlatformSpecificImplementation<
        AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(AppFcm.channel);

    /// Update the iOS foreground notification presentation options to allow heads up notifications.
    /// iOSの前景通知の表示オプションを更新し、ヘッドアップ通知を有効化。
    await FirebaseMessaging.instance
        .setForegroundNotificationPresentationOptions(
      alert: true,
      badge: true,
      sound: true,
    );
  }

  runApp(MyApp());
}