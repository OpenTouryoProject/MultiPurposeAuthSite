// web 用の Firebase 構成（#205）。
//
// web には google-services.json のような構成ファイルの仕組みが無いため、
// FirebaseOptions をコードから渡す必要がある。
// 値は、ビルド（実行）時に --dart-define-from-file=firebase_web.json で渡す。
//
//   flutter run -d chrome --dart-define-from-file=firebase_web.json
//
// firebase_web.json は実際の値を含むので、コミットしない（.gitignore 済み）。
// 項目は firebase_web.sample.json を参照。

import 'package:firebase_core/firebase_core.dart';

class AppFirebaseWeb {
  static const String apiKey = String.fromEnvironment('FIREBASE_API_KEY');
  static const String appId = String.fromEnvironment('FIREBASE_APP_ID');
  static const String messagingSenderId =
      String.fromEnvironment('FIREBASE_MESSAGING_SENDER_ID');
  static const String projectId = String.fromEnvironment('FIREBASE_PROJECT_ID');
  static const String authDomain = String.fromEnvironment('FIREBASE_AUTH_DOMAIN');
  static const String storageBucket =
      String.fromEnvironment('FIREBASE_STORAGE_BUCKET');
  static const String measurementId =
      String.fromEnvironment('FIREBASE_MEASUREMENT_ID');

  /// Web Push 用の VAPID 公開鍵
  /// （Firebase コンソール → プロジェクトの設定 → Cloud Messaging → ウェブプッシュ証明書）。
  static const String vapidKey = String.fromEnvironment('FIREBASE_VAPID_KEY');

  /// FirebaseOptions の必須 4 項目が渡されているか。
  static bool get isConfigured =>
      apiKey.isNotEmpty &&
      appId.isNotEmpty &&
      messagingSenderId.isNotEmpty &&
      projectId.isNotEmpty;

  static FirebaseOptions get options => FirebaseOptions(
        apiKey: apiKey,
        appId: appId,
        messagingSenderId: messagingSenderId,
        projectId: projectId,
        authDomain: authDomain.isEmpty ? null : authDomain,
        storageBucket: storageBucket.isEmpty ? null : storageBucket,
        measurementId: measurementId.isEmpty ? null : measurementId,
      );

  /// Web Push を受ける service worker（web/firebase-messaging-sw.js）のパス。
  ///
  /// service worker は Dart の外で動くため --dart-define を読めない。
  /// そこで、Firebase の初期化に要る項目を、登録 URL のクエリ文字列で渡す。
  static String get serviceWorkerPath => Uri(
        path: 'firebase-messaging-sw.js',
        queryParameters: <String, String>{
          'apiKey': apiKey,
          'appId': appId,
          'messagingSenderId': messagingSenderId,
          'projectId': projectId,
        },
      ).toString();
}
