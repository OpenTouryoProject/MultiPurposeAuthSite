
// トークン永続化
import 'package:shared_preferences/shared_preferences.dart';

// ...
import 'package:authentication_device/configs/app_config.dart';

class AppAuth {
  // static const String clientId = 'interactive.public';
  // static const String redirectUrl = 'io.identityserver.demo:/oauthredirect';
  // static const String discoveryUrl =
  //     'https://demo.identityserver.io/.well-known/openid-configuration';

  // Android / iOS（flutter_appauth）
  static const String clientId = '40319c0100f94ff3aab3004c8bdb5e52';
  static const String redirectUrl = 'com.opentouryo:/oauthredirect';

  // web（認可コード + PKCE を自前で実装する。components/web_sign_in.dart。#205）
  //   認証サイトの OAuth2ClientsInformation に AuthenticationDevice_Web として登録してある
  //   （パブリック クライアント。client_secret は無い）。
  //   redirect_uri は登録値との完全一致で照合されるので、flutter run は --web-port 5610 で起動する。
  static const String webClientId = 'aad529f7f9b6428a84c59ac15aef0cdb';
  static const String webRedirectUrl = String.fromEnvironment(
      'MPAS_WEB_REDIRECT_URI', defaultValue: 'http://localhost:5610/');

  // Endpoints
  //   接続先は AppConfig.mpasBaseUrl から組み立てる（#205）。
  //   以前は http:// を直書きしていたが、HTTPS で配信する PWA からは mixed content として拒否される。
  static const String authorizeEndpoint = "${AppConfig.mpasBaseUrl}/authorize";
  static const String tokenEndpoint = "${AppConfig.mpasBaseUrl}/token";
  static const String userinfoEndpoint = "${AppConfig.mpasBaseUrl}/userinfo";
  static const String setDeviceTokenEndpoint = "${AppConfig.mpasBaseUrl}/SetDeviceToken";
  static const String cibaPushResultEndpoint = "${AppConfig.mpasBaseUrl}/ciba_result";
  // 2FA のプッシュ承認（#213）。受け取ったコードを送り返す。
  static const String twoFactorPushResultEndpoint = "${AppConfig.mpasBaseUrl}/2fa_result";
  static const String discoveryUrl =
    "${AppConfig.mpasBaseUrl}/.well-known/openid-configuration";

  static Future<String?> getTokenValue() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    String? token = prefs.getString('access_token');
    return token ?? "";
  }

  static Future<void> setTokenValue(String? token) async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.setString('access_token', token ?? "");
  }

  static Future<void> removeTokenValue() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.remove('access_token');
  }
}