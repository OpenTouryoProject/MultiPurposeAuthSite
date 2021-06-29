import 'package:authentication_device/configs/app_config.dart';

// プッシュ通知
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class AppAuth {
  // static const String clientId = 'interactive.public';
  // static const String redirectUrl = 'io.identityserver.demo:/oauthredirect';
  // static const String issuer = 'https://demo.identityserver.io';
  // static const String authorizationEndpoint = "https://demo.identityserver.io/connect/authorize";
  // static const String tokenEndpoint = "https://demo.identityserver.io/connect/token";
  // static const String discoveryUrl =
  //     'https://demo.identityserver.io/.well-known/openid-configuration';

  static const String clientId = '40319c0100f94ff3aab3004c8bdb5e52';
  static const String redirectUrl = 'com.opentouryo:/oauthredirect';
  static const String issuer = 'https://ssoauth.opentouryo.com';
  static const String authorizationEndpoint = "https://${AppConfig.serverFqdn}/MultiPurposeAuthSite/authorize";
  static const String tokenEndpoint = "https://${AppConfig.serverFqdn}/MultiPurposeAuthSite/token";
  static const String discoveryUrl =
      'https://${AppConfig.serverFqdn}/MultiPurposeAuthSite/.well-known/openid-configuration';

  static String? accessToken = "hoge";
}