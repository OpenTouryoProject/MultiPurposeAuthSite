import 'package:authentication_device/configs/app_config.dart';

class AppAuth {
  // static const String clientId = 'interactive.public';
  // static const String redirectUrl = 'io.identityserver.demo:/oauthredirect';
  // static const String discoveryUrl =
  //     'https://demo.identityserver.io/.well-known/openid-configuration';

  static const String clientId = '40319c0100f94ff3aab3004c8bdb5e52';
  static const String redirectUrl = 'com.opentouryo:/oauthredirect';

  // Endpoints
  static const String userinfoEndpoint =  // テストなので、HTTP
    "http://${AppConfig.serverFqdn}/MultiPurposeAuthSite/userinfo";
  static const String setDeviceTokenEndpoint =
    "http://${AppConfig.serverFqdn}/MultiPurposeAuthSite/SetDeviceToken";
  static const String cibaPushResultEndpoint =
    "http://${AppConfig.serverFqdn}/MultiPurposeAuthSite/ciba_result";
  static const String discoveryUrl =
    "https://${AppConfig.serverFqdn}/MultiPurposeAuthSite/.well-known/openid-configuration";

  static String? accessToken = "hoge";
}