
// トークン永続化
import 'package:shared_preferences/shared_preferences.dart';

// ...
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