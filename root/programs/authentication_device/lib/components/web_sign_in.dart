// web 版のサインイン（認可コード + PKCE を自前で実装する。#205）。
//
// flutter_appauth は web に対応していない（最新の 12.1.0 でも android / ios / macos のみ）。
// 認証サイトは、code_verifier があり client_secret が無いトークン要求を、PKCE として受け付ける
// （CommonLibrary/TokenProviders/CmnEndpoints.cs の GrantAuthorizationCodeCredentials）。
//
// 流れ:
//   1. start()              : state と code_verifier を作って保存し、同じタブで /authorize へ移動する
//   2. （認証サイトでサインイン → redirect_uri へ ?code=...&state=... で戻る）
//   3. completeIfReturned() : 起動時に URL を見る。戻りなら state を照合し、/token で交換する
//
// 参考: OpenTouryoProject/FrontendTemplates の UI/XPlat/flutter_template/lib/touryo（準拠はしない）。

import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import 'package:authentication_device/configs/app_auth.dart';

class WebSignIn {
  static const String _keyState = 'web_sign_in_state';
  static const String _keyCodeVerifier = 'web_sign_in_code_verifier';

  static const List<String> _scopes = <String>['openid', 'email'];

  /// 認可要求を始める（同じタブで認証サイトへ移動する）。
  static Future<void> start() async {
    final String state = _randomString(32);
    final String nonce = _randomString(32);
    // RFC 7636 4.1 : code_verifier は 43〜128 文字の unreserved 文字
    final String codeVerifier = _randomString(64);

    // 戻ってきたときに照合するため、保存しておく（web では localStorage）。
    final SharedPreferences prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyState, state);
    await prefs.setString(_keyCodeVerifier, codeVerifier);

    final Uri uri = Uri.parse(AppAuth.authorizeEndpoint).replace(
      queryParameters: <String, String>{
        'response_type': 'code',
        'client_id': AppAuth.webClientId,
        'redirect_uri': AppAuth.webRedirectUrl,
        'scope': _scopes.join(' '),
        'state': state,
        'nonce': nonce,
        'code_challenge': _s256(codeVerifier),
        'code_challenge_method': 'S256',
      },
    );

    await launchUrl(uri, webOnlyWindowName: '_self');
  }

  /// 認可応答で戻ってきたのなら、トークンに交換してアクセス トークンを返す。
  /// 戻りでない、または失敗したときは null を返す。
  ///
  /// [current] には、web では Uri.base を渡す。
  static Future<String?> completeIfReturned(Uri current) async {
    final Map<String, String> q = current.queryParameters;

    if (q.containsKey('error')) {
      print('認可要求が拒否されました（error=${q['error']}）。');
      await _clear();
      return null;
    }

    final String? code = q['code'];
    final String? state = q['state'];
    if (code == null || state == null) {
      // 認可応答での戻りではない。
      return null;
    }

    final SharedPreferences prefs = await SharedPreferences.getInstance();
    final String? savedState = prefs.getString(_keyState);
    final String? codeVerifier = prefs.getString(_keyCodeVerifier);

    // 一度読んだら消す。URL に code が残ったまま再読み込みしても、同じ code を交換しない。
    await _clear();

    if (savedState == null || codeVerifier == null) {
      // 交換済みの戻り URL を、再読み込みした場合など。
      return null;
    }

    if (savedState != state) {
      print('state が一致しないため、認可応答を破棄しました。');
      return null;
    }

    try {
      final http.Response res = await http.post(
        Uri.parse(AppAuth.tokenEndpoint),
        headers: <String, String>{
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: <String, String>{
          'grant_type': 'authorization_code',
          'code': code,
          'redirect_uri': AppAuth.webRedirectUrl,
          'client_id': AppAuth.webClientId,
          'code_verifier': codeVerifier,
        },
      );

      if (res.statusCode != 200) {
        // 失敗時の本文は error / error_description だけで、トークンは含まない。
        print('トークン要求が失敗しました（HTTP ${res.statusCode}）: ${res.body}');
        return null;
      }

      final dynamic json = jsonDecode(res.body);
      final String? accessToken =
          (json is Map) ? json['access_token'] as String? : null;

      if (accessToken == null || accessToken.isEmpty) {
        print('トークン応答に access_token がありません。');
        return null;
      }

      return accessToken;
    } catch (e) {
      // 接続できない（接続先の誤り、CORS、証明書、サーバの停止など）。
      print('トークン要求に接続できません: $e');
      return null;
    }
  }

  static Future<void> _clear() async {
    final SharedPreferences prefs = await SharedPreferences.getInstance();
    await prefs.remove(_keyState);
    await prefs.remove(_keyCodeVerifier);
  }

  /// 暗号論的な乱数で、unreserved 文字（RFC 3986）だけの文字列を作る。
  static String _randomString(int length) {
    const String chars =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    final Random random = Random.secure();
    return List<String>.generate(
        length, (_) => chars[random.nextInt(chars.length)]).join();
  }

  /// RFC 7636 4.2 : code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))（パディングなし）
  static String _s256(String codeVerifier) {
    final List<int> digest = sha256.convert(ascii.encode(codeVerifier)).bytes;
    return base64Url.encode(digest).replaceAll('=', '');
  }
}
