/// FCMテスト画面のトークン情報

import 'package:flutter/material.dart';
import 'package:authentication_device/configs/app_fcm.dart';

/// Manages & returns the users FCM token.
/// Also monitors token refreshes and updates state.
class TokenChecker extends StatefulWidget {
  // ignore: public_member_api_docs
  TokenChecker(this._builder);
  // ...
  final Widget Function(String token) _builder;

  @override
  State<StatefulWidget> createState() => _TokenChecker();
}

class _TokenChecker extends State<TokenChecker> {
  String? _token = AppFcm.token;

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return widget._builder(this._token ?? "");
  }
}