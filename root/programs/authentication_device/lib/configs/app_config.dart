class AppConfig {
  static bool initialized = false;

  /// 接続先（汎用認証サイトのルート URL）（#205）。
  ///
  /// --dart-define-from-file で渡す。ローカル用の設定をコミットしてある。
  ///   mpas.core.json  : net10.0 版（https://localhost:44300）
  ///   mpas.netfx.json : net48 版（https://localhost:44302）
  /// 渡さないときは、ローカルの net10.0 版。
  ///
  /// **サイトが実際に待ち受けている URL を渡す。**
  /// 構成ファイルの OAuth2AuthorizationServerEndpointsRootURI（…/MultiPurposeAuthSite）とは限らない。
  /// test.ps1 で起動したサイトは、エンドポイントがルート直下にある（E2E と同じ）。
  /// Android の実機からは localhost に届かないので、届く URL を書いたファイルを渡す。
  static const String mpasBaseUrl = String.fromEnvironment(
      'MPAS_BASE_URL', defaultValue: 'https://localhost:44300');
}