import 'importer.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

// AppAuth呼出
import 'package:flutter_appauth/flutter_appauth.dart';

class AppAuthPage extends StatefulWidget {
  AppAuthPage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _AppAuthPageState createState() => _AppAuthPageState();
}

class _AppAuthPageState extends State<AppAuthPage> {
  String _display = "hoge";

  // FlutterAppAuth
  final FlutterAppAuth _appAuth = FlutterAppAuth();

  String? _codeVerifier;
  String? _authorizationCode;
  String? _accessToken;

  final List<String> _scopes = <String>[
    'openid',
    'email'
  ];

  final AuthorizationServiceConfiguration _serviceConfiguration =
    const AuthorizationServiceConfiguration(
        AppAuth.authorizationEndpoint,
        AppAuth.tokenEndpoint
    );

  @override
  void initState() {
    super.initState();
  }

  Future<void> _signInWithNoCodeExchange() async {
    try {
      final AuthorizationResponse? result
      = await this._appAuth.authorize(AuthorizationRequest(
          AppAuth.clientId, AppAuth.redirectUrl,
          discoveryUrl: AppAuth.discoveryUrl, scopes: this._scopes),
      );
      if (result != null) {
        print("AuthorizationRequest was returned the response.");
        print("authorizationCode: " + result.authorizationCode!.toString());
        this._codeVerifier = result.codeVerifier;
        this._authorizationCode = result.authorizationCode!;
        await this._exchangeCode();
      }
      else {
        print("AuthorizationResponse is null");
      }
    } catch (e) {
      print(e);
    }
  }

  Future<void> _exchangeCode() async {
    try {
      final TokenResponse? result = await this._appAuth.token(TokenRequest(
          AppAuth.clientId, AppAuth.redirectUrl,
          authorizationCode: this._authorizationCode,
          discoveryUrl: AppAuth.discoveryUrl,
          codeVerifier: this._codeVerifier,
          scopes: this._scopes));
      if (result != null) {
        this._accessToken = result.accessToken;
        AppAuth.accessToken = this._accessToken;
        await this._testApi();
      }
      else {
        print("TokenResponse is null");
      }
    } catch (e) {
      print(e);
    }
  }

  Future<void> _testApi() async {
    final http.Response httpResponse = await http.get(
        Uri.parse('http://mpos-opentouryo.ddo.jp/MultiPurposeAuthSite/userinfo'),
        headers: <String, String>{'Authorization': 'Bearer ' + AppAuth.accessToken!});
    setState(() {
      this._display = httpResponse.statusCode == 200 ?
      httpResponse.body : httpResponse.statusCode.toString();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: <Widget>[
            Column(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: <Widget>[
                Text(
                  'userinfo:',
                ),
                Text(
                  this._display,
                  style: Theme.of(context).textTheme.headline4,
                ),
              ],
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('SignIn Button', this._signInWithNoCodeExchange),
                ]
            ),
          ],
        ),
      ),
      drawer: MyDrawer(),
    );
  }
}