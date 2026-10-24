//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の 自己テストの RP
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//**********************************************************************************

/*
自己テストの RP（Redirect エンドポイントでのトークンの取得・検証・更新・失効・照会、
Front-Channel / Back-Channel Logout の受け口）を担うAccountControllerの一部（本番の口ではない）
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 自己テストの RP**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region テスト用（LoadRequestParameters）

        /// <summary>LoadRequestParameters</summary>
        /// <param name="clientId">out string</param>
        /// <param name="state">out string</param>
        /// <param name="redirect_uri">out string</param>
        /// <param name="nonce">out string</param>
        /// <param name="code_verifier">out string</param>
        private void LoadRequestParameters(
            out string clientId,
            out string state, out string redirect_uri,
            out string nonce, out string code_verifier)
        {
            IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            // client_id
            clientId = HttpContext.Session.GetString(Const.TestClientId);
            if (!string.IsNullOrEmpty(clientId))
            {
                HttpContext.Session.SetString(Const.TestClientId, "");
            }
            else
            {
                clientId = requestCookies.Get(Const.TestClientId);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestClientId, "", this._cookieOptions);
                }
            }

            // state
            state = HttpContext.Session.GetString(Const.TestState);
            if (!string.IsNullOrEmpty(state))
            {
                HttpContext.Session.SetString(Const.TestState, "");
            }
            else
            {
                state = requestCookies.Get(Const.TestState);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestState, "", this._cookieOptions);
                }
            }

            // redirect_uri
            redirect_uri = HttpContext.Session.GetString(Const.TestRedirectUri);
            if (!string.IsNullOrEmpty(redirect_uri))
            {
                HttpContext.Session.SetString(Const.TestRedirectUri, "");
            }
            else
            {
                redirect_uri = requestCookies.Get(Const.TestRedirectUri);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestRedirectUri, "", this._cookieOptions);
                }
            }

            // nonce
            nonce = HttpContext.Session.GetString(Const.TestNonce);
            if (!string.IsNullOrEmpty(nonce))
            {
                HttpContext.Session.SetString(Const.TestNonce, "");
            }
            else
            {
                nonce = requestCookies.Get(Const.TestNonce);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestNonce, "", this._cookieOptions);
                }
            }

            // code_verifier
            code_verifier = HttpContext.Session.GetString(Const.TestCodeVerifier);
            if (!string.IsNullOrEmpty(code_verifier))
            {
                HttpContext.Session.SetString(Const.TestCodeVerifier, "");
            }
            else
            {
                code_verifier = requestCookies.Get(Const.TestCodeVerifier);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestCodeVerifier, "", this._cookieOptions);
                }
            }
        }
        #endregion

        #region Client (Redirectエンドポイント)

        #region Authorization Codeグラント種別

        /// <summary>
        /// Authorization Codeグラント種別のClientエンドポイント
        /// 認可レスポンス（仲介コード）を受け取って処理する。
        /// ・仲介コードを使用してAccess Token・Refresh Tokenを取得
        /// </summary>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <param name="response">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-resp"/>
        /// <seealso cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req"/>
        // [HttpGet] // Response Mode & JARM 対応
        [AllowAnonymous]
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient(string code, string state, string response)
        {
            if (!Config.IsLockedDownTestEndpoints)
            {
                if (!string.IsNullOrEmpty(code)
                    || !string.IsNullOrEmpty(response))
                {
                    // query(.jwt)、form_post(.jwt)のカバレッジ

                    // LoadRequestParameters
                    string clientId_InSessionOrCookie = "";
                    string state_InSessionOrCookie = "";
                    string redirect_uri_InSessionOrCookie = "";
                    string nonce_InSessionOrCookie = "";
                    string code_verifier_InSessionOrCookie = "";
                    this.LoadRequestParameters(
                        out clientId_InSessionOrCookie,
                        out state_InSessionOrCookie,
                        out redirect_uri_InSessionOrCookie,
                        out nonce_InSessionOrCookie,
                        out code_verifier_InSessionOrCookie);

                    //    | 渡すもの | 値 |
                    //    |---|---|
                    //    | 鍵（`jws`） | **null**（自分が出したトークンなので、設定の選び方で引ける） |
                    //    | `iss` | **`CmnServerParams.IssuerId`（自分）** — **`SpRp_Isser` は「相手の Issuer」**である |
                    //    | `aud` | **その回の `client_id`** |
                    if (!string.IsNullOrEmpty(response))
                    {
                        // responseObject検証
                        if (ResponseObject.Verify(response,
                            null, CmnServerParams.IssuerId, clientId_InSessionOrCookie,
                            out JObject responseObject))
                        {
                            // OK
                            code = (string)responseObject[OAuth2AndOIDCConst.code];
                            state = (string)responseObject[OAuth2AndOIDCConst.state];
                        }
                        else
                        {
                            // NG
                        }
                    }

                    // Tokenエンドポイントにアクセス
                    Uri tokenEndpointUri = new Uri(
                        Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;
                    OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                    {
                        ClientId = clientId_InSessionOrCookie,
                        State = state,
                        Code = code
                    };

                    #region 仲介コードを使用してAccess, Refresh, Id Tokenを取得

                    string fapi1Prefix = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":";
                    string fapi2Prefix = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":";

                    //stateの検証
                    if (state == state_InSessionOrCookie
                        || state == fapi1Prefix + state_InSessionOrCookie  // specではなくテスト仕様
                        || state == fapi2Prefix + state_InSessionOrCookie) // specではなくテスト仕様
                    {
                        //state正常
                        if (state == null) state = ""; // null対策（テスト）

                        // 仲介コードからAccess Tokenを取得する。

                        // redirect_uriを設定
                        string redirect_uri = "";
                        if (string.IsNullOrEmpty(redirect_uri_InSessionOrCookie))
                        {
                            // 指定なしの場合のテストケース（指定不要
                        }
                        else
                        {
                            // 指定ありの場合のテストケース（指定必要
                            redirect_uri = redirect_uri_InSessionOrCookie;
                        }

                        // Tokenエンドポイントにアクセス
                        if (state.StartsWith(fapi1Prefix))
                        {
                            // FAPI1

                            // **アサーションの組み立ては SelfTestClient**（#246）。
                            model.AuthMethod = Resources.AccountController.AuthMethodFapi1;

                            model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                Sts.SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.SelfTestScopes));
                        }
                        else if (state.StartsWith(fapi2Prefix))
                        {
                            // FAPI2

                            // **private_key_jwt で交換する**（#246）。
                            //   FAPI 2.0 が認めるのは MTLS と private_key_jwt の 2 つ。
                            //   以前は client_secret を空で送り、**クライアント証明書（TB）が付くことを前提**に
                            //   していたが、自己テストのクライアントは
                            //   ClientCertPfxFilePath が設定されていなければ証明書を添えない。
                            //   **設定が無い配置では /token が 401（invalid_client）になり、
                            //   自己テストが結果画面まで通らなかった**（/ros でも /par でも同じ）。
                            //   **証明書の配置を前提にしない private_key_jwt に寄せる。**
                            //   mTLS の経路は E2E（FA-6）が測る。

                            // **アサーションの組み立ては SelfTestClient**（#246）。
                            model.AuthMethod = Resources.AccountController.AuthMethodFapi2;

                            model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                Sts.SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.OidcScopes));
                        }
                        else
                        {
                            // OAuth2 / OIDC

                            //  client_Idから、client_secretを取得。
                            string client_id = clientId_InSessionOrCookie;
                            string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                            if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
                            {
                                // 通常
                                //   **Open棟梁 のクライアントは、この経路を Basic で送る**
                                //   （既定が client_secret_basic。#246 の項目 3）。
                                model.AuthMethod = Resources.AccountController.AuthMethodClientSecretBasic;

                                model.Response = await Sts.Helper.GetInstance()
                                    .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                    client_id, client_secret, redirect_uri, code);
                            }
                            else
                            {
                                // PKCE
                                //   **PKCE の経路は既定が client_secret_post**（Basic ではない。#246 の項目 3）。
                                //   PKCE 自体はクライアント認証ではないので、code_verifier は別に送る。
                                model.AuthMethod = Resources.AccountController.AuthMethodClientSecretPostPkce;

                                model.Response = await Sts.Helper.GetInstance()
                                   .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                   client_id, client_secret, redirect_uri,
                                   code, code_verifier_InSessionOrCookie);
                            }
                        }

                        dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);
                    }
                    else
                    {
                        // state異常
                        dic = new Dictionary<string, string>();
                        dic.Add(OAuth2AndOIDCConst.error, "state error.");
                    }

                    #endregion

                    #region Access, Refresh, Id Tokenの検証と表示

                    if (!dic.ContainsKey(OAuth2AndOIDCConst.error))
                    {
                        string out_sub = "";
                        JObject out_jobj = null;

                        if (dic.ContainsKey(OAuth2AndOIDCConst.AccessToken))
                        {
                            model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken];
                            model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                                   CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);


                            if (!string.IsNullOrEmpty(model.AccessToken))
                            {
                                if (!AccessToken.Verify(model.AccessToken,
                                out out_sub, out List<string> out_roles, out List<string> out_scopes, out out_jobj))
                                {
                                    throw new Exception(Resources.AccountController.AccessTokenVerificationError);
                                }
                            }
                            else
                            {
                                throw new Exception(Resources.AccountController.AccessTokenVerificationError);
                            }
                        }

                        if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                        {
                            model.IdToken = dic[OAuth2AndOIDCConst.IDToken];

                            if (!string.IsNullOrEmpty(model.IdToken))
                            {
                                if (!IdToken.Verify(
                                    model.IdToken, model.AccessToken, code, state,
                                    null, CmnServerParams.IssuerId, clientId_InSessionOrCookie,
                                    out out_sub, out string out_nonce, out out_jobj)
                                    && out_nonce == nonce_InSessionOrCookie)
                                {
                                    throw new Exception(Resources.AccountController.IdTokenVerificationError);
                                }
                            }
                            else
                            {
                                throw new Exception(Resources.AccountController.IdTokenVerificationError);
                            }

                            // 暗号化解除のケースがあるので、jobjを使用。
                            model.IdTokenJwtToJson = out_jobj.ToString();
                        }

                        model.RefreshToken = dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken) ? dic[OAuth2AndOIDCConst.RefreshToken] : "";

                        // 画面の表示。
                        return View(model);
                    }
                    #endregion
                }
                else
                {
                    // fragmentのカバレッジ
                    // そのまま画面を出し、画面側でfragmentを処理
                    return View(new OAuth2AuthorizationCodeGrantClientViewModel());
                }
            }
            else
            {
                // IsLockedDownTestEndpoints == true;
            }

            // エラー
            return View("Error");
        }

        /// <summary>
        /// Tokenを使った処理のテストコード
        /// ・Refresh Tokenを使用してAccess Tokenを更新
        /// ・Access Tokenを使用してResourceServerのWebAPIにアクセス
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="refreshToken"></param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient2(OAuth2AuthorizationCodeGrantClientViewModel model)
        {
            if (!Config.IsLockedDownTestEndpoints)
            {
                // AccountVerifyCodeViewModelの検証
                if (ModelState.IsValid)
                {
                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;

                    if (!string.IsNullOrEmpty(Request.Form["submit.GetUserClaims"]))
                    {
                        // UserInfoエンドポイントにアクセス
                        model.Response = await Sts.Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Refresh"]))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                        // Tokenエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().
                            UpdateAccessTokenByRefreshTokenAsync(
                            tokenEndpointUri, client_id, client_secret, model.RefreshToken);

                        dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                        if (dic.ContainsKey(OAuth2AndOIDCConst.AccessToken))
                        {
                            model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken];
                            model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                                CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);
                        }

                        if (dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken))
                        {
                            model.RefreshToken = dic[OAuth2AndOIDCConst.RefreshToken] ?? "";
                        }

                        #endregion
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.RevokeAccess"])
                        || !string.IsNullOrEmpty(Request.Form["submit.RevokeRefresh"]))
                    {
                        #region Revokeエンドポイントで、Tokenを無効化

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form["submit.RevokeAccess"]))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form["submit.RevokeRefresh"]))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri revokeTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint);

                        // Revokeエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().RevokeTokenAsync(
                            revokeTokenEndpointUri, client_id, client_secret, token, token_type_hint);

                        #endregion
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectAccess"])
                        || !string.IsNullOrEmpty(Request.Form["submit.IntrospectRefresh"]))
                    {
                        #region Introspectエンドポイントで、Token情報を取得

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectAccess"]))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectRefresh"]))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri introspectTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint);

                        // Introspectエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().IntrospectTokenAsync(
                            introspectTokenEndpointUri, client_id, client_secret, token, token_type_hint);

                        #endregion
                    }
                    else
                    {
                        // ・・・
                    }
                }

                // 画面の表示。
                ModelState.Clear();
                return View("OAuth2AuthorizationCodeGrantClient", model);
            }
            else
            {
                return View("Error");
            }
        }

        #endregion

        #region Implicitグラント種別

        /// <summary>
        /// Implicitグラント種別
        /// Access Token発行後のAccess Token利用画面を返す。
        /// Parameterは、Fragment以下のQueryStringとして返り、これをUserAgent側で処理する。
        /// 
        /// "・・・#access_token=XXXXX&state=YYYY&token_type=Bearer&expires_in=nnnn"
        /// 
        /// 色々調査した所、Fragmentは、ServerからをRedirect可能だが、
        /// Server Side CodeやDebug ProxyからではFragmentを捕捉できない模様。
        /// 従って、Fragmentは、UserAgent側でしか取得＆処理できない。
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#implicit-authz-resp"/>
        // [HttpGet] // Response Mode & JARM 対応
        [AllowAnonymous]
        public ActionResult OAuth2ImplicitGrantClient(
            string access_token, string id_token, string code, string state,
            string token_type, string expires_in, string response)
        {
            if (!Config.IsLockedDownTestEndpoints)
            {
                // OAuth2のREQUIREDは、access_token, token_type, state
                if (!string.IsNullOrEmpty(state)
                   || !string.IsNullOrEmpty(response))
                {
                    // query(.jwt)、form_post(.jwt)のカバレッジ

                    // JARM
                    if (!string.IsNullOrEmpty(response))
                    {
                        string clientId_InSessionOrCookie = "";
                        string state_InSessionOrCookie = "";
                        string redirect_uri_InSessionOrCookie = "";
                        string nonce_InSessionOrCookie = "";
                        string code_verifier_InSessionOrCookie = "";
                        this.LoadRequestParameters(
                            out clientId_InSessionOrCookie,
                            out state_InSessionOrCookie,
                            out redirect_uri_InSessionOrCookie,
                            out nonce_InSessionOrCookie,
                            out code_verifier_InSessionOrCookie);

                        // responseObject検証
                        if (ResponseObject.Verify(response,
                            null, CmnServerParams.IssuerId, clientId_InSessionOrCookie,
                            out JObject responseObject))
                        {
                            // OK
                            access_token = (string)responseObject[OAuth2AndOIDCConst.AccessToken];
                            id_token = (string)responseObject[OAuth2AndOIDCConst.IDToken];
                            code = (string)responseObject[OAuth2AndOIDCConst.code];
                            state = (string)responseObject[OAuth2AndOIDCConst.state];
                            token_type = (string)responseObject[OAuth2AndOIDCConst.token_type];
                            expires_in = (string)responseObject[OAuth2AndOIDCConst.expires_in];
                            //scope = (string)responseObject[OAuth2AndOIDCConst.scope];
                        }
                        else
                        {
                            // NG
                        }
                    }

                    // 画面の表示。
                    // form_post(.jwt)
                    ViewData["FormPost"] = JsonConvert.SerializeObject(
                        new
                        {
                            access_token,
                            id_token,
                            code,
                            state,
                            token_type,
                            expires_in
                        });
                    return View();// model);
                }
                else
                {
                    // fragment(.jwt)のカバレッジ

                    // ココでstateの検証を予定していたが、コメントヘッダに有るように、ココでは実装できなかった。
                    // stateは、JWTにnonce Claimとして格納してあるため、必要であれば、UserAgent側で検証できる。

                    // そのまま画面を出し、画面側でfragmentを処理
                    return View();
                }
            }

            return View("Error");
        }

        #endregion

        #endregion

        #region Front-Channel Logout の受け口（自己テスト。#310 の段階 3）

        /// <summary>
        /// 自己テストの RP として、`iframe` で叩かれたことを覚える
        /// GET: /Account/FrontChannelLogoutClient
        /// </summary>
        /// <param name="iss">iss（どの OP か）</param>
        /// <param name="sid">sid（どのセッションか）</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **測るためだけに在る口**である（**`IsLockedDownTestEndpoints` で閉じる**）。
        ///
        /// **本来はブラウザが `iframe` で開く。**
        /// **E2E のクライアントは `iframe` を開かない**ので、
        /// **テストが画面から URL を取り出して、自分で叩く**（**ブラウザの代わりをする**）。
        ///
        /// **ここでは検証しない。** **覚えておくだけ**である（`TestFrontChannelLogoutBox`）。
        /// **`iss` と `sid` が付いていることを確かめるのは E2E の側。**
        ///
        /// **本物の RP は、ここで自分のセッションを閉じる**
        /// （**`sid` で、どのセッションかを決める**）。
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult FrontChannelLogoutClient(string iss, string sid)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return this.NotFound();
            }

            Sts.TestFrontChannelLogoutBox.Add(iss, sid);

            // オペレーション・トレース・ログ出力
            //   **値は出さない**（`sid` はセッションの識別子である）。
            Logging.MyOperationTrace("The self-test RP was called by front-channel logout.");

            // **中身は要らない**（`iframe` の中なので、見えない）。
            return this.Ok();
        }

        /// <summary>
        /// `iframe` で叩かれた記録を返す（測るため）
        /// GET: /Account/FrontChannelLogoutBox
        /// </summary>
        /// <param name="clear">true なら、返した後に空にする</param>
        /// <returns>ActionResult（JSON）</returns>
        /// <remarks>
        /// **測るためだけに在る口**である（**`IsLockedDownTestEndpoints` で閉じる**）。
        /// **`iss` と `sid` をそのまま返す** — **E2E が中身を確かめる**ため。
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult FrontChannelLogoutBox(bool clear = false)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return this.NotFound();
            }

            List<string> hits = Sts.TestFrontChannelLogoutBox.GetAll();

            if (clear)
            {
                // **測る前に空にする**ために在る。
                Sts.TestFrontChannelLogoutBox.Clear();
            }

            return this.Json(new { frontchannel_hits = hits });
        }

        #endregion

        #region Back-Channel Logout の受け口（自己テスト。#310 の段階 2）

        /// <summary>
        /// 自己テストの RP として logout_token を受け取る
        /// POST: /Account/BackChannelLogoutClient
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **測るためだけに在る口**である（**`IsLockedDownTestEndpoints` で閉じる**）。
        ///
        /// **Back-Channel Logout は「OP が RP を叩く」**ので、
        /// **RP の側に口が無いと、送れたことを確かめられない。**
        /// **E2E のクライアントは HTTP サーバを持たない**ので
        /// （#309 で `jwks_uri` の足場を別に立てたのと同じ事情）、
        /// **このサイトが自分の RP も兼ねる**（`test_self_code` と同じ考え方）。
        ///
        /// **ここでは検証しない。** **覚えておくだけ**である（`TestLogoutTokenBox`）。
        /// **署名・`events`・`sid` を確かめるのは E2E の側**
        /// （**RP が何を確かめるべきか**は、テストに書いた方が読める）。
        ///
        /// **200 を返す**（Back-Channel Logout 1.0 §2.6）。**本文が無ければ 400。**
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        public ActionResult BackChannelLogoutClient()
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return this.NotFound();
            }

            string logoutToken = MyHttpContext.Current.Request.HasFormContentType
                ? MyHttpContext.Current.Request.Form[Const.LogoutToken].ToString() : "";

            if (string.IsNullOrEmpty(logoutToken))
            {
                return this.BadRequest();
            }

            Sts.TestLogoutTokenBox.Add(logoutToken);

            // オペレーション・トレース・ログ出力
            //   **値は出さない**（`logout_token` には `sub` と `sid` が入っている）。
            Logging.MyOperationTrace("The self-test RP received a logout_token.");

            return this.Ok();
        }

        /// <summary>
        /// 受け取った logout_token を返す（測るため）
        /// GET: /Account/BackChannelLogoutBox
        /// </summary>
        /// <param name="clear">true なら、返した後に空にする</param>
        /// <returns>ActionResult（JSON）</returns>
        /// <remarks>
        /// **測るためだけに在る口**である（**`IsLockedDownTestEndpoints` で閉じる**）。
        /// **`logout_token` をそのまま返す** — **E2E が中身を確かめる**ため。
        ///
        /// **本番で開いていれば、他人のログアウトの通知を読まれる。**
        /// **閉じる判定を外さないこと**（`ProductionCheck` が
        /// `IsLockedDownTestEndpoints` の警告を出すのは、この種の口が在るためである）。
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult BackChannelLogoutBox(bool clear = false)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return this.NotFound();
            }

            List<string> tokens = Sts.TestLogoutTokenBox.GetAll();

            if (clear)
            {
                // **測る前に空にする**ために在る（前のケースの通知が混ざらないように）。
                Sts.TestLogoutTokenBox.Clear();
            }

            return this.Json(new { logout_tokens = tokens });
        }

        #endregion
    }
}
