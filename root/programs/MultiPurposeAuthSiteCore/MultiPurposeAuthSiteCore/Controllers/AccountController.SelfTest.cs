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
//*  2026/10/28  玄人 幸道         自己テストの ACS（AssertionConsumerService）を Saml2.cs から移した（#294）
//*  2026/10/29  玄人 幸道         id_token の nonce の照合、Cookie を消す条件、JARM の検証の失敗を直した（#294）
//*  2026/10/29  玄人 幸道         自己テストを始めていない要求・壊れた JARM で、500 にしない（#294）
//**********************************************************************************

/*
自己テストの RP（Redirect エンドポイントでのトークンの取得・検証・更新・失効・照会、
SAML2 の ACS、Front-Channel / Back-Channel Logout の受け口）を担うAccountControllerの一部（本番の口ではない）
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.Test;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
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
        #region LoadTest*Parameters

        /// <summary>LoadTestOauth2OidcParameters</summary>
        /// <param name="clientId">out string</param>
        /// <param name="state">out string</param>
        /// <param name="redirect_uri">out string</param>
        /// <param name="nonce">out string</param>
        /// <param name="code_verifier">out string</param>
        private void LoadTestOauth2OidcParameters(
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
                if (!string.IsNullOrEmpty(state)) // #294 : 以前は、どの値でも clientId で判定していた
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
                if (!string.IsNullOrEmpty(redirect_uri)) // #294 : 以前は、どの値でも clientId で判定していた
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
                if (!string.IsNullOrEmpty(nonce)) // #294 : 以前は、どの値でも clientId で判定していた
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
                if (!string.IsNullOrEmpty(code_verifier)) // #294 : 以前は、どの値でも clientId で判定していた
                {
                    responseCookies.Set(Const.TestCodeVerifier, "", this._cookieOptions);
                }
            }
        }

        /// <summary>送った AuthnRequest の ID を取り出す（#276）</summary>
        /// <returns>ID（無ければ空）</returns>
        /// <remarks>
        /// **`LoadTestOauth2OidcParameters` と同じ流儀**（Session → Cookie、読んだら消す）。
        /// **あちらは 5 つの out を持っており、OAuth2 側からも呼ばれる**ので、
        /// **SAML 専用のこれを別に立てている**（引数を増やさないため）。
        /// </remarks>
        private string LoadTestSamlRequestId()
        {
            IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            string id = HttpContext.Session.GetString(Const.TestSamlRequestId);

            if (!string.IsNullOrEmpty(id))
            {
                HttpContext.Session.SetString(Const.TestSamlRequestId, "");
            }
            else
            {
                id = requestCookies.Get(Const.TestSamlRequestId);

                if (!string.IsNullOrEmpty(id))
                {
                    responseCookies.Set(Const.TestSamlRequestId, "", this._cookieOptions);
                }
            }

            return id ?? "";
        }

        #endregion

        #region JARM の検証

        /// <summary>自己テストが受け取った JARM（response）を検証する</summary>
        /// <param name="response">response（JWT）</param>
        /// <param name="clientId">その回の client_id（Session・Cookie から読んだもの）</param>
        /// <param name="responseObject">検証できたら、その中身</param>
        /// <returns>検証できたら true</returns>
        /// <remarks>
        /// **その回の client_id が無い（自己テストを始めていない）要求や、壊れた JWT は、検証できないとして扱う**（#294）。
        /// 以前は `ResponseObject.Verify` が例外（`aud` が null など）を投げ、HTTP 500 になっていた。
        /// </remarks>
        private static bool VerifyTestResponseObject(string response, string clientId, out JObject responseObject)
        {
            responseObject = null;

            if (string.IsNullOrEmpty(clientId))
            {
                return false;
            }

            try
            {
                return ResponseObject.Verify(response,
                    null, CmnServerParams.IssuerId, clientId,
                    out responseObject);
            }
            catch (Exception ex)
            {
                //  **原因は、記録に残す**（握りつぶさない）。
                Logging.MyDebugLogForEx(ex);

                responseObject = null;
                return false;
            }
        }

        #endregion

        #region OAuth2 / OIDC の Redirect Endpoint

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

                    // LoadTestOauth2OidcParameters
                    string clientId_InSessionOrCookie = "";
                    string state_InSessionOrCookie = "";
                    string redirect_uri_InSessionOrCookie = "";
                    string nonce_InSessionOrCookie = "";
                    string code_verifier_InSessionOrCookie = "";
                    this.LoadTestOauth2OidcParameters(
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
                        if (AccountController.VerifyTestResponseObject(
                            response, clientId_InSessionOrCookie, out JObject responseObject))
                        {
                            // OK
                            code = (string)responseObject[OAuth2AndOIDCConst.code];
                            state = (string)responseObject[OAuth2AndOIDCConst.state];
                        }
                        else
                        {
                            // NG（**検証できない応答の値は使わない**。#294。以前はそのまま先へ進んでいた）
                            return View("Error");
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

                            model.Response = await Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.SelfTestScopes));
                        }
                        else if (state.StartsWith(fapi2Prefix))
                        {
                            // FAPI2

                            // **private_key_jwt で交換する**（#246）。
                            //   FAPI 2.0 が認めるのは MTLS と private_key_jwt の 2 つ。
                            //   **自己テストのクライアントは、ClientCertPfxFilePath が設定されていなければ証明書を添えない**ので、
                            //   **証明書の配置を前提にすると、設定が無い配置では /token が 401（invalid_client）になる。**
                            //   **証明書の配置を前提にしない private_key_jwt に寄せる。**
                            //   mTLS の経路は E2E（FA-6）が測る。

                            // **アサーションの組み立ては SelfTestClient**（#246）。
                            model.AuthMethod = Resources.AccountController.AuthMethodFapi2;

                            model.Response = await Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.OidcScopes));
                        }
                        else
                        {
                            // OAuth2 / OIDC

                            //  client_Idから、client_secretを取得。
                            string client_id = clientId_InSessionOrCookie;
                            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                            if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
                            {
                                // 通常
                                //   **Open棟梁 のクライアントは、この経路を Basic で送る**
                                //   （既定が client_secret_basic。#246 の項目 3）。
                                model.AuthMethod = Resources.AccountController.AuthMethodClientSecretBasic;

                                model.Response = await Helper.GetInstance()
                                    .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                    client_id, client_secret, redirect_uri, code);
                            }
                            else
                            {
                                // PKCE
                                //   **PKCE の経路は既定が client_secret_post**（Basic ではない。#246 の項目 3）。
                                //   PKCE 自体はクライアント認証ではないので、code_verifier は別に送る。
                                model.AuthMethod = Resources.AccountController.AuthMethodClientSecretPostPkce;

                                model.Response = await Helper.GetInstance()
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
                                    || (!string.IsNullOrEmpty(nonce_InSessionOrCookie) && out_nonce != nonce_InSessionOrCookie)) // #294 : 以前は条件が逆（nonce の不一致を見逃した）
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
                        model.Response = await Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Refresh"]))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                        // Tokenエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().
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
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().RevokeTokenAsync(
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
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().IntrospectTokenAsync(
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
                        this.LoadTestOauth2OidcParameters(
                            out clientId_InSessionOrCookie,
                            out state_InSessionOrCookie,
                            out redirect_uri_InSessionOrCookie,
                            out nonce_InSessionOrCookie,
                            out code_verifier_InSessionOrCookie);

                        // responseObject検証
                        if (AccountController.VerifyTestResponseObject(
                            response, clientId_InSessionOrCookie, out JObject responseObject))
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
                            // NG（**検証できない応答の値は使わない**。#294。以前はそのまま先へ進んでいた）
                            return View("Error");
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

        #region SAML2 の AssertionConsumerService

        /// <summary>AssertionConsumerService</summary>
        /// <param name="samlResponse">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult（Saml2Response 画面）</returns>
        /// <remarks>
        /// **検証の本体は Open棟梁 の `SAML2Client.VerifyResponseWithReason`**
        /// （鍵と期待 Issuer は引数で渡す。#246 / #286 / #294）。
        ///
        /// **アサーションを画面に出す**（#246 の項目 3）。
        /// **どこで落ちたのか、読み取った属性と XML を、画面で確かめられる。**
        /// </remarks>
        [AllowAnonymous]
        public ActionResult AssertionConsumerService(string samlResponse, string relayState, string sigAlg)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                // テスト用のエンドポイントを閉じている。
                return View("Error");
            }

            bool isGet = (Request.Method.ToLower() == "get");
            string queryString = "";

            if (isGet)
            {
                // **Redirect Binding は、クエリ文字列そのものが署名の対象**である。
                //   **受け取ったままの値で読む**（#294。組み直した URL では符号化が変わり得る）。
                queryString = (Request.QueryString.Value ?? "").TrimStart('?');
            }

            // LoadTestOauth2OidcParameters（state と RelayState を照合するため）
            string clientId_InSessionOrCookie = "";
            string state_InSessionOrCookie = "";
            string redirect_uri_InSessionOrCookie = "";
            string nonce_InSessionOrCookie = "";
            string code_verifier_InSessionOrCookie = "";
            this.LoadTestOauth2OidcParameters(
                out clientId_InSessionOrCookie,
                out state_InSessionOrCookie,
                out redirect_uri_InSessionOrCookie,
                out nonce_InSessionOrCookie,
                out code_verifier_InSessionOrCookie);

            // **自分の ACS URL**（#276。Audience / Recipient と照合する）。
            //   **IdP は登録値「test_self_saml」をこの形に展開して入れる**
            //   （`SamlProviders/CmnEndpoints`）。
            string acsUrl = Config.OAuth2ClientEndpointsRootURI + Config.Saml2ResponseEndpoint;

            string requestId = this.LoadTestSamlRequestId();

            SAML2VerifyResult result = SelfTestClient.VerifySaml2Response(
                samlResponse, queryString, relayState,
                state_InSessionOrCookie, isGet, acsUrl, requestId);

            ViewBag.Verdict = SamlProviders.CmnSaml2Response.VerdictOf(result);
            ViewBag.Reason = SamlProviders.CmnSaml2Response.ReasonOf(result, CmnServerParams.IssuerId, acsUrl, requestId);
            ViewBag.Binding = SamlProviders.CmnSaml2Response.BindingOf(result);
            ViewBag.SigAlg = result.SigAlg;
            ViewBag.RelayState = result.RelayState;
            ViewBag.RelayStateMatched = result.RelayStateMatched;
            ViewBag.AudienceMatched = result.AudienceMatched;
            ViewBag.RecipientMatched = result.RecipientMatched;
            ViewBag.InResponseToMatched = result.InResponseToMatched;
            ViewBag.NotExpired = result.NotExpired;
            ViewBag.SignatureVerified = result.SignatureVerified;
            ViewBag.IssuerMatched = result.IssuerMatched;
            ViewBag.NameId = result.NameId;
            ViewBag.Issuer = result.Issuer;
            ViewBag.Audience = result.Audience;
            ViewBag.InResponseTo = result.InResponseTo;
            ViewBag.Recipient = result.Recipient;
            ViewBag.NotOnOrAfter = SamlProviders.CmnSaml2Response.NotOnOrAfterOf(result);
            ViewBag.StatusCode = result.StatusCode?.ToString() ?? "";
            ViewBag.NameIdFormat = result.NameIdFormat?.ToString() ?? "";
            ViewBag.AuthnContextClassRef = result.AuthnContextClassRef?.ToString() ?? "";
            ViewBag.ResponseXml = SamlProviders.CmnSaml2Response.FormatXml(result.Response);

            //  **アサーションの属性**（#286）。**目視のため**（判定には使わない）。
            ViewBag.Attributes = result.Attributes;
            ViewBag.AttrEmail = SAML2Attributes.GetEmail(result.Attributes);
            ViewBag.AttrUserName = SAML2Attributes.GetUserName(result.Attributes);
            ViewBag.AttrEmailVerified = SAML2Attributes.GetEmailVerified(result.Attributes);

            return View("Saml2Response");
        }

        #endregion

        #region Front-Channel Logout の受け口

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

            TestFrontChannelLogoutBox.Add(iss, sid);

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

            List<string> hits = TestFrontChannelLogoutBox.GetAll();

            if (clear)
            {
                // **測る前に空にする**ために在る。
                TestFrontChannelLogoutBox.Clear();
            }

            return this.Json(new { frontchannel_hits = hits });
        }

        #endregion

        #region Back-Channel Logout の受け口

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

            TestLogoutTokenBox.Add(logoutToken);

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

            List<string> tokens = TestLogoutTokenBox.GetAll();

            if (clear)
            {
                // **測る前に空にする**ために在る（前のケースの通知が混ざらないように）。
                TestLogoutTokenBox.Clear();
            }

            return this.Json(new { logout_tokens = tokens });
        }

        #endregion
    }
}
