//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：OpenIDConnectModule
//* クラス日本語名  ：OpenIDConnectModule（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/07/14  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;

using System;
using System.Text.RegularExpressions;

using System.Web;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.OIDCFilter
{
    /// <summary>
    /// OpenIDConnect対応用のHttpModule
    /// </summary>
    public class OpenIDConnectModule : IHttpModule
    {
        #region IHttpModule Members

        /// <summary>Constructor</summary>
        public OpenIDConnectModule() { }

        /// <summary>Dispose</summary>
        public void Dispose()
        {
            //後処理用コードはここに追加します。
        }

        /// <summary>Init</summary>
        /// <param name="context">HttpApplication</param>
        public void Init(HttpApplication context)
        {
            // HttpApplication（Global.asax）、HttpModule、HttpHandler - マイクロソフト系技術情報 Wiki
            // https://techinfoofmicrosofttech.osscons.jp/index.php?HttpApplication%EF%BC%88Global.asax%EF%BC%89%E3%80%81HttpModule%E3%80%81HttpHandler

            if (ASPNETIdentityConfig.EnableOpenIDConnect)
            {
                //context.LogRequest += new EventHandler(this.OnLogRequest);

                // Response.Filterの適用判断
                context.BeginRequest += new EventHandler(this.OnBeginRequest);

                // Request時のparameter書き換え
                context.AuthorizeRequest += new EventHandler(this.OnAuthorizeRequest);

                //context.PreRequestHandlerExecute += new EventHandler(this.OnPreRequestHandlerExecute);
                //context.EndRequest += new EventHandler(this.OnEndRequest);

                // Response時のheader、body書き換え
                context.PreSendRequestHeaders += new EventHandler(this.OnPreSendRequestHeaders);
            }
        }

        #endregion

        #region Http Event

        #region 不使用

        /// <summary>OnLogRequest</summary>
        /// <param name="source">object</param>
        /// <param name="e">EventArgs</param>
        private void OnLogRequest(object source, EventArgs e)
        {
            // LogRequestのロジックはここに挿入
        }

        /// <summary>OnPreRequestHandlerExecute</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnPreRequestHandlerExecute(object sender, EventArgs e)
        {
            // OnPreRequestHandlerExecuteのロジックはここに挿入
        }

        /// <summary>OnEndRequest</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnEndRequest(object sender, EventArgs e)
        {
            // OnEndRequestのロジックはここに挿入
        }

        #endregion

        #region 書き換え

        #region 書換用変数

        /// <summary>VirtualPathの書き換え</summary>
        private string OriginalVirtualPath = "";

        #region ResponseType

        /// <summary>id_token</summary>
        private bool RewritedResponseTypeFrom_IdToken = false;

        /// <summary>id_token token</summary>
        private bool RewritedResponseTypeFrom_IdTokenToken = false;

        /// <summary>code id_token</summary>
        private bool RewritedResponseTypeFrom_CodeIdToken = false;

        /// <summary>code token</summary>
        private bool RewritedResponseTypeFrom_CodeToken = false;

        /// <summary>code id_token token</summary>
        private bool RewritedResponseTypeFrom_CodeIdTokenToken = false;

        #endregion

        #region response_mode

        /// <summary>response_mode=form_post</summary>
        private bool RewritedResponseModeFrom_FromPost = false;

        #endregion

        #endregion
        
        #region TokenEndpoint

        /// <summary>OnBeginRequest</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnBeginRequest(object sender, EventArgs e)
        {
            // OnBeginRequestのロジックはここに挿入
            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            string path = context.Request.Url.AbsolutePath;

            if (path.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint2) == -1
                && path.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint) != -1)
            {
                if (context.Request.Form["grant_type"] == OAuth2AndOIDCConst.RefreshTokenGrantType)
                {
                    // なにもしない
                }
                else if (context.Request.Form["grant_type"] == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
                {
                    // なにもしない
                }
                else if (context.Request.Form["grant_type"] == OAuth2AndOIDCConst.ClientCredentialsGrantType)
                {
                    // Refresh Tokenの削除
                    context.Response.Filter = new ClientCredentialsFilter(context);
                }
                else if (context.Request.Form["grant_type"] == OAuth2AndOIDCConst.ImplicitGrantType)
                {
                    // ↓OnPreSendRequestHeadersで処理
                }
                else if (context.Request.Form["grant_type"] == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
                {
                    // OpenID Connect の "response_type=code"に対応したレスポンスに書き換え
                    context.Response.Filter = new OpenIDConnectCodeFilter(context);
                }
            }
        }

        #endregion

        #region AuthorizeEndpoint

        #region Request

        /// <summary>OnAuthorizeRequest</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnAuthorizeRequest(object sender, EventArgs e)
        {
            // OnBeginRequestのロジックはここに挿入
            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            if (context.Request.IsAuthenticated)
            {
                string path = context.Request.Url.AbsolutePath;
                string orgQuery = context.Request.Url.Query;
                string reWritedQuery = orgQuery;

                string virtualPath = path.Substring(path.IndexOf(context.Request.ApplicationPath));
                this.OriginalVirtualPath = virtualPath + orgQuery;

                if (path.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint2) == -1
                    && path.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
                {
                    string pattern = "";

                    if (!string.IsNullOrEmpty(orgQuery))
                    {
                        // parameter書き換えでBad Requestを回避

                        #region response_type

                        // OpenID Connect : Implicit Flow
                        //                  - [response_type=id_token]
                        //                  - or [response_type=id_token token]
                        //                : Hybrid Flow
                        //                  - [response_type=code id_token]
                        //                  - or [response_type=code token]
                        //                  - or [response_type=code id_token token]

                        pattern = "response_type=";
                        string responseType = orgQuery.Substring(orgQuery.IndexOf(pattern) + pattern.Length);

                        if (!string.IsNullOrEmpty(responseType))
                        {
                            #region フラグ初期化

                            // OIDC Implicit
                            bool is_id_token = false;
                            bool is_id_token_token = false;

                            // [response_type=id_token token]
                            is_id_token_token = responseType.StartsWith(
                                CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcImplicit2_ResponseType));
                            if (!is_id_token_token)
                            {
                                // [response_type=token]
                                is_id_token = responseType.StartsWith(OAuth2AndOIDCConst.OidcImplicit1_ResponseType);
                            }

                            // OIDC Hybrid
                            bool is_code_id_token = false;
                            bool is_code_token = false;
                            bool is_code_id_token_token = false;

                            // [response_type=code id_token token]
                            is_code_id_token_token = responseType.StartsWith(
                                CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid3_ResponseType));

                            if (!is_code_id_token_token)
                            {
                                // [response_type=code id_token]
                                is_code_id_token = responseType.StartsWith(
                                    CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType));
                                // [response_type=code token]
                                is_code_token = responseType.StartsWith(
                                    CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType));
                            }

                            #endregion

                            #region パラメタ書き換え（補助輪回避）
                            // [response_type=id_token] or [response_type=id_token token]
                            if (is_id_token || is_id_token_token)
                            {
                                // OIDC Implicit
                                if (is_id_token)
                                {
                                    this.RewritedResponseTypeFrom_IdToken = true;
                                    reWritedQuery = reWritedQuery.Replace(
                                        "response_type=" + OAuth2AndOIDCConst.OidcImplicit1_ResponseType,
                                        "response_type=" + OAuth2AndOIDCConst.ImplicitResponseType);
                                }
                                else if (is_id_token_token)
                                {
                                    this.RewritedResponseTypeFrom_IdTokenToken = true;
                                    reWritedQuery = reWritedQuery.Replace(
                                        "response_type=" + CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcImplicit2_ResponseType),
                                        "response_type=" + OAuth2AndOIDCConst.ImplicitResponseType);
                                }
                            }
                            else if (is_code_id_token || is_code_token || is_code_id_token_token)
                            {
                                // OIDC Hybrid
                                if (is_code_id_token)
                                {
                                    this.RewritedResponseTypeFrom_CodeIdToken = true;
                                    reWritedQuery = reWritedQuery.Replace(
                                        "response_type=" + CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType),
                                        "response_type=" + OAuth2AndOIDCConst.AuthorizationCodeResponseType);
                                }
                                else if (is_code_token)
                                {
                                    this.RewritedResponseTypeFrom_CodeToken = true;
                                    reWritedQuery = reWritedQuery.Replace(
                                        "response_type=" + CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType),
                                        "response_type=" + OAuth2AndOIDCConst.AuthorizationCodeResponseType);
                                }
                                else if (is_code_id_token_token)
                                {
                                    this.RewritedResponseTypeFrom_CodeIdTokenToken = true;
                                    reWritedQuery = reWritedQuery.Replace(
                                        "response_type=" + CustomEncode.UrlEncode(OAuth2AndOIDCConst.OidcHybrid3_ResponseType),
                                        "response_type=" + OAuth2AndOIDCConst.AuthorizationCodeResponseType);
                                }
                            }
                            else
                            {
                                // サポートなし
                            }

                            #endregion
                        }

                        #endregion

                        #region response_mode

                        // OAuth2.0, OpenID Connect : response_mode=form_postに対応

                        pattern = "response_mode=";
                        string responseMode = orgQuery.Substring(orgQuery.IndexOf(pattern) + pattern.Length);

                        if (!string.IsNullOrEmpty(responseMode))
                        {
                            //bool is_query = false;
                            //bool is_fragment = false;
                            bool is_form_post = false;

                            //is_query = responseMode.StartsWith("query");
                            //is_fragment = responseMode.StartsWith("fragment");
                            is_form_post = responseMode.StartsWith("form_post");

                            if (is_form_post)
                            {
                                this.RewritedResponseModeFrom_FromPost = true;
                                //reWritedQuery = reWritedQuery.Replace("response_mode=form_post","");
                            }
                        }

                        #endregion

                        if (this.RewritedResponseTypeFrom_IdToken
                            || this.RewritedResponseTypeFrom_IdTokenToken
                            || this.RewritedResponseTypeFrom_CodeIdToken
                            || this.RewritedResponseTypeFrom_CodeToken
                            || this.RewritedResponseTypeFrom_CodeIdTokenToken)
                        //|| this.RewritedResponseModeFrom_FromPost)
                        {
                            context.RewritePath(virtualPath + reWritedQuery, false);
                        }
                    }
                }
            }
        }

        #endregion

        #region Response
         
        /// <summary>OnPreSendRequestHeaders</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            // PreSendRequestHeadersのロジックはここに挿入

            #region 変数

            #region Context
            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;
            HttpResponse response = context.Response;
            #endregion

            #region ワーク

            // code
            string code = "";
            // state
            string state = "";
            // expires_in
            ulong expires_in = 0;
            // redirect_uri
            string redirect_url = "";
            // access_token
            string access_token = "";
            // id_token
            string id_token = "";

            #endregion
            
            #endregion

            if (context.Request.Url.AbsolutePath.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint2) == -1
                && context.Request.Url.AbsolutePath.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
            {
                #region response_type

                if (this.RewritedResponseTypeFrom_IdToken
                    || this.RewritedResponseTypeFrom_IdTokenToken)
                {
                    // OpenID Connect : Implicit Flowに対応
                    //                  - [response_type=id_token]
                    //                  - or [response_type=id_token token]

                    // レスポンス内容を参照して書き換え（fragmentにid_tokenを追加）
                    string location = response.Headers["Location"];

                    if (!string.IsNullOrEmpty(location)
                        && location.IndexOf("#access_token=") != -1)
                    {
                        // ・正規表現でaccess_tokenを抜き出す。
                        string pattern = "(\\#access_token=)(?<accessToken>.+?)(\\&)";
                        access_token = Regex.Match(location, pattern).Groups["accessToken"].Value;

                        // at_hashを付与
                        id_token = OidcTokenEditor.ChangeToIdTokenFromAccessToken(access_token, "", HashClaimType.AtHash);

                        if (!string.IsNullOrEmpty(id_token))
                        {
                            // responseにid_tokenとして、このJWTを追加する。
                            if (this.RewritedResponseTypeFrom_IdTokenToken)
                            {
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                            else if (this.RewritedResponseTypeFrom_IdToken)
                            {
                                // ココは未サポート状態なので、テストできていない。
                                location = location.Replace("access_token=" + access_token + "&", "");
                                location = location.Replace("&token_type=beara", "");
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                        }
                    }
                }
                else if (this.RewritedResponseTypeFrom_CodeIdToken
                    || this.RewritedResponseTypeFrom_CodeToken
                    || this.RewritedResponseTypeFrom_CodeIdTokenToken)
                {
                    // OpenID Connect : Hybrid Flowに対応
                    //                  - [response_type=code id_token]
                    //                  - or [response_type=code token]
                    //                  - or [response_type=code id_token token]

                    //レスポンス内容を参照して書き換え（RedirectをFragmentに変更）
                    if (response.StatusCode == 302) // 302 Found
                    {
                        // ・Rewriteした為か、
                        //   何故か、以下が、
                        //     "?code=code値&state=state値&redirect_uri=Urlエンコードされたredirect_uri値"
                        //   となっている。
                        //   ※ redirect_uriがlocationのQueryStringに混じる。
                        //
                        // ・本来は、
                        //     "http(s)://redirect_uri値?code=code値&state=state値"
                        //   を期待していた。
                        string location = response.Headers["Location"];

                        string paramStrCode = "?code=";
                        string paramStrState = "&state=";
                        string paramStrRedirectUri = "&redirect_uri=";

                        if (location.IndexOf(paramStrCode) != -1
                            || location.IndexOf(paramStrState) != -1
                            || location.IndexOf(paramStrRedirectUri) != -1)
                        {
                            response.Headers.Remove("Location");

                            // 以下は、"?code=XXX&state=YYY&" という並びが前提。
                            MatchCollection matches = StringChecker.Matches(
                                location,
                                "\\?code=(?<code>.+)&state=(?<state>.+)");

                            foreach (Match match in matches)
                            {
                                GroupCollection groups = match.Groups;
                                code = groups["code"].Value;
                                state = groups["state"].Value;
                            }

                            redirect_url = location.Substring(0, location.IndexOf('?'));

                            // ★ Hybrid Flow対応なので、expを短縮してもイイ。
                            expires_in = ulong.Parse(ASPNETIdentityConfig.OAuthAccessTokenExpireTimeSpanFromMinutes.TotalSeconds.ToString());

                            // Fragmentに組み込む
                            string fragment = "";

                            if (this.RewritedResponseTypeFrom_CodeIdToken)
                            {
                                // id_tokenを取得
                                string access_token_payload = AuthorizationCodeProvider.GetInstance().GetAccessTokenPayload(code);

                                // c_hashを付与
                                id_token = OidcTokenEditor.ChangeToIdTokenFromAccessToken(
                                    OidcTokenEditor.ProtectFromPayload(access_token_payload, expires_in), code, HashClaimType.CHash);

                                fragment = "#id_token={0}&token_type=Bearer&code={1}&expires_in={2}&state={3}";
                                fragment = string.Format(fragment, new object[] { id_token, code, expires_in, state });
                            }
                            else if (this.RewritedResponseTypeFrom_CodeToken)
                            {
                                // access_tokenを取得
                                string access_token_payload = AuthorizationCodeProvider.GetInstance().GetAccessTokenPayload(code);
                                access_token = OidcTokenEditor.ProtectFromPayload(access_token_payload, expires_in);

                                fragment = "#access_token={0}&token_type=Bearer&code={1}&expires_in={2}&state={3}";
                                fragment = string.Format(fragment, new object[] { access_token, code, expires_in, state });
                            }
                            else if (this.RewritedResponseTypeFrom_CodeIdTokenToken)
                            {
                                // id_token, access_tokenを取得
                                string access_token_payload = AuthorizationCodeProvider.GetInstance().GetAccessTokenPayload(code);
                                access_token = OidcTokenEditor.ProtectFromPayload(access_token_payload, expires_in);

                                // at_hash, c_hashの両方を付与
                                id_token = OidcTokenEditor.ChangeToIdTokenFromAccessToken(access_token, code, HashClaimType.Both);

                                fragment = "#access_token={0}&id_token={1}&token_type=Bearer&code={2}&expires_in={3}&state={4}";
                                fragment = string.Format(fragment, new object[] { access_token, id_token, code, expires_in, state });
                            }

                            // Locationを追加（redirect_url + fragment）。
                            response.Headers.Add("Location", redirect_url + fragment);
                        }
                    }
                }

                #endregion

                #region response_mode

                if (this.RewritedResponseModeFrom_FromPost)
                {
                    // OAuth2.0, OpenID Connect : response_mode=form_postに対応

                    //レスポンス内容を参照して書き換え
                    //（Redirect（get）をAuto-Submit Form（post）に変更）
                    if (response.StatusCode == 302) // 302 Found
                    {
                        // ・Rewriteした為か、
                        //   何故か、以下が、
                        //     "?code=code値&state=state値&redirect_uri=Urlエンコードされたredirect_uri値"
                        //   となっている。
                        //   ※ redirect_uriがlocationのQueryStringに混じる。
                        //
                        // ・本来は、
                        //     "http(s)://redirect_uri値?code=code値&state=state値"
                        //   を期待していた。
                        string location = response.Headers["Location"];

                        string paramStrCode = "?code=";
                        string paramStrState = "&state=";
                        string paramStrRedirectUri = "&redirect_uri=";

                        if (location.IndexOf(paramStrCode) != -1
                            || location.IndexOf(paramStrState) != -1
                            || location.IndexOf(paramStrRedirectUri) != -1)
                        {
                            // 302 Found ---> 200 OK
                            response.StatusCode = 200;
                            response.Headers.Remove("Location");

                            // 以下は、"?code=XXX&state=YYY&redirect_uri=ZZZ" という並びが前提。
                            MatchCollection matches = StringChecker.Matches(
                                location,
                                "\\?code=(?<code>.+)&state=(?<state>.+)&redirect_uri=(?<redirect_uri>.+)");

                            foreach (Match match in matches)
                            {
                                GroupCollection groups = match.Groups;
                                code = groups["code"].Value;
                                state = groups["state"].Value;
                                redirect_url = CustomEncode.UrlDecode(groups["redirect_uri"].Value);
                            }

                            // form_postに必要な、HTTP response message body
                            string body =
                                "<html>" +
                                "  <body onload=\"javascript: document.forms[0].submit()\">" +
                                "    <form method=\"post\" action =\"{0}\">" +
                                "      <input type=\"hidden\" name =\"code\" value =\"{1}\"/>" +
                                "      <input type=\"hidden\" name =\"state\"  value =\"{2}\"/>" +
                                "    </form>" +
                                "  </body>" +
                                "</html>";

                            // bodyに組み込んで
                            body = string.Format(body, redirect_url, code, state);

                            // HTTP Responseに書き出し
                            byte[] buffer = response.ContentEncoding.GetBytes(body);
                            response.OutputStream.Write(buffer, 0, buffer.Length);
                        }
                    }
                }

                #endregion

                if (this.RewritedResponseTypeFrom_IdToken
                    || this.RewritedResponseTypeFrom_IdTokenToken
                    || this.RewritedResponseTypeFrom_CodeIdToken
                    || this.RewritedResponseTypeFrom_CodeToken
                    || this.RewritedResponseTypeFrom_CodeIdTokenToken)
                    //|| this.RewritedResponseModeFrom_FromPost)
                {
                    context.RewritePath(this.OriginalVirtualPath);
                }

                #region 再利用されるinstance memberの初期化を忘れずに！！
                //      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                this.OriginalVirtualPath = "";

                this.RewritedResponseTypeFrom_IdTokenToken = false;
                this.RewritedResponseTypeFrom_IdToken = false;

                this.RewritedResponseTypeFrom_CodeIdToken = false;
                this.RewritedResponseTypeFrom_CodeToken = false;
                this.RewritedResponseTypeFrom_CodeIdTokenToken = false;

                this.RewritedResponseModeFrom_FromPost = false;

                #endregion
            }
        }

        #endregion

        #endregion

        #endregion

        #endregion
    }
}
