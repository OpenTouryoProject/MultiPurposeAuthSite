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

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Filter
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

            //context.LogRequest += new EventHandler(this.OnLogRequest);

            context.BeginRequest += new EventHandler(this.OnBeginRequest);
            context.AuthorizeRequest += new EventHandler(this.OnAuthorizeRequest);
            context.PreRequestHandlerExecute += new EventHandler(this.OnPreRequestHandlerExecute);
            context.EndRequest += new EventHandler(this.OnEndRequest);
            context.PreSendRequestHeaders += new EventHandler(this.OnPreSendRequestHeaders);
        }

        #endregion

        /// <summary>OnLogRequest</summary>
        /// <param name="source">object</param>
        /// <param name="e">EventArgs</param>
        private void OnLogRequest(object source, EventArgs e)
        {
            // LogRequestのロジックはここに挿入
        }

        // 恐らく、Global.asaxと同じ。
        // http:// support.microsoft.com/kb/312607/ja
        
        /// <summary>ResponseTypeの書き換え(id_token token)</summary>
        private bool RewritedResponseType_IdTokenToken = false;
        
        /// <summary>ResponseTypeの書き換え(id_token)</summary>
        private bool RewritedResponseType_IdToken = false;

        /// <summary>ResponseModeの書き換え(form_post)</summary>
        private bool RewritedResponseMode_FromPost = false;
        
        /// <summary>書き換え</summary>
        private string OriginalVirtualPath = "";

        /// <summary>OnBeginRequest</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnBeginRequest(object sender, EventArgs e)
        {
            // OnBeginRequestのロジックはここに挿入
            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            string path = context.Request.Url.AbsolutePath;

            if (path.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint) != -1)
            {
                // OpenID Connect : Authorization Code Flow, [response_type=code]に対応

                //レスポンス内容を参照して書き換え
                context.Response.Filter = new OpenIDConnectCodeFilter(context);
            }
        }

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

                if (path.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
                {
                    string pattern = "";

                    if (!string.IsNullOrEmpty(orgQuery))
                    {
                        // parameter書き換えでBad Requestを回避

                        #region response_type

                        // OpenID Connect : Implicit Flow,
                        //                  [response_type=id_token token] or [response_type=id_token]に対応

                        pattern = "response_type=";
                        string responseType = orgQuery.Substring(orgQuery.IndexOf(pattern) + pattern.Length);

                        if (!string.IsNullOrEmpty(responseType))
                        {
                            bool is_id_token_token = false;
                            bool is_id_token = false;

                            is_id_token_token = responseType.StartsWith("id_token%20token");

                            if (!is_id_token_token)
                            {
                                is_id_token = responseType.StartsWith("id_token");
                            }

                            if (is_id_token_token || is_id_token)
                            {
                                if (is_id_token_token)
                                {
                                    this.RewritedResponseType_IdTokenToken = true;
                                    reWritedQuery = reWritedQuery.Replace("response_type=id_token%20token", "response_type=token");
                                }
                                else if (is_id_token)
                                {
                                    this.RewritedResponseType_IdToken = true;
                                    reWritedQuery = reWritedQuery.Replace("response_type=id_token", "response_type=token");
                                }
                            }
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
                                this.RewritedResponseMode_FromPost = true;
                                reWritedQuery = reWritedQuery.Replace("response_mode=form_post","");
                            }
                        }

                        #endregion

                        if (this.RewritedResponseType_IdTokenToken
                            || this.RewritedResponseType_IdToken
                            || this.RewritedResponseMode_FromPost)
                        {
                            context.RewritePath(virtualPath + reWritedQuery, false);
                        }
                    }
                }
            }
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

        /// <summary>OnPreSendRequestHeaders</summary>
        /// <param name="sender">object</param>
        /// <param name="e">EventArgs</param>
        private void OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            // PreSendRequestHeadersのロジックはここに挿入

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;
            HttpResponse response = context.Response;

            if (context.Request.Url.AbsolutePath.IndexOf(
                ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
            {
                #region response_type

                if (this.RewritedResponseType_IdTokenToken || this.RewritedResponseType_IdToken)
                {
                    // OpenID Connect : [response_type=id_token token] or [response_type=id_token]に対応

                    //レスポンス内容を参照して書き換え
                    string location = response.Headers["Location"];

                    if (!string.IsNullOrEmpty(location)
                        && location.IndexOf("#access_token=") != -1)
                    {
                        // ・正規表現でaccess_tokenを抜き出す。
                        string pattern = "(\\#access_token=)(?<accessToken>.+?)(\\&)";
                        string access_token = Regex.Match(location, pattern).Groups["accessToken"].Value;
                        string id_token = OpenIDConnectModule.ChangeToIdTokenFromJwt(access_token);

                        if (!string.IsNullOrEmpty(id_token))
                        {
                            // responseにid_tokenとして、このJWTを追加する。
                            if (this.RewritedResponseType_IdTokenToken)
                            {
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                            else if (this.RewritedResponseType_IdToken)
                            {
                                location = location.Replace("access_token=" + access_token + "&", "");
                                location = location.Replace("token_type=beara" + access_token + "&", "");
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                        }
                    }
                }

                #endregion

                #region response_mode

                if (this.RewritedResponseMode_FromPost)
                {
                    // OAuth2.0, OpenID Connect : response_mode=form_postに対応

                    //レスポンス内容を参照して書き換え
                    if (response.StatusCode == 302)
                    {
                        string location = response.Headers["Location"];

                        string paramStrCode = "?code=";
                        string paramStrState = "&state=";
                        string paramStrRedirectUri = "&redirect_uri=";

                        if (location.IndexOf(paramStrCode) != -1
                            || location.IndexOf(paramStrState) != -1
                            || location.IndexOf(paramStrRedirectUri) != -1)
                        {
                            response.StatusCode = 200;
                            response.Headers.Remove("Location");

                            string body =
                                "<html>" +
                                "  <body onload=\"javascript: document.forms[0].submit()\">" +
                                "    <form method=\"post\" action =\"{0}\">" +
                                "      <input type=\"hidden\" name =\"code\" value =\"{1}\"/>" +
                                "      <input type=\"hidden\" name =\"state\"  value =\"{2}\"/>" +
                                "    </form>" +
                                "  </body>" +
                                "</html>";

                            int startIndexOfCode = location.IndexOf(paramStrCode);
                            int startIndexOfState = location.IndexOf(paramStrState);
                            int startIndexOfRedirectUri = location.IndexOf(paramStrRedirectUri);

                            string code = location.Substring(
                                    startIndexOfCode + paramStrCode.Length,
                                    startIndexOfState - (startIndexOfCode + paramStrCode.Length));

                            string state = location.Substring(
                                    startIndexOfState + paramStrState.Length,
                                    startIndexOfRedirectUri - (startIndexOfState + paramStrState.Length));

                            // 何故か混じる。
                            string redirectUrl = CustomEncode.UrlDecode(
                                location.Substring(startIndexOfRedirectUri + paramStrRedirectUri.Length));

                            body = string.Format(body, redirectUrl, code, state);

                            byte[] buffer = response.ContentEncoding.GetBytes(body);
                            response.OutputStream.Write(buffer, 0, buffer.Length);
                        }
                    }
                }

                #endregion

                if (this.RewritedResponseType_IdTokenToken
                    || this.RewritedResponseType_IdToken
                    || this.RewritedResponseMode_FromPost)
                {
                    context.RewritePath(this.OriginalVirtualPath);

                    // 忘れずに！！
                    this.OriginalVirtualPath = "";
                    this.RewritedResponseType_IdTokenToken = false;
                    this.RewritedResponseType_IdToken = false;
                    this.RewritedResponseMode_FromPost = false;
                }
            }
        }

        /// <summary>ChangeToIdTokenFromJwt</summary>
        /// <param name="access_token">Jwt (string)</param>
        /// <returns>IdToken (string)</returns>
        public static string ChangeToIdTokenFromJwt(string access_token)
        {
            if (access_token.Contains("."))
            {
                string[] temp = access_token.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                Dictionary<string, object> authTokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                // ・access_tokenがJWTで、payloadに"nonce" and "scope=openidクレームが存在する場合、
                if (authTokenClaimSet.ContainsKey("nonce")
                    && authTokenClaimSet.ContainsKey("scopes"))
                {
                    JArray scopes = (JArray)authTokenClaimSet["scopes"];

                    // ・OpenID Connect : response_type=codeに対応する。
                    if (scopes.Any(x => x.ToString() == ASPNETIdentityConst.Scope_Openid))
                    {
                        //・payloadからscopeを削除する。
                        authTokenClaimSet.Remove("scopes");
                        //・編集したpayloadを再度JWTとして署名する。
                        string newPayload = JsonConvert.SerializeObject(authTokenClaimSet);
                        JWT_RS256 jwtRS256 = null;

                        // 署名
                        jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_pfx, ASPNETIdentityConfig.OAuthJWTPassword,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

                        string id_token = jwtRS256.Create(newPayload);

                        // 検証
                        jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_cer, ASPNETIdentityConfig.OAuthJWTPassword,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

                        if (jwtRS256.Verify(id_token))
                        {
                            // 検証できた。
                            return id_token;
                        }
                        else
                        {
                            // 検証できなかった。
                        }
                    }
                    else
                    {
                        // OIDCでない。
                    }
                }
                else
                {
                    // OIDCでない。
                }
            }
            else
            {
                // JWTでない。
            }

            return "";
        }
    }
}
