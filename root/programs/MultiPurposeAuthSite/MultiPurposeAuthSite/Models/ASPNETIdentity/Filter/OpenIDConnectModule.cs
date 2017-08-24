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
using System.Web;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util.JWT;

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
            // - Visual C# .NET を使用して ASP.NET HTTP モジュールを作成する方法
            //   https://support.microsoft.com/ja-jp/help/307996/how-to-create-an-asp-net-http-module-using-visual-c--net
            // - URL書き換え(Rewriting)を行う - Netplanetes
            //   http://www.pine4.net/Memo/Article/Archives/11
            // - ブログ表示（３） -クラスライブラリ | ++C++; // 未確認飛行 C
            //   http://ufcpp.net/study/dotnet/aspx/blog3/
            // - HttpRequestのパラメータに小細工をしたい時にどうするか(・ω・)？ -うさ☆うさ日記
            //   http://d.hatena.ne.jp/machi_pon/20091203/1259842545

            // - IIS7 の機能を拡張してみる-レスポンスヘッダー内のサーバー名の改ざん – monoe's blog
            //   https://blogs.msdn.microsoft.com/osamum/2010/04/05/iis7-2/
            // - IIS 7/7.5 で不要なHTTPレスポンスヘッダーを削除 « Fukui Labs
            //   http://blog.progfast.jp/labs/index.php/arts/iis-7-httpresponseheader/

            //context.LogRequest += new EventHandler(OnLogRequest);

            //　OpneID ConnectのAuthorization Code Flow対応
            //  OpneID ConnectのImplicit Flow対応（試行）
            context.BeginRequest += new EventHandler(OnBeginRequest);
            //context.EndRequest += new EventHandler(OnEndRequest);

            // OpneID ConnectのImplicit Flow対応（試行）
            context.PreRequestHandlerExecute += new EventHandler(OnPreRequestHandlerExecute);
            context.PreSendRequestHeaders += new EventHandler(OnPreSendRequestHeaders);
        }

        #endregion

        /// <summary>OnLogRequest</summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        private void OnLogRequest(Object source, EventArgs e)
        {
            // LogRequestのロジックはここに挿入
        }

        /// <summary>書き換え</summary>
        private bool Rewrited = false;
        /// <summary>書き換え</summary>
        private string OriginalVirtualPath = "";
         
        /// <summary>OnBeginRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnBeginRequest(Object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入

            //HttpApplication app = sender as HttpApplication;
            //if (app != null)
            //{
            //    app.Context.RewritePath(app.Context.Request.ApplicationPath + "?hoge=aaa");
            //}

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            string path = context.Request.Url.AbsolutePath;
            string query = context.Request.Url.Query;

            // response_type
            // - Authorization Code Flow : response_type=code
            // - Implicit Flow           : response_type=id_token token or response_type=id_token
            if (path.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint) != -1)
            {
                // OpenID Connect :
                // - Authorization Code Flow
                // - response_type =codeに対応

                // OpenIDConnectCodeFilter

                //レスポンス内容を参照して書き換え
                HttpResponse response = context.Response;
                response.Filter = new OpenIDConnectCodeFilter(context);
            }
            else if (path.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
            {
                // OpenID Connect :
                // - Implicit Flow
                // - [response_type=id_token token] or [response_type=id_token]に対応

                string pattern = "response_type=";
                string cookie = context.Request.Headers.Get("Cookie");
                
                if (!string.IsNullOrEmpty(query))
                {
                    string responseType = query.Substring(query.IndexOf(pattern) + pattern.Length);

                    // a = [response_type=id_token token]に対応
                    // b = [response_type=id_token]に対応
                    bool a = false;
                    bool b = false;

                    a = responseType.StartsWith("id_token%20token");

                    if (!a)
                    {
                        b = responseType.StartsWith("id_token");
                    }
                    
                    if (a || b)
                    {
                        this.Rewrited = true;
                        string temp = path.Substring(path.IndexOf(context.Request.ApplicationPath));

                        string rewritedVirtualPath = "";
                        this.OriginalVirtualPath = temp + query;

                        if (a)
                        {
                            rewritedVirtualPath = temp + query.Replace("response_type=id_token%20token", "response_type=token");

                        }
                        else if (b)
                        {
                            rewritedVirtualPath = temp + query.Replace("response_type=id_token", "response_type=token");
                        }
                       
                        context.RewritePath(rewritedVirtualPath, false);
                        //context.RewritePath(context.Request.ApplicationPath + "?hoge=aaa");

                        //context.Request.ContentEncoding = new OpenIDConnectEncoding(Encoding.GetEncoding("Shift_JIS"));
                    }
                }
            }
        }

        /// <summary>OnEndRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnEndRequest(object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入
        }

        private void OnPreRequestHandlerExecute(object sender, EventArgs e)
        {
            // OnPreRequestHandlerExecuteのロジックはここに挿入

            if (this.Rewrited)
            {
                HttpApplication application = (HttpApplication)sender;
                HttpContext context = application.Context;
                context.RewritePath(this.OriginalVirtualPath);
            }
        }

        /// <summary>OnPreSendRequestHeaders</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            // PreSendRequestHeadersのロジックはここに挿入

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            if (context.Request.Url.AbsolutePath.IndexOf(
                ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1)
            {
                bool a = (context.Request.QueryString["response_type"].ToLower() == "id_token token");
                bool b = (context.Request.QueryString["response_type"].ToLower() == "id_token");

                if (a || b)
                {
                    // OpenID Connect : [response_type=id_token token] or [response_type=id_token]に対応

                    //レスポンス内容を参照して書き換え
                    HttpResponse response = context.Response;
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
                            if (a)
                            {
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                            else if (b)
                            {
                                location = location.Replace("access_token=" + access_token + "&", "");
                                location = location.Replace("token_type=beara" + access_token + "&", "");
                                response.Headers["Location"] = location + "&id_token=" + id_token;
                            }
                        }
                    }
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
