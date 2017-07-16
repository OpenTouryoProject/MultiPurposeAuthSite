//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
using System.Text.RegularExpressions;

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
            // ASP.NET MVC の イベント 発生順序 - galife
            // https://garafu.blogspot.jp/2014/01/aspnet-mvc.html

            //context.LogRequest += new EventHandler(OnLogRequest);

            //　OpneID ConnectのAuthorization Code Flow対応
            context.BeginRequest += new EventHandler(OnBeginRequest);

            //context.EndRequest += new EventHandler(OnEndRequest);

            // OpneID ConnectのImplicit Flow対応（試行）
            //context.PreSendRequestHeaders += new EventHandler(OnPreSendRequestHeaders);
        }

        #endregion

        /// <summary>OnLogRequest</summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        private void OnLogRequest(Object source, EventArgs e)
        {
            // LogRequestのロジックはここに挿入
        }

        /// <summary>OnBeginRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnBeginRequest(Object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            if (context.Request.Url.AbsolutePath.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint) != -1)
            {
                // OpenIDConnectCodeFilter
                // OpenID Connect : response_type=codeに対応

                //レスポンス内容を参照して書き換え
                HttpResponse response = context.Response;
                response.Filter = new OpenIDConnectCodeFilter(context);
            }
        }

        /// <summary>OnEndRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnEndRequest(object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入
        }

        /// <summary>OnPreSendRequestHeaders</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            // PreSendRequestHeadersのロジックはここに挿入

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;

            if (string.IsNullOrEmpty(context.Request.QueryString["response_type"]))
            {
                // response_typeが無い。
            }
            else
            {
                // response_typeが有る。
                if ((context.Request.QueryString["response_type"].ToLower() == "id_token"
                    || context.Request.QueryString["response_type"].ToLower() == "id_token token"))
                {

                }

                if (context.Request.Url.AbsolutePath.IndexOf(ASPNETIdentityConfig.OAuthAuthorizeEndpoint) != -1
                && context.Request.QueryString["response_type"].ToLower() == "token")
                {
                    // OpenIDConnectTokenFilter
                    // OpenID Connect : response_type=tokenに対応

                    //レスポンス内容を参照して書き換え
                    HttpResponse response = context.Response;
                    string location = response.Headers["Location"];

                    if (location.IndexOf("#access_token=") != -1)
                    {
                        // ・正規表現でaccess_tokenを抜き出す。
                        string pattern = "(\\#access_token=)(?<accessToken>.+?)(\\&)";
                        string accessToken = Regex.Match(location, pattern).Groups["accessToken"].Value;

                        // ・access_tokenがJWTで、payloadに"nonce" and "scope=openidクレームが存在する場合、
                        // ・OpenID Connect : response_type=codeに対応する。
                        //   ・payloadからscopeを削除する。
                        //   ・編集したpayloadを再度JWTとして署名する。
                        //   ・responseにid_tokenとして、このJWTを追加する。
                    }
                }
            }
        }
    }
}
