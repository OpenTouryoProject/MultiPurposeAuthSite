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
//* クラス名        ：AuthorizationCodeProvider
//* クラス日本語名  ：AuthorizationCodeProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using ExtOAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;
using MultiPurposeAuthSite.Extensions.OIDC.HttpMod;

using System;
using System.IO;
using System.Data;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;

using System.Web;

using Microsoft.Owin.Security.Infrastructure;

using Dapper;
using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// AuthorizationCodeのProvider
    /// TokenにSerializeTicket一時保存する。
    /// （Cluster対応する場合、ストアを用意する必要がある）
    /// </summary>
    /// <see cref="https://msdn.microsoft.com/ja-jp/library/microsoft.owin.security.infrastructure.authenticationtokenprovider.aspx"/>
    /// <seealso cref="https://msdn.microsoft.com/ja-jp/library/dn385573.aspx"/>
    public class AuthorizationCodeProvider : IAuthenticationTokenProvider
    {
        /// <summary>シングルトン</summary>
        private static AuthorizationCodeProvider _AuthorizationCodeProvider = new AuthorizationCodeProvider();
        
        /// <summary>GetInstance</summary>
        /// <returns>AuthorizationCodeProvider</returns>
        public static AuthorizationCodeProvider GetInstance()
        {
            return AuthorizationCodeProvider._AuthorizationCodeProvider;
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        public void Create(AuthenticationTokenCreateContext context)
        {
            this.CreateAuthenticationCode(context);
        }

        /// <summary>CreateAsync</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        /// <returns>Task</returns>
        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() => this.CreateAuthenticationCode(context));
        }

        /// <summary>CreateAuthenticationCode</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            string tokenId = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");

            Dictionary<string, string> temp = new Dictionary<string, string>();
            NameValueCollection queryString = HttpUtility.ParseQueryString(context.Request.QueryString.Value);

            // 標準（標準方式は、今のところ、残しておく）
            temp.Add("ticket", context.SerializeTicket());

            // 有効期限が無効なtokenのペイロードだけ作成
            string access_token_payload = OidcTokenEditor.CreateAccessTokenPayloadFromAuthenticationTicket(context.Ticket);
            temp.Add("access_token_payload", access_token_payload);

            // OAuth PKCE 対応
            temp.Add(OAuth2AndOIDCConst.code_challenge, queryString[OAuth2AndOIDCConst.code_challenge]);
            temp.Add(OAuth2AndOIDCConst.code_challenge_method, queryString[OAuth2AndOIDCConst.code_challenge_method]);

            // Hybrid Flow対応
            //   OAuthAuthorizationServerHandler経由での呼び出しができず、
            //   AuthenticationTokenXXXXContextを取得できないため、抜け道。
            // サイズ大き過ぎるので根本の方式を修正。
            //temp.Add("claims",  CustomEncode.ToBase64String(BinarySerialize.ObjectToBytes(context.Ticket.Identity)));
            //temp.Add("properties", CustomEncode.ToBase64String(BinarySerialize.ObjectToBytes(context.Ticket.Properties.Dictionary)));

            // 新しいCodeのticketをストアに保存
            string jsonString = JsonConvert.SerializeObject(temp);
            ExtOAuth2.AuthorizationCodeProvider.CreateAuthenticationCode(tokenId, jsonString);

            context.SetToken(tokenId);
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            this.ReceiveAuthenticationCode(context);
        }

        /// <summary>ReceiveAsync</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        /// <returns>Task</returns>
        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return Task.Factory.StartNew(() => this.ReceiveAuthenticationCode(context));
        }

        /// <summary>ReceiveAuthenticationCode</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            context.Request.Body.Position = 0;

            string code_verifier = null;
            string body = new StreamReader(context.Request.Body).ReadToEnd();

            if (body.IndexOf("code_verifier=") != -1)
            {
                string[] forms = body.Split('&');
                foreach (string form in forms)
                {
                    if (form.StartsWith("code_verifier="))
                    {
                        code_verifier = form.Split('=')[1];
                    }
                }
            }

            // CodeのTicketを受け取り、ストアから削除する。
            context.DeserializeTicket(ExtOAuth2.AuthorizationCodeProvider.
                ReceiveAuthenticationCode(context.Token, code_verifier));
        }

        /// <summary>VerifyCodeVerifier</summary>
        /// <param name="value">string</param>
        /// <param name="code_verifier">string</param>
        /// <returns>ticket</returns>
        private string VerifyCodeVerifier(string value, string code_verifier)
        {
            // null チェック
            if (string.IsNullOrEmpty(value)) { return ""; }

            Dictionary<string, string> temp = 
                JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            bool isPKCE = (code_verifier != null);
            
            if (!isPKCE)
            {
                // 通常のアクセストークン・リクエスト
                if (string.IsNullOrEmpty(temp[OAuth2AndOIDCConst.code_challenge]))
                {
                    // Authorization Codeのcode
                    return temp["ticket"];
                }
                else
                {
                    // OAuth PKCEのcode（要 code_verifier）
                    return "";
                }
            }
            else
            {
                // OAuth PKCEのアクセストークン・リクエスト
                if (!string.IsNullOrEmpty(temp[OAuth2AndOIDCConst.code_challenge]) && !string.IsNullOrEmpty(code_verifier))
                {
                    if (temp[OAuth2AndOIDCConst.code_challenge_method].ToLower() == OAuth2AndOIDCConst.PKCE_plain)
                    {
                        // plain
                        if (temp[OAuth2AndOIDCConst.code_challenge] == code_verifier)
                        {
                            // 検証成功
                            return temp["ticket"];
                        }
                        else
                        {
                            // 検証失敗
                        }
                    }
                    else if (temp[OAuth2AndOIDCConst.code_challenge_method].ToUpper() == OAuth2AndOIDCConst.PKCE_S256)
                    {
                        // S256
                        if (temp[OAuth2AndOIDCConst.code_challenge] == OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(code_verifier))
                        {
                            // 検証成功
                            return temp["ticket"];
                        }
                        else
                        {
                            // 検証失敗
                        }
                    }
                    else
                    {
                        // パラメタ不正
                    }
                }
                else
                {
                    // パラメタ不正
                }

                return null;
            }
        }

        #endregion
    }
}