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
//* クラス名        ：OAuth2EndpointController
//* クラス日本語名  ：OAuth2EndpointController の 失効と照会（/revoke・/introspect）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（失効と照会（/revoke・/introspect））</summary>
    public partial class OAuth2EndpointController
    {
        #region /revoke 

        /// <summary>
        /// AccessTokenとRefreshTokenの取り消し
        /// POST: /revoke
        /// </summary>
        /// <param name="formData">
        /// token
        /// token_type_hint
        /// </param>
        /// <returns>成功（無効なトークンを含む）は 200、エラーは 400 / 401（RFC 7009 2.2 / 2.2.1）（#196）</returns>
        [HttpPost]
        public IActionResult RevokeToken(IFormCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                // token は必須、token_type_hint は任意（RFC 7009 2.1 / RFC 7662 2.1）（#200）
                if (!string.IsNullOrEmpty(token))
                {
                    // クライアント証明書
                    // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                    // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                    // tls_client_authのクライアントも利用できるよう有効化（#194）。
                    X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!Token.CmnEndpoints.GetBasicCredentials(
                        MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                        out string client_id, out string client_secret))
                    {
                        // client_secret_post
                        client_id = formData[OAuth2AndOIDCConst.client_id];
                        client_secret = formData[OAuth2AndOIDCConst.client_secret];
                    }

                    // **client_secret / mTLS / private_key_jwt のどれでも受ける（#239）。**
                    //   RFC 7009 2.1 / RFC 7662 2.1 は「トークン エンドポイントと同じ
                    //   クライアント認証」を求めている。以前はアサーションを読んでいなかった。
                    string clientAssertion = OAuth2AndOIDCSpec.GetClientAssertion(
                        formData[OAuth2AndOIDCConst.client_assertion],
                        formData[OAuth2AndOIDCConst.client_assertion_type],
                        formData[OAuth2AndOIDCConst.assertion]);

                    if (Token.CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out Token.ClientModePolicy.Proof _))
                    {
                        // 失効（#200）
                        // ・token_type_hint は探す順番の手掛かりにすぎない（RFC 7009 2.1）
                        // ・無効なトークンはエラーにしない（RFC 7009 2.2）
                        // ・成功は空の JSON（HTTP 200）で返し、両アプリで揃える
                        err = Token.CmnEndpoints.RevokeToken(client_id, token, token_type_hint);

                        if (err.Count == 0)
                        {
                            return this.Ok(err); // 成功（RFC 7009 2.2 : 200）
                        }

                        // 他のクライアントのトークン（invalid_grant）は、下でエラーとして返す（#196）。
                    }
                    else
                    {
                        // クライアント認証エラー（Credential不正
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    }
                }
                else
                {
                    // token が無い
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token is null or empty.");
                }
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return this.OAuth2Error(err, Const.EndpointRevoke); // 失敗（RFC 7009 2.2.1 : RFC 6749 5.2 のとおり 400 / 401）（#196）
        }

        #endregion

        #region /introspect 

        /// <summary>
        /// AccessTokenとRefreshTokenのメタデータを返す。
        /// POST: /introspect
        /// </summary>
        /// <param name="formData">
        /// token
        /// token_type_hint
        /// </param>
        /// <returns>問い合わせへの答え（active=false を含む）は 200、エラーは 400 / 401（RFC 7662 2.2 / 2.3）（#196）</returns>
        [HttpPost]
        public IActionResult IntrospectToken(IFormCollection formData)
        {
            // **資格情報・属性を返すので、キャッシュに残さない**（#218）。
            //   RFC は MUST としていないが、困る性質は /token と同じ。
            this.SetNoStore();

            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                // token は必須、token_type_hint は任意（RFC 7009 2.1 / RFC 7662 2.1）（#200）
                if (!string.IsNullOrEmpty(token))
                {
                    // クライアント証明書
                    // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                    // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                    // tls_client_authのクライアントも利用できるよう有効化（#194）。
                    X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!Token.CmnEndpoints.GetBasicCredentials(
                        MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                        out string client_id, out string client_secret))
                    {
                        // client_secret_post
                        client_id = formData[OAuth2AndOIDCConst.client_id];
                        client_secret = formData[OAuth2AndOIDCConst.client_secret];
                    }

                    // **client_secret / mTLS / private_key_jwt のどれでも受ける（#239）。**
                    //   RFC 7009 2.1 / RFC 7662 2.1 は「トークン エンドポイントと同じ
                    //   クライアント認証」を求めている。以前はアサーションを読んでいなかった。
                    string clientAssertion = OAuth2AndOIDCSpec.GetClientAssertion(
                        formData[OAuth2AndOIDCConst.client_assertion],
                        formData[OAuth2AndOIDCConst.client_assertion_type],
                        formData[OAuth2AndOIDCConst.assertion]);

                    if (Token.CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out Token.ClientModePolicy.Proof _))
                    {
                        // 問い合わせ（#200）
                        // ・token_type_hint は探す順番の手掛かりにすぎない（RFC 7662 2.1）
                        // ・無効なトークン（存在しない・失効済み・期限切れ）は active=false で答える（RFC 7662 2.2）
                        // ・active=false もエラーではなく、問い合わせへの正常な答えなので 200（RFC 7662 2.2）（#196）
                        return this.Ok(Token.CmnEndpoints.IntrospectToken(client_id, token, token_type_hint));
                    }
                    else
                    {
                        // クライアント認証エラー（Credential不正
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    }
                }
                else
                {
                    // token が無い
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token is null or empty.");
                }
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return this.OAuth2Error(err, Const.EndpointIntrospect); // 失敗（RFC 7662 2.3 : RFC 6749 5.2 のとおり 400 / 401）（#196）
        }

        #endregion
    }
}