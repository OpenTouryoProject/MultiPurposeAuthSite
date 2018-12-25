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
//* クラス名        ：ApplicationOAuthBearerTokenProvider
//* クラス日本語名  ：ApplicationOAuthBearerTokenProvider（ライブラリ）
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
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;
using System.Net.Http;

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// OAuthAuthorizationServerProviderの派生クラス。
    /// 以下の４つのメソッドをオーバーライドする。
    /// ・OnValidateClientRedirectUriプロパティ設定 or ValidateClientRedirectUriのオーバーライド
    /// ・OnValidateClientAuthenticationプロパティ設定 or ValidateClientAuthenticationのオーバーライド
    /// ・OnGrantResourceOwnerCredentialsプロパティ設定 or GrantResourceOwnerCredentialsのオーバーライド
    /// ・OnGrantClientCredentialsプロパティ設定 or GrantClientCredentialsのオーバーライド
    ///</summary>
    ///<see cref="https://msdn.microsoft.com/ja-jp/library/microsoft.owin.security.oauth.oauthauthorizationserverprovider.aspx"/>
    public class ApplicationOAuthBearerTokenProvider : OAuthAuthorizationServerProvider
    {
        #region  constructor

        /// <summary>constructor</summary>
        public ApplicationOAuthBearerTokenProvider() { }

        #endregion

        #region エラー処理

        /// <summary>SetError</summary>
        /// <param name="context">BaseValidatingClientContext</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        private void SetError(BaseValidatingClientContext context, string err, string errDescription)
        {
            context.SetError(err, errDescription);
        }

        /// <summary>SetError</summary>
        /// <param name="context">BaseValidatingTicketContext(OAuthAuthorizationServerOptions)</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        private void SetError(BaseValidatingTicketContext<OAuthAuthorizationServerOptions> context, string err, string errDescription)
        {
            context.SetError(err, errDescription);
        }

        #endregion

        #region (1) ValidateClientRedirectUriのオーバーライド

        /// <summary>
        /// Authorization Code、Implicitグラント種別において、
        /// AuthorizeEndpointPathを処理する場合に発生する。
        /// 以下の両方の要素を検証する処理を実装するためのメソッド。
        /// ・context.ClientId が、登録された "client_id" であること。
        /// ・context.RedirectUri が、そのクライアント用に登録された "redirect_uri" であること。
        /// </summary>
        /// <param name="context">OAuthValidateClientRedirectUriContext</param>
        /// <returns>Task</returns>
        /// <see cref="https://msdn.microsoft.com/ja-jp/library/dn385496.aspx"/>
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            string client_id = context.ClientId;
            string redirect_uri = context.RedirectUri;
            string response_type = context.Request.Query.Get(OAuth2AndOIDCConst.response_type); // OIDC拡張
            string scope = context.Request.Query.Get(OAuth2AndOIDCConst.scope); // OIDC拡張
            string nonce = context.Request.Query.Get(OAuth2AndOIDCConst.nonce); // OIDC拡張

            string valid = "";
            string err = "";
            string errDescription = "";

            if (CmnEndpoints.ValidateClientRedirectUri(
                client_id, redirect_uri, response_type, scope, nonce,
                out valid, out err, out errDescription))
            {
                context.Validated(valid);
            }
            else
            {
                this.SetError(context, err, errDescription);
            }

            // 結果を返す。
            return Task.FromResult(0);
        }

        #endregion

        #region (2) ValidateClientAuthenticationのオーバーライド

        /// <summary>
        /// Authorization Code、Resource Owner Password Credentialsl、Client Credentialsグラント種別において、
        /// OAuthBearerTokenEndpointPathを処理する場合に発生する、" クライアント認証 " を行なうメソッド。
        /// " クライアント認証 "では、以下の両方の要素を検証する。
        /// ・context.ClientId が、登録された "client_id" であること。
        /// ・その他、資格情報が要求に存在していることを検証する。
        /// </summary>
        /// <param name="context">OAuthValidateClientAuthenticationContext</param>
        /// <returns>Task</returns>
        /// <see cref="https://msdn.microsoft.com/ja-jp/library/dn385497.aspx"/>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string grant_type = context.Parameters[OAuth2AndOIDCConst.grant_type];
            string assertion = context.Parameters[OAuth2AndOIDCConst.assertion];
            string client_id = "";
            string client_secret = "";

            string valid = "";
            string err = "";
            string errDescription = "";

            bool ret = context.TryGetBasicCredentials(out client_id, out client_secret);

            if (CmnEndpoints.ValidateClientAuthentication(
                grant_type, assertion, client_id, client_secret,
                out valid, out err, out errDescription))
            {
                context.Validated(valid);
            }
            else
            {
                this.SetError(context, err, errDescription);
            }


            // 結果を返す。
            return Task.FromResult(0);
        }

        #endregion

        #region (3) GrantResourceOwnerCredentialsのオーバーライド

        /// <summary>
        /// Resource Owner Password Credentials Grantのカスタム認証ロジック
        /// TokenEndpointPathへの grant_type = password アクセスは、こちらに到達する。
        /// ・context.Username および context.Password を検証する。
        /// ・クライアントは"access_token" および "refresh_token" を取得する。
        /// </summary>
        /// <param name="context">OAuthGrantResourceOwnerCredentialsContext</param>
        /// <returns>Task</returns>
        /// <see cref="https://msdn.microsoft.com/ja-jp/library/dn343587.aspx"/>
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            string userName = context.UserName;
            string password = context.Password;
            string client_id = context.ClientId;
            IList<string> scope = context.Scope;

            string err = "";
            string errDescription = "";

            // ClaimsIdentityを自前で生成する。
            ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);

            if (CmnEndpoints.GrantResourceOwnerCredentials(
                userName, password, client_id, scope, identity, out err, out errDescription))
            {   
                context.Validated(identity);
            }
            else
            {
                this.SetError(context, err, errDescription);
            }

            // 結果を返す。
            return Task.FromResult(0);
        }

        #endregion

        #region (4) GrantClientCredentialsのオーバーライド

        /// <summary>
        /// Client Credentialsグラント種別のカスタム認証ロジック
        /// TokenEndpointPathへの grant_type=client_credentials アクセスは、こちらに到達する。
        /// ・client_id, client_secret の検証は、(2) ValidateClientAuthenticationで済。
        /// ・クライアントは"access_token"を取得する。
        /// </summary>
        /// <param name="context">OAuthGrantClientCredentialsContext</param>
        /// <returns>Task</returns>
        /// <see cref="https://msdn.microsoft.com/ja-jp/library/dn343586.aspx"/>
        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            string client_id = context.ClientId;
            IList<string> scope = context.Scope;

            string err = "";
            string errDescription = "";

            // ClaimsIdentityを自前で生成する。
            ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);

            if (CmnEndpoints.GrantClientCredentials(
                client_id, scope, identity, out err, out errDescription))
            {
                context.Validated(identity);
            }
            else
            {
                this.SetError(context, err, errDescription);
            }

            // 結果を返す。
            return Task.FromResult(0);
        }

        #endregion
    }
}