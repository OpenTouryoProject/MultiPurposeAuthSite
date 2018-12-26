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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）
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
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Collections.Generic;
using System.Security.Claims;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>ApplicationOAuthBearerTokenProviderからの切り出し</summary>
    public class CmnEndpoints
    {
        #region (1) ValidateClientRedirectUriのオーバーライド

        /// <summary>ApplicationOAuthBearerTokenProvider.ValidateClientRedirectUri</summary>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="response_type">string</param>
        /// <param name="scope">string</param>
        /// <param name="nonce">string</param>
        /// <param name="Validated">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static bool ValidateClientRedirectUri(
            string client_id, string redirect_uri, string response_type, string scope, string nonce,
            out string valid, out string err, out string errDescription)
        {
            valid = "";
            err = "";
            errDescription = "";

            #region response_type

            // OIDC Implicit, Hybridの場合、書き換え
            if (Config.EnableOpenIDConnect)
            {
                if (response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    // OIDC Implicit, Hybridの場合、書き換え
                    // Authorization Code Flowの場合は、codeなので書き換え不要。
                    // ※ この変数は、使用するredirect_uriを決定するだめダケに利用される。
                    response_type = OAuth2AndOIDCConst.ImplicitResponseType;

                    // OIDC Implicit Flow、Hybrid Flowのパラメタチェック

                    // nonceパラメタ 必須
                    if (string.IsNullOrEmpty(nonce))
                    {
                        err = "server_error";
                        errDescription = "there was no nonce in query.";
                        return false;
                    }

                    // scopeパラメタ 必須
                    if (scope.IndexOf(OAuth2AndOIDCConst.Scope_Openid) == -1)
                    {   
                        err = "server_error";
                        errDescription = "there was no openid in scope of query.";
                        return false;
                    }
                }
            }

            if (!string.IsNullOrEmpty(response_type))
            {
                if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    if (!Config.EnableAuthorizationCodeGrantType)
                    {
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType;
                        return false;
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType)
                {
                    if (!Config.EnableImplicitGrantType)
                    {
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType;
                        return false;
                    }
                }
            }
        
            #endregion

            #region redirect_uri

            // redirect_uriのチェック
            if (string.IsNullOrEmpty(redirect_uri))
            {
                // redirect_uriの指定が無い。

                // クライアント識別子に対応する事前登録したredirect_uriを取得する。
                redirect_uri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);

                if (!string.IsNullOrEmpty(redirect_uri))
                {
                    // 事前登録されている。
                    if (redirect_uri.ToLower() == "test_self_code")
                    {
                        // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                        valid = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2AuthorizationCodeGrantClient_Account;
                    }
                    else if (redirect_uri.ToLower() == "test_self_token")
                    {
                        // Implicitグラント種別のテスト用のセルフRedirectエンドポイント
                        valid = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2ImplicitGrantClient_Account;
                    }
                    else if (redirect_uri.ToLower() == "id_federation_code")
                    {
                        // ID連携時のエンドポイント
                        valid = Config.IdFederationRedirectEndPoint;
                    }
                    else
                    {
                        // 事前登録した、redirect_uriをそのまま使用する。
                        valid = redirect_uri;
                    }

                    err = "";
                    errDescription = "";
                    return true;
                }
            }
            else
            {
                // redirect_uriの指定が有る。

                // 指定されたredirect_uriを使用する場合は、チェックが必要になる。
                if (
                    // self_code : Authorization Codeグラント種別
                    redirect_uri == (Config.OAuth2ClientEndpointsRootURI + Config.OAuth2AuthorizationCodeGrantClient_Manage))
                {
                    // 不特定多数のクライアント識別子に許可されたredirect_uri
                    valid = redirect_uri;
                    return true;
                }
                else
                {
                    // クライアント識別子に対応する事前登録したredirect_uriに
                    string preRegisteredUri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);

                    //if (redirect_uri.StartsWith(preRegisteredUri))
                    if (redirect_uri == preRegisteredUri)
                    {
                        // 完全一致する場合。
                        valid = redirect_uri;
                        return true;
                    }
                    else
                    {
                        // 完全一致しない場合。
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_redirect_uri;                        
                        return false;
                    }
                }
            }

            #endregion

            // 結果を返す。
            return false;
        }

        #endregion

        #region (2) ValidateClientAuthenticationのオーバーライド

        /// <summary>ApplicationOAuthBearerTokenProvider.ValidateClientAuthentication</summary>
        /// <param name="grant_type">string</param>
        /// <param name="assertion">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="valid">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static  bool ValidateClientAuthentication(
            string grant_type, string assertion,  string client_id, string client_secret,
            out string valid, out string err, out string errDescription)
        {
            valid = "";
            err = "";
            errDescription = "";

            #region クライアント認証を行なう。

            if (string.IsNullOrEmpty(grant_type))
            {
                // 指定なし。
                // 検証未完
            }
            else if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
            {
                #region Authorization Codeグラント種別

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (!string.IsNullOrEmpty(client_secret))
                {
                    // 通常のクライアント認証
                    if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                        {
                            // 検証完了
                            valid = client_id;
                            return true;
                        }
                    }
                }
                else
                {
                    // その他のクライアント認証の可能性
                    if (!string.IsNullOrEmpty(assertion))
                    {
                        // JWT client assertion
                        Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                assertion.Split('.')[1]), CustomEncode.us_ascii));

                        string pubKey = Helper.GetInstance().GetJwtAssertionPublickey(dic[OAuth2AndOIDCConst.iss]);
                        pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                        if (!string.IsNullOrEmpty(pubKey))
                        {
                            string iss = "";
                            string aud = "";
                            string scopes = "";
                            JObject jobj = null;

                            if (JwtAssertion.VerifyJwtBearerTokenFlowAssertionJWK(
                                assertion, out iss, out aud, out scopes, out jobj, pubKey))
                            {
                                // aud 検証
                                if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI
                                    + Config.OAuth2BearerTokenEndpoint)
                                {
                                    // 検証完了
                                    valid = iss;
                                    return true;
                                }
                            }
                        }
                    }
                    else
                    {
                        // クライアント認証なしエラー
                    }
                }

                #endregion
            }
            else if (grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
            {
                #region Resource Owner Password Credentialsグラント種別

                #region 参考
                // Simple OAuth Server: Implementing a Simple OAuth Server with Katana
                // OAuth Authorization Server Components (Part 1) - Tugberk Ugurlu's Blog
                // http://www.tugberkugurlu.com/archive/simple-oauth-server-implementing-a-simple-oauth-server-with-katana-oauth-authorization-server-components-part-1
                // ・・・ 基本認証を使用する既存のクライアントを認証してOAuthに移行する。
                #endregion

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (!string.IsNullOrEmpty(client_secret))
                {
                    if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                        {
                            // 検証完了
                            valid = client_id;
                            return true;
                        }
                    }
                }

                #endregion
            }
            else if (grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType)
            {
                #region Client Credentialsグラント種別

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (!string.IsNullOrEmpty(client_secret))
                {
                    if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                        {
                            // 検証完了
                            valid = client_id;
                            return true;
                        }
                    }
                }

                #endregion
            }
            else if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
            {
                #region RefreshToken

                if (!Config.EnableRefreshToken)
                {
                    throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableRefreshToken);
                }

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (!string.IsNullOrEmpty(client_secret))
                {
                    if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                        {
                            // 検証完了
                            valid = client_id;
                            return true;
                        }
                    }
                }

                #endregion
            }
            else
            {
                // 不明な値
                // 検証未完
            }

            #endregion

            // 結果を返す。
            return false;
        }

        #endregion

        #region (3) GrantResourceOwnerCredentialsのオーバーライド

        /// <summary>ApplicationOAuthBearerTokenProvider.GrantResourceOwnerCredentials</summary>
        /// <param name="userName">string</param>
        /// <param name="password">string</param>
        /// <param name="client_id">string</param>
        /// <param name="scope">IList(string)</param>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static bool GrantResourceOwnerCredentials(
            string userName, string password, string client_id, IList<string> scope,
            ClaimsIdentity identity, out string err, out string errDescription)
        {
            err = "";
            errDescription = "";

            if (!Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableResourceOwnerCredentialsGrantType);
            }

            // username=ユーザ名&password=パスワードとして送付されたクレデンシャルを検証する。
            ApplicationUser user = CmnUserStore.FindByName(userName);

            if (user != null)
            {
                // ユーザーが見つかった場合。
#if NETFX
                string passwordHash = (new CustomPasswordHasher()).HashPassword(password);
#else
                    string passwordHash = (new CustomPasswordHasher<ApplicationUser>()).HashPassword(user, password);
#endif
                if (user.PasswordHash == passwordHash)
                {
                    // Name Claimを追加
                    identity.AddClaim(new Claim(ClaimTypes.Name, Helper.GetInstance().GetClientName(client_id)));

                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity = Helper.AddClaim(identity, client_id, "", scope, "");

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format("{0}({1}) passed the 'resource owner password credentials flow' by {2}({3}).",
                        user.Id, user.UserName, user.ClientID, Helper.GetInstance().GetClientName(user.ClientID)));

                    return true;
                }
            }

            // ユーザーが見つからないか、パスワードが一致しない場合。
            // Resources Ownerの資格情報が無効であるか、Resources Ownerが存在しません。
            err = "access_denied";
            errDescription = Resources.ApplicationOAuthBearerTokenProvider.access_denied;

            return false;
        }

        #endregion

        #region (4) GrantClientCredentialsのオーバーライド

        /// <summary>ApplicationOAuthBearerTokenProvider.GrantClientCredentials</summary>
        /// <param name="client_id">string</param>
        /// <param name="scope">IList(string)</param>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static bool GrantClientCredentials(string client_id, IList<string> scope,
            ClaimsIdentity identity, out string err, out string errDescription)
        {
            err = "";
            errDescription = "";

            if (!Config.EnableClientCredentialsGrantType)
            {
                throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
            }

            // client_idに対応するApplicationUserを取得する。
            bool isResourceOwner = false;
            string sub = Helper.GetInstance().GetClientName(client_id, out isResourceOwner);

            if (isResourceOwner)
            {
                // User Accountの場合、
                ApplicationUser user = CmnUserStore.FindByName(sub);

                // Name Claimを追加
                identity.AddClaim(new Claim(ClaimTypes.Name, Helper.GetInstance().GetClientName(client_id)));

                // ClaimsIdentityに、その他、所定のClaimを追加する。
                identity = Helper.AddClaim(identity, client_id, "", scope, "");

                // オペレーション・トレース・ログ出力
                Logging.MyOperationTrace(
                    string.Format("{0}({1}) passed the 'client credentials flow' by {2}({3}).",
                    user.Id, user.UserName, client_id, Helper.GetInstance().GetClientName(client_id)));

                // 検証完了
                return true;
            }
            else
            {
                // Client Accountの場合、
                if (string.IsNullOrEmpty(sub))
                {
                    // 検証失敗
                    err = "server_error";
                    errDescription = "";

                    return false;
                }
                else
                {
                    // Name Claimを追加（空文字列とする）
                    identity.AddClaim(new Claim(ClaimTypes.Name, ""));

                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity = Helper.AddClaim(identity, client_id, "", scope, "");

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format(
                        "Passed the 'client credentials flow' by {0}({1}).", client_id, sub));

                    // 検証完了
                    return true;
                }
            }
        }

        #endregion
    }
}