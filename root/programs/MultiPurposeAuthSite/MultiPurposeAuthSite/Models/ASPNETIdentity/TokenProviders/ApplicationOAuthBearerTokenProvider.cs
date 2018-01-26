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

using MultiPurposeAuthSite.Models.Log;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using System;
using System.Web;
using System.Threading.Tasks;
using System.Security.Claims;

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
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
            // context.Validatedに事前登録したRedirectエンドポイントを指定して呼び出し、contextを検証完了に設定する。
            // ・ 検証完了にしなければ要求はそれ以上先には進まない。
            // ・ RFC上の記載で、RedirectEndpointのURIは、AbsoluteUriである必要があるとの記載あり。
            //    ASP.NET IdentityのチェックでAbsoluteUriである必要があるとの記載あり形式でないと弾かれる。

            #region response_type

            string response_type = context.Request.Query.Get("response_type");

            // OIDC Implicit, Hybridの場合、書き換え
            if (ASPNETIdentityConfig.EnableOpenIDConnect)
            {
                if (response_type.ToLower() == ASPNETIdentityConst.OidcImplicit1_ResponseType
                    || response_type.ToLower() == ASPNETIdentityConst.OidcImplicit2_ResponseType
                    || response_type.ToLower() == ASPNETIdentityConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == ASPNETIdentityConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == ASPNETIdentityConst.OidcHybrid3_ResponseType)
                {
                    // OIDC Implicit, Hybridの場合、書き換え
                    // Authorization Code Flowの場合は、codeなので書き換え不要。
                    // ※ この変数は、使用するredirect_uriを決定するだめダケに利用される。
                    response_type = ASPNETIdentityConst.ImplicitResponseType;

                    // OIDC Implicit Flow、Hybrid Flowのパラメタチェック

                    // nonceパラメタ 必須
                    string nonce = context.Request.Query.Get("nonce");
                    if (string.IsNullOrEmpty(nonce))
                    {
                        //throw new NotSupportedException("there was no nonce in query.");
                        context.SetError(
                            "server_error",
                            "there was no nonce in query.");
                        return Task.FromResult(0);
                    }

                    // scopeパラメタ 必須
                    string scope = context.Request.Query.Get("scope");
                    if (scope.IndexOf("openid") == -1)
                    {
                        //throw new NotSupportedException("there was no openid in scope of query.");
                        context.SetError(
                            "server_error",
                            "there was no openid in scope of query.");
                        return Task.FromResult(0);
                    }
                }
            }

            if (!string.IsNullOrEmpty(response_type))
            {
                if (response_type.ToLower() == ASPNETIdentityConst.AuthorizationCodeResponseType)
                {
                    if (!ASPNETIdentityConfig.EnableAuthorizationCodeGrantType)
                    {
                        //throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType);
                        context.SetError(
                            "server_error",
                            Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType);
                        return Task.FromResult(0);
                    }
                }
                else if (response_type.ToLower() == ASPNETIdentityConst.ImplicitResponseType)
                {
                    if (!ASPNETIdentityConfig.EnableImplicitGrantType)
                    {
                        //throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType);
                        context.SetError(
                            "server_error",
                            Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType);
                        return Task.FromResult(0);
                    }
                }
            }

            #endregion

            #region redirect_uri

            string redirect_uri = context.RedirectUri;

            // redirect_uriのチェック
            if (string.IsNullOrEmpty(redirect_uri))
            {
                // redirect_uriの指定が無い。

                // クライアント識別子に対応する事前登録したredirect_uriを取得する。
                redirect_uri = OAuth2Helper.GetInstance().GetClientsRedirectUri(context.ClientId, response_type);

                if (!string.IsNullOrEmpty(redirect_uri))
                {
                    // 事前登録されている。
                    if (redirect_uri.ToLower() == "test_self_code")
                    {
                        // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                        context.Validated(
                            ASPNETIdentityConfig.OAuthClientEndpointsRootURI
                            + ASPNETIdentityConfig.OAuthAuthorizationCodeGrantClient_Account);
                    }
                    else if (redirect_uri.ToLower() == "test_self_token")
                    {
                        // Implicitグラント種別のテスト用のセルフRedirectエンドポイント
                        context.Validated(
                            ASPNETIdentityConfig.OAuthClientEndpointsRootURI
                            + ASPNETIdentityConfig.OAuthImplicitGrantClient_Account);
                    }
                    else if (redirect_uri.ToLower() == "id_federation_code")
                    {
                        // ID連携時のエンドポイント
                        context.Validated(ASPNETIdentityConfig.IdFederationRedirectEndPoint);
                    }
                    else
                    {
                        // 事前登録した、redirect_uriをそのまま使用する。
                        context.Validated(redirect_uri);
                    }
                }
                else
                {
                    // 事前登録されていない。
                }
            }
            else
            {
                // redirect_uriの指定が有る。

                // 指定されたredirect_uriを使用する場合は、チェックが必要になる。
                if (
                    // self_code : Authorization Codeグラント種別
                    redirect_uri == (ASPNETIdentityConfig.OAuthClientEndpointsRootURI + ASPNETIdentityConfig.OAuthAuthorizationCodeGrantClient_Manage)
                )
                {
                    // 不特定多数のクライアント識別子に許可されたredirect_uri
                    context.Validated(redirect_uri);
                }
                else
                {
                    // クライアント識別子に対応する事前登録したredirect_uriに
                    string preRegisteredUri = OAuth2Helper.GetInstance().GetClientsRedirectUri(context.ClientId, response_type);

                    //if (redirect_uri.StartsWith(preRegisteredUri))
                    if (redirect_uri == preRegisteredUri)
                    {
                        // 完全一致する場合。
                        context.Validated(redirect_uri);
                    }
                    else
                    {
                        // 完全一致しない場合。
                        context.SetError(
                            "server_error",
                            Resources.ApplicationOAuthBearerTokenProvider.Invalid_redirect_uri);
                    }
                }
            }

            #endregion

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
            // クライアント識別子
            string clientId = "";
            string clientSecret = "";

            // ・context.Validated を呼び出し、contextを検証完了に設定する。
            // ・検証完了にしなければ要求はそれ以上先には進まない。
            //context.Validated(clientId);

            #region クライアント認証を行なう。

            if (string.IsNullOrEmpty(context.Parameters["grant_type"]))
            {
                // 指定なし。
                // 検証未完
            }
            else if (context.Parameters["grant_type"].ToLower() == ASPNETIdentityConst.AuthorizationCodeGrantType)
            {
                #region Authorization Codeグラント種別

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (context.TryGetBasicCredentials(out clientId, out clientSecret))
                {
                    if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(context.ClientId))
                        {
                            // 検証完了
                            context.Validated(clientId);
                        }
                    }
                }

                #endregion
            }
            else if (context.Parameters["grant_type"].ToLower() == ASPNETIdentityConst.ResourceOwnerPasswordCredentialsGrantType)
            {
                #region Resource Owner Password Credentialsグラント種別

                #region 参考
                // Simple OAuth Server: Implementing a Simple OAuth Server with Katana
                // OAuth Authorization Server Components (Part 1) - Tugberk Ugurlu's Blog
                // http://www.tugberkugurlu.com/archive/simple-oauth-server-implementing-a-simple-oauth-server-with-katana-oauth-authorization-server-components-part-1
                // ・・・ 基本認証を使用する既存のクライアントを認証してOAuthに移行する。
                #endregion

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (context.TryGetBasicCredentials(out clientId, out clientSecret))
                {
                    if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(context.ClientId))
                        {
                            // 検証完了
                            context.Validated(clientId);
                        }
                    }
                }

                #endregion
            }
            else if (context.Parameters["grant_type"].ToLower() == ASPNETIdentityConst.ClientCredentialsGrantType)
            {
                #region Client Credentialsグラント種別

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (context.TryGetBasicCredentials(out clientId, out clientSecret))
                {
                    if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(context.ClientId))
                        {
                            // 検証完了
                            context.Validated(clientId);
                        }
                    }
                }

                #endregion
            }
            else if (context.Parameters["grant_type"].ToLower() == ASPNETIdentityConst.RefreshTokenGrantType)
            {
                #region RefreshToken

                if (!ASPNETIdentityConfig.EnableRefreshToken)
                {
                    throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableRefreshToken);
                }

                // "client_id" および "client_secret"を基本認証の認証ヘッダから取得
                if (context.TryGetBasicCredentials(out clientId, out clientSecret))
                {
                    if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                    {
                        // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                        if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(context.ClientId))
                        {
                            // 検証完了
                            context.Validated(clientId);
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
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            if (!ASPNETIdentityConfig.EnableResourceOwnerCredentialsGrantType)
            {
                throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableResourceOwnerCredentialsGrantType);
            }

            // この実装は、ValidateClientAuthenticationの続きで、ClientのOAuth権限を確認する。
            // 権限がある場合、Resource Owner Password Credentialsグラント種別の処理フローを継続する。

            try
            {
                // ApplicationUser を取得する。
                ApplicationUserManager userManager
                    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

                // username=ユーザ名&password=パスワードとして送付されたクレデンシャルを検証する。
                ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

                if (user != null)
                {
                    // ユーザーが見つかった場合。

                    try
                    {
                        // ユーザーに対応するClaimsIdentityを生成する。
                        ClaimsIdentity identity = await userManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);

                        // ClaimsIdentityに、その他、所定のClaimを追加する。
                        OAuth2Helper.AddClaim(identity, context.ClientId, "", context.Scope, "");

                        // 検証完了
                        context.Validated(identity);

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) passed the 'resource owner password credentials flow' by {2}({3}).",
                            user.Id, user.UserName, context.ClientId, OAuth2Helper.GetInstance().GetClientName(context.ClientId)));
                    }
                    catch
                    {
                        // ClaimManagerIdentityは、UserManagerで作成できませんでした。
                        context.SetError(
                            "server_error",
                             Resources.ApplicationOAuthBearerTokenProvider.server_error2);

                        // 拒否
                        context.Rejected();
                    }
                }
                else
                {
                    // ユーザーが見つからなかった場合。

                    // Resources Ownerの資格情報が無効であるか、Resources Ownerが存在しません。
                    context.SetError(
                        "access_denied",
                        Resources.ApplicationOAuthBearerTokenProvider.access_denied);

                    // 拒否
                    context.Rejected();
                }
            }
            catch
            {
                // ユーザーを取得できませんでした。
                context.SetError(
                    "server_error",
                    Resources.ApplicationOAuthBearerTokenProvider.server_error1);

                // 拒否
                context.Rejected();
            }
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
        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            if (!ASPNETIdentityConfig.EnableClientCredentialsGrantType)
            {
                throw new NotSupportedException(Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
            }

            // ASP.Net MVC: Creating an OAuth client credentials grant type token endpoint
            // http://www.hackered.co.uk/articles/asp-net-mvc-creating-an-oauth-client-credentials-grant-type-token-endpoint
            // WEB API 2 OAuth Client Credentials Authentication, How to add additional parameters? - Stack Overflow
            // http://stackoverflow.com/questions/29132031/web-api-2-oauth-client-credentials-authentication-how-to-add-additional-paramet

            try
            {
                ApplicationUser user = null;
                ApplicationUserManager userManager
                    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

                // client_idに対応するApplicationUserを取得する。
                user = await userManager.FindByNameAsync(
                    OAuth2Helper.GetInstance().GetClientName(context.ClientId));

                // ClaimsIdentity
                ClaimsIdentity identity = null;
                if (user != null)
                {
                    // User Accountの場合、
                    
                    // ユーザーに対応するClaimsIdentityを生成する。
                    identity = await userManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity = OAuth2Helper.AddClaim(identity, context.ClientId, "", context.Scope, "");

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format("{0}({1}) passed the 'client credentials flow' by {2}({3}).",
                                user.Id, user.UserName, context.ClientId, OAuth2Helper.GetInstance().GetClientName(context.ClientId)));
                }
                else
                {
                    // Client Accountの場合、

                    // ClaimsIdentityを自前で生成する。
                    identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    // Name Claimを追加
                    identity.AddClaim(new Claim(ClaimTypes.Name, OAuth2Helper.GetInstance().GetClientName(context.ClientId)));
                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity = OAuth2Helper.AddClaim(identity, context.ClientId, "", context.Scope, "");
                    
                    // オペレーション・トレース・ログ出力
                    string clientName = OAuth2Helper.GetInstance().GetClientName(context.ClientId);
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) passed the 'client credentials flow' by {2}({3}).",
                        context.ClientId, clientName, context.ClientId, clientName));
                }

                // 検証完了
                context.Validated(identity);
            }
            catch
            {
                // ユーザーを取得できませんでした。
                context.SetError(
                    "server_error",
                    Resources.ApplicationOAuthBearerTokenProvider.server_error1);

                // 拒否
                context.Rejected();
            }
        }

        #endregion
    }
}