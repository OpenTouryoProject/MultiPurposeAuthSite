//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：StartupAuth
//* クラス日本語名  ：認証の構成（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Twitter;

using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.Infrastructure;

using Owin;

using MultiPurposeAuthSite.Models.Util;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity
{
    /// <summary>
    /// StartupAuth.Configure
    /// </summary>
    /// <remarks>
    /// 認証に関するOWINミドルウェアの設定を行う。
    /// </remarks>
    public class StartupAuth
    {
        #region member variable
        
        /// <summary>OAuthAuthorizationServerOptions</summary>
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        #endregion

        /// <summary>
        /// 認証設定の詳細については、http://go.microsoft.com/fwlink/?LinkId=301864 を参照してください
        /// 
        /// Code! MVC 5 App with Facebook, Twitter, LinkedIn
        /// and Google OAuth2 Sign-on (C#) | The ASP.NET Site
        /// http://www.asp.net/mvc/overview/security/create-an-aspnet-mvc-5-app-with-facebook-and-google-oauth2-and-openid-sign-on
        /// </summary>
        /// <param name="app">app</param>
        public static void Configure(IAppBuilder app)
        {
            // 1 要求につき 1 インスタンスのみを使用するように
            // DB コンテキスト、ユーザー マネージャー、サインイン マネージャーを構成します。

            // Add to OwinContext.

            #region EntityFramework
            //app.CreatePerOwinContext(ApplicationDbContext.Create);
            #endregion

            #region EntityFramework以外

            #region UserStore, ApplicationUserManager, RoleManager, SignInManagerのOwinContextを生成

            // UserStoreのOwinContextを生成
            app.CreatePerOwinContext<UserStore>(() => new UserStore());

            // ApplicationUserManagerのOwinContextを生成
            // 以下を設定する
            // - ユーザ名検証
            // - パスワード検証
            // - ユーザ ロックアウト
            // - 2FAプロバイダ
            // - 暗号化プロバイダ
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            
            // ApplicationRoleManagerのOwinContextを生成
            app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
            
            // ApplicationSignInManagerのOwinContextを生成
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);
            
            #endregion

            #region UseCookieAuthenticationのOwinContextを生成

            // 次を設定
            // - AuthenticationType
            // - LoginPath
            // - Provider
            // - SecurityStamp

            // Enable the application to use a cookie to store information for the signed in user.
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider configure the sign in cookie.

            // アプリケーションがユーザのサイン・イン情報をCookie認証チケットに一時的に保存するようにします。
            // また、サードパーティのプロバイダでログインするユーザ情報もCookie認証チケットを使用してできるようにします。
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,  // 認証タイプを設定する。
                LoginPath = new PathString("/Account/Login"),                       // ログイン画面のパスを設定する。
                Provider = new CookieAuthenticationProvider                         // 認証プロバイダを設定する(ICookieAuthenticationProvider の既定の実装)。
                {
                    #region SecurityStamp

                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.

                    // ユーザーがログインするときにセキュリティ スタンプを検証するように設定します。
                    // これはセキュリティ機能の 1 つであり、パスワードを変更するときやアカウントに外部ログインを追加するときに使用されます。

                    // --------------------------------------------------
                    // SecurityStampValidator.OnValidateIdentity
                    // --------------------------------------------------
                    // パスワードの変更や、外部ログインを追加した際に、全てのログインセッションを
                    // 無効化できるようCookie認証チケットに、ログインに紐付くセキュリティスタンプを埋め込んでいる。
                    // http://kendik.hatenablog.com/entry/2014/08/17/212645
                    // --------------------------------------------------
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        // SecurityStampValidatorによる検証の間隔
                        validateInterval: ASPNETIdentityConfig.SecurityStampValidateIntervalFromSeconds,
                        // ClaimsIdentityを返すdelegate
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))

                    #endregion
                }
            });

            #endregion

            #region UseExternalSignInCookieのOwinContextを生成

            // 外部アイデンティティのためOWINミドルウェアベースの
            // Cookie認証を使用するようにアプリケーションを設定します。
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            #endregion

            #region UseTwoFactor(2FA)のOwinContextを生成

            #region SignInCookie（2FAのCookie認証チケット）

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            // 2FAプロセスにおいて第 2 認証要素を検証しているユーザの情報を一時的に格納するようにします。
            app.UseTwoFactorSignInCookie(
                authenticationType: DefaultAuthenticationTypes.TwoFactorCookie,
                expires: ASPNETIdentityConfig.TwoFactorCookieExpiresFromHours);

            #endregion

            #region RememberBrowserCookie（2FAのブラウザ記憶）

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.

            // 電話や電子メールなど2FAのログイン検証係数を記憶するようにアプリケーションを設定します。
            // このオプションをチェックすると、ログイン時プロセスの第二検証ステップでログインデバイス上に記憶されます。
            // これは、ログイン時の「このアカウントを記憶する」オプションに似ています。

            app.UseTwoFactorRememberBrowserCookie(
                DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            #endregion

            #endregion

            #region Use(External)AuthenticationのOwinContextを生成
            
            // c# - Get E-mail of User Authenticated with Microsoft Account in ASP.NET Identity - Stack Overflow
            // http://stackoverflow.com/questions/22229593/get-e-mail-of-user-authenticated-with-microsoft-account-in-asp-net-identity

            #region MicrosoftAccountAuthentication

            if (ASPNETIdentityConfig.MicrosoftAccountAuthentication)
            {
                MicrosoftAccountAuthenticationOptions options = new MicrosoftAccountAuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = ASPNETIdentityConfig.UseInternetProxy
                    },
                    ClientId = ASPNETIdentityConfig.MicrosoftAccountAuthenticationClientId,
                    ClientSecret = ASPNETIdentityConfig.MicrosoftAccountAuthenticationClientSecret
                };
                // スコープを追加する。
                options.Scope.Add("wl.basic");
                options.Scope.Add("wl.emails");
                
                // MicrosoftAccountAuthenticationの有効化
                app.UseMicrosoftAccountAuthentication(options);
            }

            #endregion

            #region GoogleAuthentication
            
            if (ASPNETIdentityConfig.GoogleAuthentication)
            {
                GoogleOAuth2AuthenticationOptions options = new GoogleOAuth2AuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = ASPNETIdentityConfig.UseInternetProxy
                    },
                    ClientId = ASPNETIdentityConfig.GoogleAuthenticationClientId,
                    ClientSecret = ASPNETIdentityConfig.GoogleAuthenticationClientSecret
                };
                // スコープを追加する。
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");

                // GoogleAuthenticationの有効化
                app.UseGoogleAuthentication(options);
            }

            #endregion

            #region FacebookAuthentication
            
            if (ASPNETIdentityConfig.FacebookAuthentication)
            {
                FacebookAuthenticationOptions options = new FacebookAuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = ASPNETIdentityConfig.UseInternetProxy
                    },
                    AppId = ASPNETIdentityConfig.FacebookAuthenticationClientId,
                    AppSecret = ASPNETIdentityConfig.FacebookAuthenticationClientSecret,
                    Provider = new FacebookAuthenticationProvider
                    {
                        OnAuthenticated = context =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
                            return Task.FromResult(true);
                        }
                    }
                };
                // スコープを追加する。
                options.Scope.Add("email");

                // FacebookAuthenticationの有効化
                app.UseFacebookAuthentication(options);
            }

            #endregion

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            #endregion

            #region OAuth Endpointの追加

            // asp.net identity - UseOAuthBearerTokens vs UseOAuthBearerAuthentication - Stack Overflow
            // http://stackoverflow.com/questions/28048355/useoauthbearertokens-vs-useoauthbearerauthentication
            //   Pseudocode from source using reflector:
            //   UseOAuthAuthorizationServer();  // authorization server middleware.
            //   UseOAuthBearerAuthentication(); // application bearer token middleware.          
            //   UseOAuthBearerAuthentication(); // external bearer token middleware.
            //   UseOAuthBearerTokens();         // extension method creates both the token server
            //                                   //   and the middleware to validate tokens for requests in the same application.

            // c# - ASP.Net identity: Difference between UseOAuthBearerTokens and UseCookieAuthentication? - Stack Overflow
            // http://stackoverflow.com/questions/22121330/asp-net-identity-difference-between-useoauthbearertokens-and-usecookieauthentic

            if (ASPNETIdentityConfig.EquipOAuthServer)
            {
                // OAuth Bearer Tokenを使用可能に設定する。
                // UseOAuthAuthorizationServerとUseOAuthBearerTokensの違いが不明だが、
                // UseOAuthAuthorizationServerだとOAuthBearerTokenEndpointPathが動かない。

                #region UseOAuthAuthorizationServer

                /*
                // --------------------------------------------------
                // OAuthAuthorizationServerを設定する。
                // --------------------------------------------------
                // OAuthAuthorizationServerExtensions.UseOAuthAuthorizationServer メソッド (Owin)
                // https://msdn.microsoft.com/ja-jp/library/dn270711.aspx
                // --------------------------------------------------
                // 参考：https://www.asp.net/aspnet/overview/owin-and-katana/owin-oauth-20-authorization-server
                app.UseOAuthAuthorizationServer(
                    new OAuthAuthorizationServerOptions
                    {
                        Provider = new ApplicationOAuthAuthorizationServerProvider(),
                        AllowInsecureHttp = ASPNETIdentityConfig.AllowOAuthInsecureHttpEndpoints,
                        ApplicationCanDisplayErrors = ASPNETIdentityConfig.OAuthAuthorizeEndpointCanDisplayErrors,
                        AuthorizeEndpointPath = ASPNETIdentityConfig.OAuthAuthorizeEndpointPath,
                        AccessTokenExpireTimeSpan = ASPNETIdentityConfig.OAuthAccessTokenExpireTimeSpanFromMinutes,

                        // Authorization code provider which creates and receives the authorization code.
                        AuthorizationCodeProvider = new AuthenticationTokenProvider
                        {
                            OnCreate = CreateAuthenticationCode,
                            OnReceive = ReceiveAuthenticationCode,
                        },

                        // Refresh token provider which creates and receives refresh token.
                        RefreshTokenProvider = new AuthenticationTokenProvider
                        {
                            OnCreate = CreateRefreshToken,
                            OnReceive = ReceiveRefreshToken,
                        }
                    });
                */

                #endregion

                #region UseOAuthBearerAuthentication

                // --------------------------------------------------
                // Resource Server単品を実装する際のメソッドであるもよう。
                // --------------------------------------------------

                //app.UseOAuthBearerAuthentication(
                //    new OAuthBearerAuthenticationOptions
                //    {
                //    });

                #endregion

                #region UseOAuthBearerTokens

                // --------------------------------------------------
                // OAuth Bearer Tokenを使用可能に設定する。
                // --------------------------------------------------
                // AppBuilderExtensions.UseOAuthBearerTokens Method (IAppBuilder, OAuthAuthorizationServerOptions) (Owin)
                // https://msdn.microsoft.com/ja-jp/library/owin.appbuilderextensions.useoauthbearertokens.aspx
                // --------------------------------------------------
                AuthenticationTokenProvider atp = new AuthenticationTokenProvider();

                // 以下のOAuth 2.0のフロー定義をサポートする。
                // ・Implicitグラント種別
                // ・Resource Owner Password Credentialsグラント種別
                // ・Client Credentialsグラント種別
                OAuthAuthorizationServerOptions oAuthAuthorizationServerOptions =
                    new OAuthAuthorizationServerOptions
                    {
                        #region 全てのグラント種別の共通設定

                        // ・Provider
                        //   OAuthAuthorizationServerProviderの派生クラスである、
                        //   ApplicationOAuthBearerTokenProvider（UseOAuthBearerTokens用）を設定する。
                        //   以下の４つのメソッドをオーバーライドする。
                        //   ・OnValidateClientRedirectUriプロパティ設定 or ValidateClientRedirectUriのオーバーライド
                        //   ・OnValidateClientAuthenticationプロパティ設定 or ValidateClientAuthenticationのオーバーライド
                        //   ・OnGrantResourceOwnerCredentialsプロパティ設定 or GrantResourceOwnerCredentialsのオーバーライド
                        //   ・OnGrantClientCredentialsプロパティ設定 or GrantClientCredentialsのオーバーライド
                        Provider = new ApplicationOAuthBearerTokenProvider(),

                        //AccessTokenFormat = new AccessTokenFormatJwt(),
                
                        // ・AccessTokenExpireTimeSpan（OAuth Access Token の 有効期限
                        AccessTokenExpireTimeSpan = ASPNETIdentityConfig.OAuthAccessTokenExpireTimeSpanFromMinutes, // System.TimeSpan.FromSeconds(10), // Debug時 

                        // ・AllowInsecureHttp
                        //   認証して、Token要求が http URI アドレスに届くことを許可し、
                        //   受信する redirect_uri 承認要求パラメータに http URI アドレスを設定する場合は true。
                        AllowInsecureHttp = ASPNETIdentityConfig.AllowOAuthInsecureHttpEndpoints,

                        #endregion

                        #region  Implicitグラント種別を除く全てのグラント種別の共通設定

                        // ・OAuth Bearer Token の Token Endpoint
                        TokenEndpointPath = new PathString(ASPNETIdentityConfig.OAuthBearerTokenEndpoint),

                        #endregion

                        #region Authorization Code, Implicitグラント種別の共通設定

                        // ・AuthorizeEndpointPath
                        //   OAuth の Authorize Endpoint
                        AuthorizeEndpointPath = new PathString(ASPNETIdentityConfig.OAuthAuthorizeEndpoint),

                        // ・ApplicationCanDisplayErrors
                        //   AuthorizeEndpointPath上でエラー メッセージを表示できるようにする。
                        ApplicationCanDisplayErrors = ASPNETIdentityConfig.OAuthAuthorizeEndpointCanDisplayErrors,

                        #endregion

                        #region Authorization Codeグラント種別

                        #region AuthorizationCodeProvider
                        //   1 回だけ使用する認証コードを生成して、クライアント アプリケーションに返す。
                        //   OnCreate または OnCreateAsync イベントによって生成されたトークンは、
                        //   OnReceive または OnReceiveAsync イベントへの呼び出しに対して、一度だけ有効となる。
                        //   Authorization code provider which creates and receives authorization code
                        AuthorizationCodeProvider = new AuthenticationTokenProvider
                        {
                            OnCreate = AuthorizationCodeProvider.GetInstance().Create,
                            OnReceive = AuthorizationCodeProvider.GetInstance().Receive,
                            //OnCreateAsync = AuthorizationCodeProvider.GetInstance().CreateAsync,
                            //OnReceiveAsync = AuthorizationCodeProvider.GetInstance().ReceiveAsync,
                        },
                        #endregion

                        #region  RefreshTokenProvider
                        //   必要に応じて、新しいAccessTokenの生成に使うことができるRefresh Tokenを生成する。 
                        //   RefreshTokenProviderが提供されない場合、OAuthBearerTokenEndpointPathからRefresh Tokenが返されない。
                        //   Refresh token provider which creates and receives referesh token
                        RefreshTokenProvider = new AuthenticationTokenProvider
                        {
                            OnCreate = RefreshTokenProvider.GetInstance().Create,
                            OnReceive = RefreshTokenProvider.GetInstance().Receive,
                            //OnCreateAsync = RefreshTokenProvider.GetInstance().CreateAsync,
                            //OnReceiveAsync = RefreshTokenProvider.GetInstance().ReceiveAsync,
                        },
                        #endregion

                        #endregion
                    };

                #region Options可変部分
                // AccessTokenFormat（OAuth Access Token の Format をJWTフォーマットに変更する。
                if (ASPNETIdentityConfig.EnableCustomTokenFormat)
                    oAuthAuthorizationServerOptions.AccessTokenFormat = new AccessTokenFormatJwt();
                #endregion

                // UseOAuthBearerTokensにOAuthAuthorizationServerOptionsを設定
                app.UseOAuthBearerTokens(oAuthAuthorizationServerOptions);

                #endregion
            }

            #endregion

            #endregion
        }
    }
}