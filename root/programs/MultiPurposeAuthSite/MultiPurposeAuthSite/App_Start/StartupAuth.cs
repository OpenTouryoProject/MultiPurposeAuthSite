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

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.TokenProviders;

using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Twitter;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite
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

            #region AuthenticationType

            // AuthenticationType:
            //   ClaimsIdentity生成時や、AuthenticationTicket取得時に指定する。

            // --------------------------------------------------
            // OAuthDefaultsクラス (Microsoft.Owin.Security)
            // https://msdn.microsoft.com/ja-jp/library/microsoft.owin.security.oauth.oauthdefaults.aspx
            // --------------------------------------------------
            // - OAuthDefaults.AuthenticationType フィールド (Microsoft.Owin.Security.OAuth)
            //   https://msdn.microsoft.com/ja-jp/library/microsoft.owin.security.oauth.oauthdefaults.authenticationtype.aspx
            //   OAuthBearerAuthenticationOptions と OAuthAuthorizationServerOptions の AuthenticationType プロパティの既定値。
            //   - AuthenticationOptions.AuthenticationType プロパティ (Microsoft.Owin.Security)
            //     https://msdn.microsoft.com/ja-jp/library/dn300391.aspx
            //   - AuthenticationOptions.AuthenticationType プロパティ (Microsoft.Owin.Security)
            //     https://msdn.microsoft.com/ja-jp/library/dn300391.aspx
            // --------------------------------------------------

            // --------------------------------------------------
            // DefaultAuthenticationTypes クラス (Microsoft.AspNet.Identity)
            // https://msdn.microsoft.com/ja-jp/library/microsoft.aspnet.identity.defaultauthenticationtypes.aspx
            // --------------------------------------------------
            // - ApplicationCookie
            //   Forms認証用 Cookie認証チケット
            //   https://msdn.microsoft.com/ja-jp/library/microsoft.aspnet.identity.defaultauthenticationtypes.applicationcookie.aspx
            // - TwoFactorRememberBrowserCookie
            //   Browser認証用 Cookie認証チケット
            //   https://msdn.microsoft.com/en-us/library/microsoft.aspnet.identity.defaultauthenticationtypes.twofactorrememberbrowsercookie.aspx
            // - TwoFactorCookie
            //   TwoFactor認証用 Cookie認証チケット
            //   https://msdn.microsoft.com/en-us/library/microsoft.aspnet.identity.defaultauthenticationtypes.twofactorcookie.aspx
            // - ExternalCookie
            //   外部ログイン Cookie認証チケット
            //   /userinfoやid_tokenの情報をCookieに格納してある。
            //   https://msdn.microsoft.com/ja-jp/library/microsoft.aspnet.identity.defaultauthenticationtypes.externalcookie.aspx
            // - ExternalBearer
            //   Bearer TokenのUnprotectする際、ClaimsIdentityに指定。
            //   https://msdn.microsoft.com/ja-jp/library/microsoft.aspnet.identity.defaultauthenticationtypes.externalbearer.aspx
            // --------------------------------------------------

            #endregion

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
                        validateInterval: Config.SecurityStampValidateIntervalFromSeconds,
                        // ClaimsIdentityを返すdelegate
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                        
                    #endregion
                },

                // Cookie認証チケットの有効期限
                ExpireTimeSpan = Config.AuthCookieExpiresFromHours,
                // Cookie認証チケットの有効期限を半分過ぎた祭の要求で再発行(Sliding)される。
                SlidingExpiration = Config.AuthCookieSlidingExpiration,

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
                expires: Config.TwoFactorCookieExpiresFromHours);

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

            if (Config.MicrosoftAccountAuthentication)
            {
                MicrosoftAccountAuthenticationOptions options = new MicrosoftAccountAuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = Config.UseInternetProxy
                    },
                    ClientId = Config.MicrosoftAccountAuthenticationClientId,
                    ClientSecret = Config.MicrosoftAccountAuthenticationClientSecret
                };
                // スコープを追加する。
                options.Scope.Add("wl.basic");
                options.Scope.Add("wl.emails");
                
                // MicrosoftAccountAuthenticationの有効化
                app.UseMicrosoftAccountAuthentication(options);
            }

            #endregion

            #region GoogleAuthentication
            
            if (Config.GoogleAuthentication)
            {
                GoogleOAuth2AuthenticationOptions options = new GoogleOAuth2AuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = Config.UseInternetProxy
                    },
                    ClientId = Config.GoogleAuthenticationClientId,
                    ClientSecret = Config.GoogleAuthenticationClientSecret
                };
                // スコープを追加する。
                options.Scope.Add(OAuth2AndOIDCConst.Scope_Openid);
                options.Scope.Add(OAuth2AndOIDCConst.Scope_Profile);
                options.Scope.Add(OAuth2AndOIDCConst.Scope_Email);

                // GoogleAuthenticationの有効化
                app.UseGoogleAuthentication(options);
            }

            #endregion

            #region FacebookAuthentication

            if (Config.FacebookAuthentication)
            {
                FacebookAuthenticationOptions options = new FacebookAuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = Config.UseInternetProxy
                    },
                    AppId = Config.FacebookAuthenticationClientId,
                    AppSecret = Config.FacebookAuthenticationClientSecret,
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
                options.Scope.Add(OAuth2AndOIDCConst.Scope_Email);

                // FacebookAuthenticationの有効化
                app.UseFacebookAuthentication(options);
            }

            #endregion

            #region TwitterAuthentication

            if (Config.TwitterAuthentication)
            {
                TwitterAuthenticationOptions options = new TwitterAuthenticationOptions
                {
                    BackchannelHttpHandler = new WebRequestHandler()
                    {
                        Proxy = CreateProxy.GetInternetProxy(),
                        UseProxy = Config.UseInternetProxy
                    },
                    ConsumerKey = Config.TwitterAuthenticationClientId,
                    ConsumerSecret = Config.TwitterAuthenticationClientSecret,

                    Provider = new TwitterAuthenticationProvider
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_token", context.AccessToken));
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_secret", context.AccessTokenSecret));
                            return Task.FromResult(0);
                        }
                    },

                    BackchannelCertificateValidator = new CertificateSubjectKeyIdentifierValidator(
                        new string[] {
                            "A5EF0B11CEC04103A34A659048B21CE0572D7D47",  // VeriSign Class 3 Secure Server CA - G2
                            "0D445C165344C1827E1D20AB25F40163D8BE79A5",  // VeriSign Class 3 Secure Server CA - G3
                            "7FD365A7C2DDECBBF03009F34339FA02AF333133",  // VeriSign Class 3 Public Primary Certification Authority - G5
                            "39A55D933676616E73A761DFA16A7E59CDE66FAD",  // Symantec Class 3 Secure Server CA - G4
                            "5168FF90AF0207753CCCD9656462A212B859723B",  // DigiCert SHA2 High Assurance Server C‎A 
                            "B13EC36903F8BF4701D498261A0802EF63642BC3" } // DigiCert High Assurance EV Root CA
                            ),
                };

                // スコープを追加する。
                // ・・・

                // TwitterAuthenticationの有効化
                app.UseTwitterAuthentication(options);
            }

            #endregion

            #endregion

            #endregion
        }
    }
}