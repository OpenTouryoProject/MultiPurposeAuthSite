//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：Startup
//* クラス日本語名  ：Startup
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//*  2020/02/28  西野 大介         プッシュ通知、CIBA対応実施
//*  2020/07/29  西野 大介         SecurityStamp対応
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認（/2fa_result）のルートを追加（#213）
//*  2026/09/17  玄人 幸道         開発向けの設定が残っていないかを起動時に確かめる（#219）
//*  2026/09/17  玄人 幸道         テスト用の口（/TestHybridFlow）を閉じられるようにする（#219）
//*  2026/09/19  玄人 幸道         認証クッキーの設定を、実際に使うスキームへ移す（#223）
//*  2026/09/25  玄人 幸道         設定キーの改名（AuthRequestPushUri）に追随（#236）
//*  2026/09/27  玄人 幸道         AuthRequestPushUri は Open棟梁 側で読むようにした（#236 の宿題）
//*  2026/09/27  玄人 幸道         /end_session（RP-Initiated Logout）のルートを追加（#232）
//*  2026/09/30  玄人 幸道         Google の email_verified をクレームに写す（#140 の段階 1）
//*  2026/09/30  玄人 幸道         AuthCookieName で認証 Cookie の名前を変えられるようにした（#250 の段階 4）
//*  2026/10/01  玄人 幸道         TempData の Cookie にも接頭辞を付ける（#255）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Notifications;

using System;
using System.IO;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Caching.Memory;

//using Microsoft.AspNetCore.Mvc.Cors.Internal;
using Microsoft.AspNetCore.Mvc; // CookieTempDataProviderOptions（#255）

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Util;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// Startup
    /// ミドルウェア /サービス / フレームワークを
    /// Startupクラスのメソッドで注入することにより、活用できるようになる。
    /// </summary>
    public class Startup
    {
    	#region mem & prop & constructor

        /// <summary>Configuration</summary>
        public IConfiguration Configuration { get; }
        
        /// <summary>constructor</summary>
        /// <param name="configuration">IConfiguration</param>
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            // ライブラリにも設定
            GetConfigParameter.InitConfiguration(configuration);
            // Dockerで埋め込まれたリソースを使用する場合、
            // 以下のコメントアウトを解除し、appsettings.jsonのappSettings sectionに、
            // "Azure": "既定の名前空間" を指定し、設定ファイルを埋め込まれたリソースに変更する。
            //Touryo.Infrastructure.Business.Dao.MyBaseDao.UseEmbeddedResource = true;
        }

        #endregion
        
        #region Configure & ConfigureServices
        
        /// <summary>
        /// This method gets called by the runtime.
        /// Use this method to configure the HTTP request pipeline.
        /// </summary>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {            
            // **開発向けの設定が残っていないかを確かめる**（#219。CONFIGURATION.md 11 節）。
            //   起動は止めない。警告を OPERATION ログに出すだけ。
            ProductionCheck.WarnIfRisky();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");

                // The default HSTS value is 30 days.
                // You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
                //app.UseHttpsRedirection();
            }

            // HttpContextのマイグレーション用
            app._UseHttpContextAccessor();

            // /wwwroot（既定の）の
            // 静的ファイルをパイプラインに追加
            app.UseStaticFiles();

            // Cookieを使用する。
            app.UseCookiePolicy(new CookiePolicyOptions()
            {
                HttpOnly = HttpOnlyPolicy.Always,
                // https://github.com/aspnet/Security/issues/1822
                MinimumSameSitePolicy = SameSiteMode.None, //SameSiteMode.Strict,
                //Secure= CookieSecurePolicy.Always
            });

            // Sessionを使用する。
            app.UseSession(new SessionOptions()
            {
                IdleTimeout = TimeSpan.FromMinutes(30), // ここで調整
                IOTimeout = TimeSpan.FromSeconds(30),
                Cookie = new CookieBuilder()
                {
                    Expiration = TimeSpan.FromDays(1), // 効かない
                    HttpOnly = true,
                    // **接頭辞を掛ける**（#255。同じホストに 2 つ立てたときに分けるため）
                    Name = Config.PrefixCookieName(
                        GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName")),
                    Path = "/",
                    SameSite = SameSiteMode.Strict,
                    SecurePolicy = CookieSecurePolicy.SameAsRequest
                }
            });

            // Routing
            app.UseRouting();

            // Identity
            app.UseAuthentication();
            app.UseAuthorization();
            
            app.UseCors( //認証・認可の後ろ
                builder => builder
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader());
                    
            //.AllowCredentials());
            
            app.UseEndpoints(endpoints =>
            {
                #region AuthZ(N)Server

                #region Initial Request
                endpoints.MapControllerRoute(
                   name: "Saml2Request",
                   pattern: Config.Saml2RequestEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "Saml2Request" });

                endpoints.MapControllerRoute(
                   name: "OAuth2Authorize",
                   pattern: Config.OAuth2AuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "OAuth2Authorize" });

                // **RP からのログアウト**（RP-Initiated Logout 1.0。#232）
                endpoints.MapControllerRoute(
                   name: "EndSession",
                   pattern: Config.OAuth2EndSessionEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "EndSession" });
                #endregion

                #region WebAPI Endpoint

                endpoints.MapControllerRoute(
                    name: "OAuth2Token",
                    pattern: Config.OAuth2TokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "OAuth2Token" });

                endpoints.MapControllerRoute(
                    name: "GetUserClaims",
                    pattern: Config.OAuth2UserInfoEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "GetUserClaims" });

                endpoints.MapControllerRoute(
                    name: "RevokeToken",
                    pattern: Config.OAuth2RevokeTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RevokeToken" });

                endpoints.MapControllerRoute(
                    name: "IntrospectToken",
                    pattern: Config.OAuth2IntrospectTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "IntrospectToken" });

                endpoints.MapControllerRoute(
                    name: "JwksUri",
                    pattern: OAuth2AndOIDCParams.JwkSetUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "JwksUri" });

                endpoints.MapControllerRoute(
                    name: "PushedAuthorizationRequest",
                    pattern: OAuth2AndOIDCParams.AuthRequestPushUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "PushedAuthorizationRequest" });

                endpoints.MapControllerRoute(
                    name: "RequestObjectUri",
                    pattern: OAuth2AndOIDCParams.RequestObjectRegUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RequestObjectUri" });

                #endregion

                #region Back Channel

                #region Device AuthZ

                endpoints.MapControllerRoute(
                    name: "DeviceAuthZAuthorize",
                    pattern: Config.DeviceAuthZAuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "DeviceAuthZAuthorize" });

                endpoints.MapControllerRoute(
                    name: "DeviceAuthZVerify",
                    pattern: Config.DeviceAuthZVerifyEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "Account", action = "DeviceAuthZVerify" });

                #endregion

                #region CIBA FAPI2

                endpoints.MapControllerRoute(
                    name: "CibaAuthorize",
                    pattern: Config.CibaAuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "CibaAuthorize" });

                endpoints.MapControllerRoute(
                    name: "CibaPushResult",
                    pattern: Config.CibaPushResultEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "CibaPushResult" });

                #endregion

                #endregion

                #region Push Notification

                endpoints.MapControllerRoute(
                    name: "SetDeviceToken",
                    pattern: Config.SetDeviceTokenWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "SetDeviceToken" });

                endpoints.MapControllerRoute(
                    name: "TwoFactorPushResult",
                    pattern: Config.TwoFactorPushResultEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "TwoFactorPushResult" });

                #endregion

                #endregion

                #region ResourceServer
                // **テスト用の口は、閉じられるようにする**（#219）。
                if (!Config.IsLockedDownTestEndpoints)
                {
                    endpoints.MapControllerRoute(
                        name: "TestHybridFlow",
                        pattern: Config.TestHybridFlowWebAPI.Substring(1), // 先頭の[/]を削除,
                        defaults: new { controller = "OAuth2ResourceServer", action = "TestHybridFlow" });
                }

                endpoints.MapControllerRoute(
                    name: "ChageToUser",
                    pattern: Config.ChageToUserWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2ResourceServer", action = "ChageToUser" });
                #endregion

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        /// <summary>
        /// This method gets called by the runtime.
        /// Use this method to add services to the container.
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        public void ConfigureServices(IServiceCollection services)
        {
            // 構成情報から、AppConfiguration SectionをAppConfiguration Classへバインドするようなケース。
            //services.Configure<AppConfiguration>(Configuration.GetSection("AppConfiguration"));

            // HttpContextのマイグレーション用
            services._AddHttpContextAccessor();

            #region DataProtection の鍵の永続化（#251。C-13）

            // **鍵の置き場を指定しないと、%LOCALAPPDATA% 配下に置かれる**（コンテナでは揮発）。
            //   そうすると —
            //     ・**再起動で認証 Cookie と AntiForgery トークンが全て無効**になる
            //     ・**複数インスタンスでインスタンス間の Cookie が通らない**
            //     ・**メール確認 / パスワード リセットのリンクが切れる**
            //       （DataProtectorTokenProvider が使う）
            //
            //   **net48 の <machineKey> と同じ役割**だが、**鍵そのものは設定に書かない。**
            //   **鍵は自動生成・自動ローテーションされ、その「置き場」を共有する。**
            //
            //   **access_token / id_token には影響しない**（JWS。自前の署名鍵）。
            //   **PPID にも影響しない**（SaltParameter から導出）。
            //   **認可コード / refresh_token にも影響しない**（サーバ側のストアに保存）。
            //   つまり「発行済みのトークンが無効になる」話ではなく、
            //   **「画面のセッションが切れる」**話である。
            //
            // **未設定なら、従来どおり何もしない**（下位互換）。
            if (!string.IsNullOrEmpty(Config.DataProtectionKeyPath))
            {
                services.AddDataProtection()
                    .PersistKeysToFileSystem(
                        new DirectoryInfo(Config.DataProtectionKeyPath));

                // **鍵リングは平文の XML である。** マウント先の保護は運用側の責任。
                //   証明書で包む（ProtectKeysWithCertificate）かどうかは、ここでは決めない。
            }

            #endregion

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent
                // for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
            });

                // Sessionのモード
                services.AddDistributedMemoryCache(); // 開発用
                //services.AddDistributedSqlServerCache();
                //services.AddDistributedRedisCache();

            // Sessionを使用する。
            services.AddSession();

            // Core 3.0のテンプレートではUseMvcの
            // 代わりにこれらを使用するようになった。
            services
                .AddControllersWithViews()// MVC & WebAPI
                .AddNewtonsoftJson();// JSON シリアライザの変更

            #region Add Frameworks

            // 一般的な Webアプリでは、
            // EF, Identity, MVC などのミドルウェア サービスを登録する。
            // ミドルウェアの実行順序は、IStartupFilter の登録順に設定される。

            // EF
            //services.AddDbContext<ApplicationDbContext>(options =>
            //    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            // AddMvc
            services.AddMvc();

            // **TempData の Cookie の名前にも接頭辞を付ける**（#255）。
            //   **空なら既定のまま**（`.AspNetCore.Mvc.CookieTempDataProvider`）。
            //
            //   **同じホストに 2 つ立てると、この Cookie も上書きし合う**
            //   （Cookie のスコープにポートは入らないため）。
            //   **中身は配備ごとの鍵で守られており相手は読めない**が、**消えるので
            //   画面のメッセージ（[TempData] ErrorMessage など）が出なくなる。**
            //
            //   **net10.0 版だけの話。** net48 版の TempData はセッションに載る。
            //   **PostConfigure で掛ける。** 既定の名前が入った後に読みたいため
            //   （Configure だと、既定が入る前に走る余地がある）。
            if (!string.IsNullOrEmpty(Config.CookieNamePrefix))
            {
                services.PostConfigure<CookieTempDataProviderOptions>(options =>
                {
                    options.Cookie.Name = Config.PrefixCookieName(options.Cookie.Name);
                });

                // **Identity が使う Cookie すべてに掛ける**（#255）。
                //   **AuthCookieName で名前を決めた後**に付けたいので、PostConfigure で行う。
                //   AuthCookieName が空でも、**枠組みの既定名に接頭辞が付く。**
                //
                //   **サインインの Cookie（Application）だけでは足りない。**
                //   **外部ログイン（External）は ID フェデレーションと外部 IdP の途中で使い**、
                //   **2 要素認証（TwoFactor*）も同じように途中の状態を持つ。**
                //   **これらが混ざると、連携や 2FA の途中で別のサイトの状態を掴む。**
                string[] identitySchemes = new string[]
                {
                    IdentityConstants.ApplicationScheme,
                    IdentityConstants.ExternalScheme,
                    IdentityConstants.TwoFactorUserIdScheme,
                    IdentityConstants.TwoFactorRememberMeScheme
                };

                foreach (string scheme in identitySchemes)
                {
                    services.PostConfigure<CookieAuthenticationOptions>(
                        scheme, options =>
                        {
                            options.Cookie.Name = Config.PrefixCookieName(options.Cookie.Name);
                        });
                }
            }

            // AddCors
            services.AddCors(
                o => o.AddPolicy("AllowAllOrigins",
                builder =>
                {
                    builder
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
                }));

            #region ASP.NET Core Identity

            // must be added before AddIdentity()
            services.AddScoped<IPasswordHasher<ApplicationUser>, CustomPasswordHasher<ApplicationUser>>();
            services.AddScoped<ISecurityStampValidator, SecurityStampValidator<ApplicationUser>>();

            services.AddIdentity<ApplicationUser, ApplicationRole>()
                //.AddEntityFrameworkStores<ApplicationDbContext>()
                .AddUserStore<UserStoreCore>()
                .AddRoleStore<RoleStoreCore>()
                .AddDefaultTokenProviders();
            
            // Add application services.
            services.AddTransient<IUserStore<ApplicationUser>, UserStoreCore>();
            services.AddTransient<IRoleStore<ApplicationRole>, RoleStoreCore>();
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<ISmsSender, SmsSender>();

            #region 認証

            #region IdentityOptions

            Action<IdentityOptions> IdentityOptionsConf = new Action<IdentityOptions>(idOptions =>
                {
                    // ユーザー
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#user
                    //idOptions.SignIn.AllowedUserNameCharacters = false;
                    // **メアドは常に一意**（#151 の段階 3）。
                    //   **利用者名とメアドの両方でサインインできる**ので、
                    //   **メアドが一意でないと FindByEmailAsync が成り立たない。**
                    //   以前は RequireUniqueEmail の設定で切り替えていた（その設定は落とした）。
                    idOptions.User.RequireUniqueEmail = true;

                    // サインイン
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#sign-in
                    idOptions.SignIn.RequireConfirmedEmail = false;
                    idOptions.SignIn.RequireConfirmedPhoneNumber = false;

                    // パスワード検証（8文字以上の大文字・小文字、数値、記号
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#password
                    idOptions.Password.RequiredLength = Config.RequiredLength;
                    idOptions.Password.RequireNonAlphanumeric = Config.RequireNonLetterOrDigit;
                    idOptions.Password.RequireDigit = Config.RequireDigit;
                    idOptions.Password.RequireLowercase = Config.RequireLowercase;
                    idOptions.Password.RequireUppercase = Config.RequireUppercase;

                    // ユーザ ロックアウト
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#lockout
                    idOptions.Lockout.DefaultLockoutTimeSpan = Config.DefaultAccountLockoutTimeSpanFromSeconds;
                    idOptions.Lockout.MaxFailedAccessAttempts = Config.MaxFailedAccessAttemptsBeforeLockout;
                    idOptions.Lockout.AllowedForNewUsers = Config.UserLockoutEnabledByDefault;

                    // 二要素認証

                    // トークン
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#tokens
                    //idOptions.Tokens...

                });

            services.Configure<IdentityOptions>(IdentityOptionsConf);

            #endregion

            #region AuthOptions

            AuthenticationBuilder authenticationBuilder = services.AddAuthentication();

            #region AuthCookie

            // **スキーム "Cookies" の登録は、外せない（#223）。**
            //   Open棟梁のフレームワーク（MyMVCCoreFilterAttribute）がこのスキームを参照するため、
            //   登録が無いと、次の例外で落ちる。
            //     No authentication handler is registered for the scheme 'Cookies'.
            //
            //   **ただし、このサイトがサインインに使うのは Identity.Application。**
            //   ここに LoginPath や ExpireTimeSpan を書いても**効かない**ので、書かない。
            //   実際の設定は、下の ConfigureApplicationCookie で行う。
            authenticationBuilder.AddCookie();

            // **ASP.NET Core Identity のクッキー（Identity.Application）を設定する（#223）。**
            //
            //   以前は authenticationBuilder.AddCookie(options => ...) に書いていたが、
            //   **それはスキーム "Cookies" の設定で、サインインには使われていなかった。**
            //   AddIdentity が既定のスキームを Identity.Application にするため、
            //   **書いた設定が 1 つも効いていなかった**（LoginPath も ExpireTimeSpan も）。
            //
            //   ConfigureApplicationCookie は Identity.Application を設定するので、
            //   ここに書いたことが実際に効く。**AddIdentity より後に呼ぶこと。**
            services.ConfigureApplicationCookie(options =>
                {
                    // **接頭辞を直書きしない。** PathBase は実行時に前置される
                    //   （IIS Express の仮想アプリでは /MultiPurposeAuthSite が付く）。
                    options.LoginPath = "/Account/Login";
                    options.LogoutPath = "/Account/LogOff";
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    // **net48 と同じ設定キーで揃える**（App_Start/StartupAuth.cs）。
                    //   以前の net10.0 は、この 2 つを読んでいなかった。
                    options.ExpireTimeSpan = Config.AuthCookieExpiresFromHours;
                    options.SlidingExpiration = Config.AuthCookieSlidingExpiration;

                    //options.AccessDeniedPath = "/Identity/Account/AccessDenied";

                    // **Cookie の名前を設定で変えられるようにする**（#250 の段階 4）。
                    //   **空なら既定のまま**（`.AspNetCore.Identity.Application`）。
                    //   **同じホストに 2 つ立てるときだけ指定する**
                    //   （Cookie のスコープにポートは入らないため、
                    //     上流と下流を同じホストで動かすと、同名の Cookie が奪い合いになる）。
                    if (!string.IsNullOrEmpty(Config.AuthCookieName))
                    {
                        options.Cookie.Name = Config.AuthCookieName;
                    }

                    options.Cookie.HttpOnly = true;

                    // ※ SecurityStamp の検証（OnValidatePrincipal）は書かない。
                    //    Identity が既定で設定しており、間隔は
                    //    SecurityStampValidatorOptions.ValidationInterval で指定している（下の方）。
                });

            #endregion

            #region 外部ログイン
            if (Config.MicrosoftAccountAuthentication)
            {
                authenticationBuilder.AddMicrosoftAccount(options =>
                {
                    options.ClientId = Config.MicrosoftAccountAuthenticationClientId;
                    options.ClientSecret = Config.MicrosoftAccountAuthenticationClientSecret;
                });
            }
            if (Config.GoogleAuthentication)
            {
                authenticationBuilder.AddGoogle(options =>
                {
                    options.ClientId = Config.GoogleAuthenticationClientId;
                    options.ClientSecret = Config.GoogleAuthenticationClientSecret;

                    // **email_verified をクレームに写す**（#140 の段階 1）。
                    //   Google は userinfo で email_verified を返すが、
                    //   **既定の ClaimActions には含まれない**ので、明示的に写す。
                    //   これが無いと、**Google はメアドを検証しているのに**
                    //   「言っていない」扱いになり、既存アカウントへのリンクが拒否される
                    //   （判定は Extensions.Sts.AccountLink）。
                    //
                    //   **他の 3 つ（Microsoft / Facebook / Twitter）には足さない。**
                    //     Microsoft : Graph の /me に相当するクレームが無い
                    //     Facebook  : verified はアカウントの検証で、メアドの検証ではない
                    //     Twitter   : メアド自体が返らないのが普通
                    options.ClaimActions.MapJsonKey(
                        OAuth2AndOIDCConst.email_verified, OAuth2AndOIDCConst.email_verified);
                });
            }
            // **Facebook / Twitter は取り下げた**（#249）。
            //   **動かないからではなく、維持コストが便益に見合わないため。**
            //   ・この 2 つだけ、メアドを取るための専用コードを抱えていた（net48 側）
            //   ・両アプリに二重にあり、外部 API の変更に追随する必要があった
            //   ・#140 の段階 1（C-23）以降、**検証済みのメアドを示せないので、
            //     既存アカウントへの自動リンクができない側に固定される**
            //
            //   **削除せずコメントアウトにしてある**（WebAuthn / MS Passport と同じ扱い）。
            //   判断が変われば戻せるように、パッケージ参照と設定キーも残してある。
            //if (Config.FacebookAuthentication)
            //{
            //    authenticationBuilder.AddFacebook(options =>
            //    {
            //        options.AppId = Config.FacebookAuthenticationClientId;
            //        options.AppSecret = Config.FacebookAuthenticationClientSecret;
            //    });
            //}
            //if (Config.TwitterAuthentication)
            //{
            //    authenticationBuilder.AddTwitter(options =>
            //    {
            //        options.ConsumerKey = Config.TwitterAuthenticationClientId;
            //        options.ConsumerSecret = Config.TwitterAuthenticationClientSecret;
            //        options.RetrieveUserDetails = true;
            //    });
            //}
            #endregion

            #region OAuth2 / OIDC

            // スクラッチ実装

            #endregion

            #endregion

            services.Configure<SecurityStampValidatorOptions>(options =>
            {
                options.ValidationInterval = Config.SecurityStampValidateIntervalFromSeconds;
            });

            #endregion

            #endregion

            #region Forms認証
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            //{
            //    options.LoginPath = new PathString("/Home/Login");
            //    //options.LogoutPath = new PathString("/Home/Logout");
            //    options.AccessDeniedPath = new PathString(GetConfigParameter.GetConfigValue("FxErrorScreenPath"));
            //    options.ReturnUrlParameter = "ReturnUrl";
            //    options.ExpireTimeSpan = TimeSpan.FromHours(1);
            //    options.SlidingExpiration = true;
            //    options.Cookie.HttpOnly = true;
            //    //options.DataProtectionProvider = DataProtectionProvider.Create(new DirectoryInfo(@"C:\artifacts"));
            //});
            #endregion

            #endregion
        }

        #endregion
    }
}
