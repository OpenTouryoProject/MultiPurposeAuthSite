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
            }

            // HttpContextのマイグレーション用
            app._UseHttpContextAccessor();

            app.UseHttpsRedirection();

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
                    Name = GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName"),
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
                #region Account
                endpoints.MapControllerRoute(
                   name: "Saml2Request",
                   pattern: Config.Saml2RequestEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "Saml2Request" });

                endpoints.MapControllerRoute(
                   name: "OAuth2Authorize",
                   pattern: Config.OAuth2AuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "OAuth2Authorize" });
                #endregion

                #region OAuth2Endpoint

                #region OAuth2 / OIDC

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
                    name: "RequestObjectUri",
                    pattern: OAuth2AndOIDCParams.RequestObjectRegUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RequestObjectUri" });

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

                #region Push Notification

                endpoints.MapControllerRoute(
                    name: "SetDeviceToken",
                    pattern: Config.SetDeviceTokenWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "SetDeviceToken" });

                endpoints.MapControllerRoute(
                    name: "TwoFactorAuthPushResult",
                    pattern: Config.TwoFactorAuthPushResultWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "TwoFactorAuthPushResult" });

                #endregion

                #endregion

                #region OAuth2ResourceServer
                endpoints.MapControllerRoute(
                    name: "TestHybridFlow",
                    pattern: Config.TestHybridFlowWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2ResourceServer", action = "TestHybridFlow" });

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
                    idOptions.User.RequireUniqueEmail = Config.RequireUniqueEmail;

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

            authenticationBuilder.AddCookie(options =>
                {
                    // https://community.auth0.com/t/asp-net-core-2-intermittent-correlation-failed-errors/11918/18
                    options.LoginPath = "/MultiPurposeAuthSite/Account/Login";
                    options.LogoutPath = "/MultiPurposeAuthSite/Account/LogOff";
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter; 
                    options.ExpireTimeSpan = new TimeSpan(0, 2, 0);
                    options.SlidingExpiration = true;

                    //options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                    //options.Cookie.Name = "YourAppCookieName";
                    options.Cookie.HttpOnly = true;
                    
                    options.Events = options.Events = new CookieAuthenticationEvents()
                    {
                        OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
                    };
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
                });
            }
            if (Config.FacebookAuthentication)
            {
                authenticationBuilder.AddFacebook(options =>
                {
                    options.AppId = Config.FacebookAuthenticationClientId;
                    options.AppSecret = Config.FacebookAuthenticationClientSecret;
                });
            }
            if (Config.TwitterAuthentication)
            {
                authenticationBuilder.AddTwitter(options =>
                {
                    options.ConsumerKey = Config.TwitterAuthenticationClientId;
                    options.ConsumerSecret = Config.TwitterAuthenticationClientSecret;
                    options.RetrieveUserDetails = true;
                });
            }
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
