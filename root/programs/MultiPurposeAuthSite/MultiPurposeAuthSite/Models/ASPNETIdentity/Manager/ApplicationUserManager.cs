//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ApplicationUserManager
//* クラス日本語名  ：ユーザ情報の永続化管理クラス（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.NotificationProvider;

using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.Manager</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Manager
{
    /// <summary>
    /// ApplicationUserManager
    /// Configure the application user manager used in this application.
    /// UserManager is defined in ASP.NET Identity and is used by the application.
    /// このアプリケーションで使用されるアプリケーションのUserManagerを構成します。
    /// UserManagerはASP.NET Identityで定義されており、アプリケーションによって使用されます。
    /// 
    /// UserManager(TUser) クラス (Microsoft.AspNet.Identity)
    /// https://msdn.microsoft.com/ja-jp/library/dn468199.aspx
    /// 　Exposes user related api which will automatically save changes to the UserStore
    /// 　自動的に UserStore に変更を保存する api に関連するユーザーを公開する
    /// </summary>
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        /// <summary>constructor</summary>
        /// <param name="store">IUserStore</param>
        public ApplicationUserManager(IUserStore<ApplicationUser> store) : base(store) { }

        /// <summary>Create</summary>
        /// <param name="options">options</param>
        /// <param name="context">context</param>
        /// <returns>ApplicationUserManager</returns>
        /// <remarks>
        /// ApplicationSignInManagerのOwinContext生成で利用されるdelegate
        /// </remarks>
        public static ApplicationUserManager Create(
            IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            // EntityFrameworkの場合
            // var manager = new ApplicationUserManager(
            //     new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));

            // EntityFrameworkでない場合
            ApplicationUserManager manager = new ApplicationUserManager(new UserStore());

            #region ユーザ名検証

            // Configure validation logic for usernames
            // ユーザ名のための検証ロジックを設定（メアド）
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                // ユーザ名は、E-mail
                AllowOnlyAlphanumericUserNames = ASPNETIdentityConfig.AllowOnlyAlphanumericUserNames,
                RequireUniqueEmail = ASPNETIdentityConfig.RequireUniqueEmail
            };

            #endregion
            
            #region パスワード検証

            // Configure validation logic for passwords
            // パスワードの検証ロジックを設定
            manager.PasswordValidator = new PasswordValidator
            {
                // 初期設定
                //    RequiredLength = 6,
                //    RequireNonLetterOrDigit = true,
                //    RequireDigit = true,
                //    RequireLowercase = true,
                //    RequireUppercase = true,
                
                RequiredLength = ASPNETIdentityConfig.RequiredLength,
                RequireNonLetterOrDigit = ASPNETIdentityConfig.RequireNonLetterOrDigit,
                RequireDigit = ASPNETIdentityConfig.RequireDigit,
                RequireLowercase = ASPNETIdentityConfig.RequireLowercase,
                RequireUppercase = ASPNETIdentityConfig.RequireUppercase
            };

            #endregion

            #region ユーザ ロックアウト

            // Configure user lockout defaults
            // ユーザ ロックアウトの既定値を設定

            // 初期設定
            // 5 回入力ミスすると、5分ロックアウトされる。
            //manager.UserLockoutEnabledByDefault = true;
            //manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            //manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            manager.UserLockoutEnabledByDefault = ASPNETIdentityConfig.UserLockoutEnabledByDefault;
            manager.DefaultAccountLockoutTimeSpan = ASPNETIdentityConfig.DefaultAccountLockoutTimeSpanFromSeconds;
            manager.MaxFailedAccessAttemptsBeforeLockout = ASPNETIdentityConfig.MaxFailedAccessAttemptsBeforeLockout;

            #endregion

            #region  2FAプロバイダ

            // Register two factor authentication providers.
            // This application uses Phone and Emails as a step of receiving a code for verifying the user

            // 2FAプロバイダを登録する。
            // このアプリケーションは、ユーザ検証のためのコードを受信するステップとして、電話や電子メールを使用する。

            // You can write your own provider and plug it in here.
            // 独自のプロバイダを書いてここでプラグインできる。

            #region SmsService

            manager.RegisterTwoFactorProvider(Resources.ApplicationUserManager.PhoneCode, new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = Resources.ApplicationUserManager.PhoneCode_msg
            });

            manager.SmsService = new SmsService();

            #endregion

            #region EmailService

            manager.RegisterTwoFactorProvider(Resources.ApplicationUserManager.EmailCode, new EmailTokenProvider<ApplicationUser>
            {
                Subject = Resources.ApplicationUserManager.EmailCode_sub,
                BodyFormat = Resources.ApplicationUserManager.EmailCode_body
            });

            manager.EmailService = new EmailService();

            #endregion

            #endregion

            #region 暗号化プロバイダ

            // [めも]ASP.NET Identity 2.0.0 カスタマイズ – CAT EARS
            // http://www.cat-ears.net/?p=31697
            // - PasswordHasherの入れ替え
            manager.PasswordHasher = new CustomPasswordHasher();

            // DataProtectionProvider取得または設定します。
            // 静的データやデータ ストリームを非同期的に暗号化および復号化できる暗号化プロバイダー
            IDataProtectionProvider dataProtectionProvider = options.DataProtectionProvider;

            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }

            #endregion

            return manager;
        }
    }
}