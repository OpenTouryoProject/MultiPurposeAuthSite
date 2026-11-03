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
//*  2026/09/16  玄人 幸道         MobileApp（プッシュ通知）の2FAプロバイダを登録（#216）
//*  2026/10/01  玄人 幸道         メアドの一意を常に必須にした（#151 の段階 3）
//*  2026/11/02  玄人 幸道         更新の競合を失敗で返し、数えやスタンプの更新は読み直してやり直す（#316）
//*  2026/11/03  玄人 幸道         変更を当て直してやり直す UpdateWithRetryAsync を足した（#331）
//**********************************************************************************

using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Co;

using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using System;
using System.Linq;
using System.Threading.Tasks;

/// <summary>MultiPurposeAuthSite.Manager</summary>
namespace MultiPurposeAuthSite.Manager
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

        #region 楽観排他（#316）

        /// <summary>UpdateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IdentityResult（競合したら失敗）</returns>
        public override async Task<IdentityResult> UpdateAsync(ApplicationUser user)
        {
            try
            {
                return await base.UpdateAsync(user);
            }
            catch (CmnUserStore.ConcurrencyException)
            {
                return IdentityResult.Failed(CmnUserStore.ConcurrencyFailureMessage);
            }
        }

        /// <summary>AccessFailedAsync</summary>
        /// <param name="userId">利用者の Id</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**競合で数えが消えると、ロックアウトに届きにくくなる**（`ANALYSIS-IdP.md` の E-14）。</remarks>
        public override Task<IdentityResult> AccessFailedAsync(string userId)
        {
            return this.RetryOnConflictAsync(() => base.AccessFailedAsync(userId));
        }

        /// <summary>ResetAccessFailedCountAsync</summary>
        /// <param name="userId">利用者の Id</param>
        /// <returns>IdentityResult</returns>
        public override Task<IdentityResult> ResetAccessFailedCountAsync(string userId)
        {
            return this.RetryOnConflictAsync(() => base.ResetAccessFailedCountAsync(userId));
        }

        /// <summary>UpdateSecurityStampAsync</summary>
        /// <param name="userId">利用者の Id</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**結果を見ない呼び出しがあり、競合で更新が消えると、古いセッションが生き残る。**</remarks>
        public override Task<IdentityResult> UpdateSecurityStampAsync(string userId)
        {
            return this.RetryOnConflictAsync(() => base.UpdateSecurityStampAsync(userId));
        }

        /// <summary>SetTwoFactorEnabledAsync</summary>
        /// <param name="userId">利用者の Id</param>
        /// <param name="enabled">有効にするか</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**結果を見ない呼び出しがある。**</remarks>
        public override Task<IdentityResult> SetTwoFactorEnabledAsync(string userId, bool enabled)
        {
            return this.RetryOnConflictAsync(() => base.SetTwoFactorEnabledAsync(userId, enabled));
        }

        /// <summary>変更を当てて書き、競合したら読み直して当て直す（#331）</summary>
        /// <param name="user">ApplicationUser（1 回目は、この物に当てる）</param>
        /// <param name="change">変更（**読み直すたびに当て直す**ので、前の値から計算しない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **送り直す人がいない要求**（端末からの `/SetDeviceToken` など）のためにある。
        /// **画面からの更新には使わない**（見ていない値の上に書くことになる。競合なら、失敗を見せて送り直させる）。
        /// </remarks>
        public Task<IdentityResult> UpdateWithRetryAsync(ApplicationUser user, Action<ApplicationUser> change)
        {
            bool first = true;

            return this.RetryOnConflictAsync(async () =>
            {
                ApplicationUser target = user;

                if (!first)
                {
                    //  **2 回目からは、読み直した物に当てる。** 消えていたら、そのまま失敗させる。
                    target = await this.FindByIdAsync(user.Id) ?? user;
                }

                first = false;
                change(target);
                return await this.UpdateAsync(target);
            });
        }

        /// <summary>競合したら、やり直す（基底の操作は、Id で読み直すところから始まる）</summary>
        /// <param name="operation">操作</param>
        /// <returns>IdentityResult</returns>
        private async Task<IdentityResult> RetryOnConflictAsync(Func<Task<IdentityResult>> operation)
        {
            IdentityResult result = null;

            for (int i = 0; i < CmnUserStore.ConcurrencyRetryCount; i++)
            {
                if (0 < i)
                {
                    await Task.Delay(CmnUserStore.ConcurrencyRetryDelayMilliseconds());
                }

                result = await operation();

                if (!result.Errors.Contains(CmnUserStore.ConcurrencyFailureMessage))
                {
                    return result;
                }
            }

            return result;
        }

        #endregion

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
                AllowOnlyAlphanumericUserNames = Config.AllowOnlyAlphanumericUserNames,

                // **メアドは常に一意**（#151 の段階 3）。
                //   **利用者名とメアドの両方でサインインできる**ので、
                //   **メアドが一意でないと FindByEmailAsync が成り立たない。**
                //   以前は RequireUniqueEmail の設定で切り替えていた（その設定は落とした）。
                RequireUniqueEmail = true
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
                
                RequiredLength = Config.RequiredLength,
                RequireNonLetterOrDigit = Config.RequireNonLetterOrDigit,
                RequireDigit = Config.RequireDigit,
                RequireLowercase = Config.RequireLowercase,
                RequireUppercase = Config.RequireUppercase
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

            manager.UserLockoutEnabledByDefault = Config.UserLockoutEnabledByDefault;
            manager.DefaultAccountLockoutTimeSpan = Config.DefaultAccountLockoutTimeSpanFromSeconds;
            manager.MaxFailedAccessAttemptsBeforeLockout = Config.MaxFailedAccessAttemptsBeforeLockout;

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

            #region MobileApp（プッシュ通知の 2FA。#216）

            // **端末を登録している利用者にだけ、選択肢として出る**
            //   （MobileAppTokenProvider.IsValidProviderForUserAsync が DeviceToken を見る）。
            // コードの生成と検証は、メール / SMS と同じ仕組みに任せ、送り先だけを変える。
            manager.RegisterTwoFactorProvider(
                MobileAppTokenProvider.ProviderName, new MobileAppTokenProvider());

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
            
            // ASP.NET Identityを使ったメール認証でのtokenの有効期限の変更方法 -tonkunの備忘録
            // http://tonkun-no.hatenablog.com/entry/2016/09/15/212145
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"))
                    {
                        TokenLifespan = Config.EmailConfirmationTokenLifespanFromHours,
                    };
            }

            #endregion

            return manager;
        }
    }
}