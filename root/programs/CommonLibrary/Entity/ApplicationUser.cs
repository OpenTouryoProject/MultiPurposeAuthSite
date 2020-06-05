//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ApplicationUser
//* クラス日本語名  ：IUser<string>を拡張したApplicationUser（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  201X/XX/XX  西野 大介         TotpAuthenticatorKey追加(Core)
//*  201X/XX/XX  西野 大介         FIDO2PublicKey追加(WebAuthn)
//*  2020/02/27  西野 大介         DeviceToken追加(プッシュ通知)
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Newtonsoft.Json;

#if NETFX
/// <summary>MultiPurposeAuthSite.Entity</summary>
namespace MultiPurposeAuthSite.Entity
#else
/// <summary>MultiPurposeAuthSite</summary>
namespace MultiPurposeAuthSite // ルートでないとダメ？
#endif
{
    /// <summary>
    /// You can add profile data for the user by adding more properties to your ApplicationUser class,
    /// please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    /// ApplicationUser クラスにプロパティを追加することでユーザーのプロファイル データを追加できます。
    /// 詳細については、http://go.microsoft.com/fwlink/?LinkID=317594 を参照してください。
    /// #・・・上記は Entity Framework の Code First Migrationsを使用する方法なので・・・。
    /// </summary>
#if NETFX
    public class ApplicationUser : IUser<string> // IdentityUser (Entity Frameworkの場合)
#else
    public class ApplicationUser
#endif
    {
        // ASP.NET Identity – User Lockout « Trailmax Tech
        // http://tech.trailmax.info/2014/06/asp-net-identity-user-lockout/
        //   And fields on IdentityUser
        //     don’t use them to detect is user is locked out, they are lies! Use UserManager functions to detect user state.
        //     Hope this will save some people a head-banging, cause that caused me some stress!

        #region IdentityUser(EF前提クラス)から、IUser<string>に変更

        // https://techinfoofmicrosofttech.osscons.jp/index.php?ASP.NET%20Identity#w4a7fdb2

        // IdentityUser(EF前提クラス)の型情報を確認して自分で定義＆処理。
        // 別途、App_Data中のテーブルのフィールドを確認する。

        // IdentityUser(TKey, TLogin, TRole, TClaim) Class
        // (Microsoft.AspNet.Identity.EntityFramework)
        // https://msdn.microsoft.com/en-us/library/dn613256.aspx

        // ASP.NET Identity uses Entity Framework Code First and it is possible to extend the POCO classes.
        // Entity Frameworkのコードファーストを使用し、POCOクラスを拡張することが可能です。

        // If informations have needs to be stored in a different storage mechanism, it is now possible to plug in different storage providers.
        // 異なる記憶機構に格納される可能性があるということであるならば、別のストレージ・プロバイダーにプラグインすることが可能。

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public ApplicationUser()
        {
            // 引数なしのpublic default constructor以外 NGっぽい。
            this.Logins = new List<UserLoginInfo>();
            this.Roles = new List<ApplicationRole>();
            this.Claims = new List<Claim>();
        }

        #region CreateBy

        /// <summary>ApplicationUser生成</summary>
        /// <param name="userName">string</param>
        /// <param name="emailConfirmed">bool</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser CreateUser(string userName, bool emailConfirmed)
        {
            // ApplicationUserのCreate
            ApplicationUser user = new ApplicationUser
            {
                AccessFailedCount = 0,                                              // サインアップ時は、0。
                //Claims                                                            // サインアップ時は設定しない。
                //Id                                                                // コンストラクタで自動生成
                LockoutEnabled = Config.UserLockoutEnabledByDefault,                // Config
                LockoutEndDateUtc = null,                                           // DateTimeOffset.MinValue.DateTime,
                                                                                    //Logins                                                            // サインアップ時は設定しない。
                                                                                    //PasswordHash                                                      // PasswordHashは直接設定しない。
                                                                                    // CreateAsyncでPasswordを設定。
                PhoneNumber = "",                                                   // サインアップ時は、空文字列。
                PhoneNumberConfirmed = false,                                       // サインアップ時は、false
                //Roles                                                             // 後でAddToRoleAsyncで登録する。
                SecurityStamp = "",                                                 // サインアップ時は、空文字列
                TwoFactorEnabled = Config.TwoFactorEnabled,                           // Config
                UserName = userName                                                 // 入力値（パラメタ）
            };

            // E-mail
            if (Config.RequireUniqueEmail)
            {
                user.Email = userName;                                              // 入力値（パラメタ）
                user.EmailConfirmed = emailConfirmed;                               // 設定値（パラメタ）
            }
            else
            {
                user.Email = "";                                                    // 固定値
                user.EmailConfirmed = !Config.DisplayAgreementScreen;               // 固定値
            }

            return user;
        }

        #endregion

        #endregion

        #region properties

        #region Properties from Identity2 or earlier.

        #region UserInfo

        #region Account

        /// <summary>
        /// Gets or sets the user identifier.
        /// </summary>
        /// <remarks>
        /// GUIDを使用
        /// </remarks>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the user name ( = Email) .
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// NormalizedUserName
        /// UserNameを大文字化した値が自動的にセットされる。
        /// これをUserStoreに登録しておけば、検索し易くなる。
        /// </summary>
        /// <remarks>
        /// 本プロパティは、検索条件用に、UserNameプロパティを大文字化したプロパティですが、
        /// 本システムではUserNameプロパティを軸にするため、.NET Framework 上で実行する場合は指定された値を無視します。
        /// </remarks> 
        public string NormalizedUserName
        {
#if NETFX
            set
            {
                // 捨て
            }
            get
            {
                return this.UserName.ToUpper();
            }
#else
            set; get;
#endif
        }

        /// <summary>salted / hashed form of the user password</summary>
        private string _passwordHash = "";

        /// <summary>
        /// Gets or sets the salted / hashed form of the user password.
        /// </summary>
        [JsonIgnore]
        public string PasswordHash
        {
            get
            {
                return this._passwordHash;
            }
            set
            {
                // Support "90-day update policy" of PCI DSS 
                if (string.IsNullOrEmpty(this._passwordHash))
                {
                    // 新規や、DBからロード
                }
                else
                {
                    // 更新時
                    this.PasswordChangeDate = DateTime.Now;
                }

                this._passwordHash = value;
            }
        }

        #endregion

        #region Email

        /// <summary>
        /// Gets or sets the email for the user.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets a value that indicates whether the email is confirmed.
        /// </summary>
        public bool EmailConfirmed { get; set; }

        /// <summary>
        /// NormalizedEmail
        /// Emailを大文字化した値が自動的にセットされる。
        /// これをUserStoreに登録しておけば、検索し易くなる。
        /// </summary>
        /// <remarks>
        /// 本プロパティは、検索条件用に、Emailプロパティを大文字化したプロパティですが、
        /// 本システムではEmailプロパティを軸にするため、.NET Framework 上で実行する場合は指定された値を無視します。
        /// </remarks> 
        public string NormalizedEmail
        {
#if NETFX
            set
            {
                // 捨て
            }
            get
            {
                return this.Email.ToUpper();
            }
#else
            set; get;
#endif
        }

        #endregion

        #region PhoneNumber

        /// <summary>
        /// Gets or sets the phone number for the user.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the value that indicates whether the phone number is confirmed. The default is false.
        /// </summary>
        public bool PhoneNumberConfirmed { get; set; }

        #endregion

        #endregion

        #region LoginInfo

        #region Lockout

        /// <summary>
        /// Gets or sets a value that indicates whether lockout enabled for this user.
        /// </summary>
        public bool LockoutEnabled { get; set; }

        /// <summary>
        /// Gets or sets the number of failures for the purposes of lockout.
        /// </summary>
        public int AccessFailedCount { get; set; }

        /// <summary>
        /// Gets or sets the date time value (in UTC) when lockout ends, any time in the past is considered not locked out.
        /// </summary>
        public DateTime? LockoutEndDateUtc { get; set; }

        #endregion

        #region Security options

        /// <summary>
        /// Gets or sets a random value that changes when a user’s credentials change.
        /// ユーザーの資格情報 (パスワードの変更、ログインの削除) が変更されたときに必ず変更するランダム値.
        /// </summary>
        /// <remarks>
        /// </remarks>
        public string SecurityStamp { get; set; }

        /// <summary>
        /// Gets or sets a value that indicates whether two-factor authentication is enabled for the user.
        /// </summary>
        public bool TwoFactorEnabled { get; set; }

        #endregion

        #endregion

        #region Collection

        /// <summary>
        /// Gets the collection of roles for the user.
        /// </summary>
        public IList<ApplicationRole> Roles { get; set; }

        /// <summary>
        /// Gets the collection of logins for the user.
        /// </summary>
        public IList<UserLoginInfo> Logins { get; set; }

        /// <summary>
        /// Gets the collection of user claims.
        /// </summary>
        public IList<Claim> Claims { get; set; }

        #endregion

        #endregion

        // 要DBスキーマ拡張
        #region Properties after Identity 3.

        /// <summary>Totp AuthenticatorKey</summary>
        public string TotpAuthenticatorKey { get; set; }

        #region Collection

#if NETFX
#else
        /// <summary>Totp Tokens</summary>
        public IList<IdentityUserToken<string>> TotpTokens { get; set; }
#endif
        #endregion

        #endregion

        #region Additional properties

        /// <summary>
        /// ClientID
        /// </summary>
        /// <remarks>
        /// OAuth2関連のClientID
        /// </remarks>
        public string ClientID { get; set; } = Guid.NewGuid().ToString("N"); //Guid.NewGuid().ToString();

        /// <summary>
        /// ユーザの支払元情報
        /// </summary>
        public string PaymentInformation { get; set; } = null;

        /// <summary>
        /// 非構造化データ
        /// </summary>
        public string UnstructuredData { get; set; } = null;

        /// <summary>
        /// FIDO2PublicKey
        /// </summary>
        public string FIDO2PublicKey { get; set; } = null;

        /// <summary>
        /// DeviceToken 
        /// </summary>
        public string DeviceToken { get; set; } = null;

        /// <summary>
        /// レコード生成日
        /// </summary>
        public DateTime CreatedDate { get; set; } = DateTime.Now;

        /// <summary>
        /// パスワード更新日
        /// </summary>
        public DateTime PasswordChangeDate { get; set; } = DateTime.Now;

        #endregion

        #endregion

        #region ClaimsIdentity生成メソッド

#if NETFX
        /// <summary>GenerateUserIdentityAsync</summary>
        /// <param name="manager">UserManager</param>
        /// <returns>ClaimsIdentityを非同期に返す</returns>
        /// <remarks>
        /// 以下から利用されている。
        /// - ApplicationSignInManager.CreateUserIdentityAsync()から呼び出される。
        /// - SecurityStampValidator.OnValidateIdentityでdelegateとして設定された後、呼び出される。
        /// </remarks>
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // サインインの際（SignInManager.PasswordSignInAsync）、
            // ApplicationSignInManager.CreateUserIdentityAsync()経由で呼び出されている。

            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            // 注：authenticationTypeはCookieAuthenticationOptions.AuthenticationTypeで定義されたものと一致する必要があります。
            ClaimsIdentity userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);

            // Add custom user claims here
            // カスタム　ユーザのClaimsをここで追加する。
            return userIdentity;
        }
#endif
        #endregion
    }
}