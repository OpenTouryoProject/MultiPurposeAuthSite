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
//**********************************************************************************

using System;
using System.Web;
using System.Collections.Generic;

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;

/// <summary>MultiPurposeAuthSite.Models</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Entity
{
    /// <summary>
    /// You can add profile data for the user by adding more properties to your ApplicationUser class,
    /// please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    /// ApplicationUser クラスにプロパティを追加することでユーザーのプロファイル データを追加できます。
    /// 詳細については、http://go.microsoft.com/fwlink/?LinkID=317594 を参照してください。
    /// #・・・上記は Entity Framework の Code First Migrationsを使用する方法なので・・・。
    /// </summary>
    public class ApplicationUser : IUser<string> // IdentityUser (Entity Frameworkの場合)
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

        /// <summary>サインアップのためのApplicationUserを生成します</summary>
        /// <param name="userName">string</param>
        /// <param name="emailConfirmed">bool</param>
        /// <returns>ApplicationUser</returns>
        public static async Task<ApplicationUser> CreateBySignup(string userName, bool emailConfirmed)
        {
            // ApplicationUserのCreate
            ApplicationUser user = new ApplicationUser
            {
                AccessFailedCount = 0,                                              // サインアップ時は、0。
                //Claims                                                            // サインアップ時は設定しない。
                //Id                                                                // コンストラクタで自動生成
                LockoutEnabled = ASPNETIdentityConfig.UserLockoutEnabledByDefault,  // ASPNETIdentityConfig
                LockoutEndDateUtc = null,                                           // DateTimeOffset.MinValue.DateTime,
                //Logins                                                            // サインアップ時は設定しない。
                //PasswordHash                                                      // PasswordHashは直接設定しない。
                                                                                    // CreateAsyncでPasswordを設定。
                PhoneNumber = "",                                                   // サインアップ時は、空文字列。
                PhoneNumberConfirmed = false,                                       // サインアップ時は、false
                //Roles                                                             // 後でAddToRoleAsyncで登録する。
                SecurityStamp = "",                                                 // サインアップ時は、空文字列
                TwoFactorEnabled = ASPNETIdentityConfig.TwoFactorEnabled,           // ASPNETIdentityConfig
                UserName = userName                                                 // 入力値（パラメタ）
            };

            // E-mail
            if (ASPNETIdentityConfig.RequireUniqueEmail)
            {
                user.Email = userName;                                              // 入力値（パラメタ）
                user.EmailConfirmed = emailConfirmed;                               // 設定値（パラメタ）
            }
            else
            {
                user.Email = "";                                                    // 固定値
                user.EmailConfirmed = !ASPNETIdentityConfig.DisplayAgreementScreen; // 固定値
            }

            // ParentId（実質的に分割キー）
            if (ASPNETIdentityConfig.MultiTenant)
            {
                // マルチテナントの場合、サインアップするユーザが「テナントの管理者ユーザ」になる。
                user.ParentId = user.Id;
            }
            else
            {
                // マルチテナントでない場合、「既定の管理者ユーザ」を使用する。

                if (userName == ASPNETIdentityConfig.AdministratorUID)
                {
                    // 自分が「既定の管理者ユーザ」の場合、
                    user.ParentId = user.Id;
                }
                else
                {
                    // 自分が既定の管理者ユーザでない場合、
                    ApplicationUserManager userManager
                        = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

                    ApplicationUser parentUser = await userManager.FindByNameAsync(ASPNETIdentityConfig.AdministratorUID);

                    // 「既定の管理者ユーザ」が管理者ユーザになる。
                    user.ParentId = parentUser.Id;
                }
            }
            
            return user;
        }

        /// <summary>管理者登録のためのApplicationUserを生成します</summary>
        /// <param name="parentId">string</param>
        /// <param name="userName">string</param>
        /// <returns>ApplicationUser</returns>
        public static async Task<ApplicationUser> CreateByRegister(string parentId, string userName)
        {
            // ApplicationUserのCreate
            ApplicationUser user = new ApplicationUser
            {   
                AccessFailedCount = 0,                                              // 管理者登録時は、0。
                //Claims                                                            // 管理者登録時は設定しない。
                //Id                                                                // コンストラクタで自動生成
                LockoutEnabled = ASPNETIdentityConfig.UserLockoutEnabledByDefault,  // ASPNETIdentityConfig
                LockoutEndDateUtc = null,                                           // DateTimeOffset.MinValue.DateTime,
                //Logins                                                            // 管理者登録時は設定しない。
                //PasswordHash                                                      // PasswordHashは直接設定しない。
                                                                                    // CreateAsyncでPasswordを設定。
                PhoneNumber = "",                                                   // 管理者登録時は、空文字列。
                PhoneNumberConfirmed = false,                                       // 管理者登録時は、false
                //Roles                                                             // 後でAddToRoleAsyncで登録する。
                SecurityStamp = "",                                                 // 管理者登録時は、空文字列
                TwoFactorEnabled = ASPNETIdentityConfig.TwoFactorEnabled,           // ASPNETIdentityConfig
                UserName = userName                                                 // 入力値（パラメタ）
            };

            // E-mail
            if (ASPNETIdentityConfig.RequireUniqueEmail)
            {
                user.Email = userName;                                              // 入力値（パラメタ）
                user.EmailConfirmed = true;                                         // 固定値
            }
            else
            {
                user.Email = "";                                                    // 固定値
                user.EmailConfirmed = true;                                         // 固定値
            }

            // ParentId（実質的に分割キー）
            if (ASPNETIdentityConfig.MultiTenant)
            {
                // マルチテナントの場合、「一般ユーザ」は「テナントの管理者ユーザ」が管理者ユーザになる。
                user.ParentId = parentId;
            }
            else
            {
                // マルチテナントでない場合、「一般ユーザ」は「既定の管理者ユーザ」が管理者ユーザになる。

                // AdministratorのApplicationUser を取得する。
                ApplicationUserManager userManager
                    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

                ApplicationUser parentUser = await userManager.FindByNameAsync(ASPNETIdentityConfig.AdministratorUID);
                
                user.ParentId = parentUser.Id;
            }

            return user;
        }

        #endregion

        #endregion

        #region properties

        #region Original properties

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
        /// Gets or sets the salted / hashed form of the user password.
        /// </summary>
        public string PasswordHash { get; set; }

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

        #region Collection (private set)

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

        #region Additional properties

        /// <summary>
        /// ParentId
        /// </summary>
        /// <remarks>
        /// このフィールドはマルチテナント処理のために使用されます。
        /// </remarks>
        public string ParentId { get; set; } = null;

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
        /// レコード生成日
        /// </summary>
        public DateTime CreatedDate { get; set; } = DateTime.Now ;

        #endregion

        #endregion

        #region ClaimsIdentity生成メソッド

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

        #endregion
    }
}