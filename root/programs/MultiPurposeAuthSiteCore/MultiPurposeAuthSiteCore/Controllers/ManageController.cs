//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/11/12  西野 大介         SameSiteCookie対応 (.NET Fx側は対策不要)
//*  2026/09/30  玄人 幸道         auth_time / セッション Cookie の名前を設定から取るようにした（#255）
//*  2026/10/01  玄人 幸道         メアドの追加・削除を引退させ、利用者名の変更と分けた（#151 の段階 3）
//*  2026/10/04  玄人 幸道         折り返し先の既定をtest_self_code_manageに（C-10）
//*  2026/10/04  玄人 幸道         登録の保存でCORSのキャッシュを捨てる（#266）
//*  2026/10/06  玄人 幸道         クライアント登録を専用列に保存する（#270）
//*  2026/10/06  玄人 幸道         CORSの許可オリジンのキャッシュをやめた（#271）
//*  2026/10/06  玄人 幸道         同意の一覧と取り消しを追加（#272 の段階 2）
//*  2026/10/07  玄人 幸道         WebAuthnの登録・削除をFido2 4.2.0で復活、MsPassを削除（#137）
//*  2026/10/09  玄人 幸道         WebAuthn の削除を複数選択に対応（#277 の段階 6）
//*  2026/10/09  西野 大介         オンライン決済サービス、トークン取得処理の削除
//*  2026/10/14  玄人 幸道         GDPR削除を物理削除に（DBストアなら CASCADE で関連明細も消える。
//*  2026/10/18  玄人 幸道         画面の保存で registration_access_token を消さない（#307 の段階 2）
//*  2026/10/25  玄人 幸道         WebAuthn の登録の失敗を OPERATION に記録する（障害対応のため。#294）
//*  2026/10/26  玄人 幸道         クライアント登録の保存で、画面に欄の無い EC の公開鍵を持ち越すようにした（#294）
//*  2026/10/26  玄人 幸道         クライアント登録の削除で、全利用者の同意も消すようにした（#294）
//*  2026/10/28  玄人 幸道         auth_time の Cookie を、改ざんできない形で書く（#294）
//*  2026/10/29  玄人 幸道         partial に分割（Account / TwoFactor / ExternalLogin / Data / OAuth2Data / Helper。#294）
//*  2026/10/29  玄人 幸道         ManageController.*.cs のレビュー指摘を反映（各ファイルの履歴を参照。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Notifications;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>ManageController</summary>
    [Authorize]
    public partial class ManageController : MyBaseMVControllerCore
    {
        #region Enum

        /// <summary>列挙型</summary>
        public enum EnumManageMessageId
        {
            /// <summary>ChangeUserNameSuccess</summary>
            ChangeUserNameSuccess,
            /// <summary>ChangeUserNameFailure</summary>
            ChangeUserNameFailure,
            /// <summary>ChangeEmailSuccess</summary>
            ChangeEmailSuccess,
            /// <summary>ChangeEmailFailure</summary>
            ChangeEmailFailure,
            /// <summary>SetPasswordSuccess</summary>
            SetPasswordSuccess,
            /// <summary>ChangePasswordSuccess</summary>
            ChangePasswordSuccess,
            /// <summary>RemoveExternalLoginSuccess</summary>
            RemoveExternalLoginSuccess,
            /// <summary>RevokeConsentSuccess（#272 の段階 2）</summary>
            RevokeConsentSuccess,
            /// <summary>AccountConflictInSocialLogin</summary>
            AccountConflictInSocialLogin,
            /// <summary>SetTwoFactorSuccess</summary>
            SetTwoFactorSuccess,
            /// <summary>AddPhoneSuccess</summary>
            AddPhoneSuccess,
            /// <summary>RemovePhoneSuccess</summary>
            RemovePhoneSuccess,
            /// <summary>AddUnstructuredDataSuccess</summary>
            AddUnstructuredDataSuccess,
            /// <summary>RemoveUnstructuredDataSuccess</summary>
            RemoveUnstructuredDataSuccess,
            /// <summary>AddSaml2OAuth2DataSuccess</summary>
            AddSaml2OAuth2DataSuccess,
            /// <summary>RemoveSaml2OAuth2DataSuccess</summary>
            RemoveSaml2OAuth2DataSuccess,
            /// <summary>AddWebAuthnDataSuccess</summary>
            AddWebAuthnDataSuccess,
            /// <summary>RemoveWebAuthnDataSuccess</summary>
            RemoveWebAuthnDataSuccess,
            /// <summary>Error</summary>
            Error
        }

        #endregion

        #region members & constructor

        #region members

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

        /// <summary>コードを確かめる前の、認証アプリの鍵（TempData。#294）</summary>
        private const string PendingAuthenticatorKey = nameof(PendingAuthenticatorKey);

        /// <summary>StatusMessage</summary>
        [TempData]
        public string StatusMessage { get; set; }

        #region OwinContext
        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;
        /// <summary>SignInManager</summary>
        private readonly SignInManager<ApplicationUser> _signInManager = null;
        #endregion

        #region IXXXSender
        /// <summary>IEmailSender</summary>
        private readonly IEmailSender _emailSender = null;
        /// <summary>ISmsSender</summary>
        private readonly ISmsSender _smsSender = null;
        #endregion

        /// <summary>UrlEncoder</summary>
        private readonly UrlEncoder _urlEncoder = null;

        //  <summary>CookieOptions</summary>
        private readonly CookieOptions _cookieOptions = null;

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="smsSender">ISmsSender</param>
        /// <param name="urlEncoder">UrlEncoder</param>
        public ManageController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            UrlEncoder urlEncoder)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
            // SignInManager
            this._signInManager = signInManager;

            // IEmailSender
            this._emailSender = emailSender;
            // ISmsSender
            this._smsSender = smsSender;
            
            // UrlEncoder
            this._urlEncoder = urlEncoder;

            // CookieOptions
            CookieOptions co = new CookieOptions();
            co.HttpOnly = true;
            co.Secure = true;
            co.SameSite = SameSiteMode.None;
            this._cookieOptions = co;
        }
        #endregion

        #endregion

        #region property

        /// <summary>SessionCookieName</summary>
        /// <remarks>
        /// **接頭辞を掛ける**（#255）。**`Startup` が同じ規則で名前を付けている**ので、
        /// ここで掛けないと、**セッションを捨てるときに別の名前を消しに行く。**
        ///
        /// **net48 版は掛けない。** あちらのセッション Cookie は ASP.NET のもので
        /// （`system.web/sessionState` の `cookieName`）、**接頭辞の対象外**である。
        /// </remarks>
        private string SessionCookieName
        {
            get
            {
                return Config.PrefixedCookieName(
                    GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName"));
            }
        }

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private SignInManager<ApplicationUser> SignInManager
        {
            get
            {
                return this._signInManager;
            }
        }

        #endregion

        #region Else

        /// <summary>IEmailSender</summary>
        private IEmailSender EmailSender
        {
            get
            {
                return this._emailSender;
            }
        }

        /// <summary>ISmsSender</summary>
        private ISmsSender SmsSender
        {
            get
            {
                return this._smsSender;
            }
        }

        /// <summary>UrlEncoder</summary>
        private UrlEncoder UrlEncoder
        {
            get
            {
                return this._urlEncoder;
            }
        }

        #endregion

        #endregion

        #region Action Method

        #region 管理画面（初期表示）

        /// <summary>
        /// 管理画面（初期表示）
        /// GET: /Manage/Index
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Index(EnumManageMessageId? message)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
                message == EnumManageMessageId.SetPasswordSuccess ? Resources.ManageController.SetPasswordSuccess
                : message == EnumManageMessageId.ChangeUserNameSuccess ? Resources.ManageController.ChangeUserNameSuccess
                : message == EnumManageMessageId.ChangeUserNameFailure ? Resources.ManageController.ChangeUserNameFailure
                : message == EnumManageMessageId.ChangeEmailSuccess ? Resources.ManageController.ChangeEmailSuccess
                : message == EnumManageMessageId.ChangeEmailFailure ? Resources.ManageController.ChangeEmailFailure
                : message == EnumManageMessageId.ChangePasswordSuccess ? Resources.ManageController.ChangePasswordSuccess
                : message == EnumManageMessageId.RemoveExternalLoginSuccess ? Resources.ManageController.RemoveExternalLoginSuccess
                : message == EnumManageMessageId.RevokeConsentSuccess ? Resources.ManageController.RevokeConsentSuccess
                : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                : message == EnumManageMessageId.SetTwoFactorSuccess ? Resources.ManageController.SetTwoFactorSuccess
                : message == EnumManageMessageId.AddPhoneSuccess ? Resources.ManageController.AddPhoneSuccess
                : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                : message == EnumManageMessageId.AddUnstructuredDataSuccess ? Resources.ManageController.AddUnstructuredDataSuccess
                : message == EnumManageMessageId.RemoveUnstructuredDataSuccess ? Resources.ManageController.RemoveUnstructuredDataSuccess
                : message == EnumManageMessageId.AddSaml2OAuth2DataSuccess ? Resources.ManageController.AddSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.RemoveSaml2OAuth2DataSuccess ? Resources.ManageController.RemoveSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.AddWebAuthnDataSuccess ? Resources.ManageController.AddWebAuthnDataSuccess
                : message == EnumManageMessageId.RemoveWebAuthnDataSuccess ? Resources.ManageController.RemoveWebAuthnDataSuccess
                : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                : "";

                // ユーザの取得
                ApplicationUser user = await UserManager.GetUserAsync(User);

                if (user != null) // デバッガの仕様の変更による
                {
                    // モデルの生成
                    //  **所有者の登録の件数**（#307 の段階 5-a-2）。
                    //    **1 利用者 n クライアント**になったので、**件数を数える** —
                    //    **「在る / 無い」だけでは、何件在るのかが分からない。**
                    //    **中身は一覧の画面（`Saml2OAuth2DataList`）で見せる。**
                    int saml2OAuth2DataCount = Sts.Saml2OAuth2DataProvider.GetByOwner(user.Id).Count;
                    bool hasSaml2OAuth2Data = (0 < saml2OAuth2DataCount);

                    string totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
                    ManageIndexViewModel model = new ManageIndexViewModel
                    {
                        // パスワード
                        HasPassword = await UserManager.HasPasswordAsync(user),
                        // ログイン
                        Logins = user.Logins,
                        // E-mail
                        Email = user.Email,
                        // 電話番号
                        PhoneNumber = user.PhoneNumber,
                        // 2FA
                        // Email, SMS
                        TwoFactor = user.TwoFactorEnabled,
                        // TOTP
                        TwoFactorTOTP = !string.IsNullOrEmpty(totpAuthenticatorKey),
                        // 非構造化データ
                        HasUnstructuredData = !string.IsNullOrEmpty(user.UnstructuredData),
                        // Saml2OAuth2Data
                        HasSaml2OAuth2Data = hasSaml2OAuth2Data,
                        Saml2OAuth2DataCount = saml2OAuth2DataCount,
                        // WebAuthn（#137）
                        HasFIDO2Data = (Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                            && (0 < FIDO.DataProvider.GetCredentialsByUser(user.UserName).Count)
                    };

                    // 管理画面の表示
                    return View(model);
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #endregion
    }
}
