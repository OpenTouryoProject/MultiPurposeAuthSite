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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Extensions;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using AspNetId = Microsoft.AspNetCore.Identity;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Objects;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.Diagnostics;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>ManageController</summary>
    [Authorize]
    public class ManageController : MyBaseMVControllerCore
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
            /// <summary>AccountConflictInSocialLogin</summary>
            AccountConflictInSocialLogin,
            /// <summary>SetTwoFactorSuccess</summary>
            SetTwoFactorSuccess,
            /// <summary>AddEmailSuccess</summary>
            AddEmailSuccess,
            /// <summary>AddEmailFailure</summary>
            AddEmailFailure,
            /// <summary>RemoveEmailSuccess</summary>
            RemoveEmailSuccess,
            /// <summary>AddPhoneSuccess</summary>
            AddPhoneSuccess,
            /// <summary>RemovePhoneSuccess</summary>
            RemovePhoneSuccess,
            /// <summary>AddPaymentInformationSuccess</summary>
            AddPaymentInformationSuccess,
            /// <summary>RemovePaymentInformationSuccess</summary>
            RemovePaymentInformationSuccess,
            /// <summary>AddUnstructuredDataSuccess</summary>
            AddUnstructuredDataSuccess,
            /// <summary>RemoveUnstructuredDataSuccess</summary>
            RemoveUnstructuredDataSuccess,
            /// <summary>AddSaml2OAuth2DataSuccess</summary>
            AddSaml2OAuth2DataSuccess,
            /// <summary>RemoveSaml2OAuth2DataSuccess</summary>
            RemoveSaml2OAuth2DataSuccess,
            /// <summary>AddMsPassDataSuccess</summary>
            AddMsPassDataSuccess,
            /// <summary>RemoveMsPassDataSuccess</summary>
            RemoveMsPassDataSuccess,
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
        private string SessionCookieName
        {
            get
            {
                return GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName");
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
                : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                : message == EnumManageMessageId.SetTwoFactorSuccess ? Resources.ManageController.SetTwoFactorSuccess
                : message == EnumManageMessageId.AddEmailSuccess ? Resources.ManageController.AddEmailSuccess
                : message == EnumManageMessageId.AddEmailFailure ? Resources.ManageController.AddEmailFailure
                : message == EnumManageMessageId.RemoveEmailSuccess ? Resources.ManageController.RemoveEmailSuccess
                : message == EnumManageMessageId.AddPhoneSuccess ? Resources.ManageController.AddPhoneSuccess
                : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                : message == EnumManageMessageId.AddPaymentInformationSuccess ? Resources.ManageController.AddPaymentInformationSuccess
                : message == EnumManageMessageId.RemovePaymentInformationSuccess ? Resources.ManageController.RemovePaymentInformationSuccess
                : message == EnumManageMessageId.AddUnstructuredDataSuccess ? Resources.ManageController.AddUnstructuredDataSuccess
                : message == EnumManageMessageId.RemoveUnstructuredDataSuccess ? Resources.ManageController.RemoveUnstructuredDataSuccess
                : message == EnumManageMessageId.AddSaml2OAuth2DataSuccess ? Resources.ManageController.AddSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.RemoveSaml2OAuth2DataSuccess ? Resources.ManageController.RemoveSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.AddMsPassDataSuccess ? Resources.ManageController.AddMsPassDataSuccess
                : message == EnumManageMessageId.RemoveMsPassDataSuccess ? Resources.ManageController.RemoveMsPassDataSuccess
                : message == EnumManageMessageId.AddWebAuthnDataSuccess ? Resources.ManageController.AddWebAuthnDataSuccess
                : message == EnumManageMessageId.RemoveWebAuthnDataSuccess ? Resources.ManageController.RemoveWebAuthnDataSuccess
                : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                : "";

                // ユーザの取得
                ApplicationUser user = await UserManager.GetUserAsync(User);

                if (user != null) // デバッガの仕様の変更による
                {
                    // モデルの生成
                    string saml2OAuth2Data = Sts.DataProvider.Get(user.ClientID);

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
                        // 支払元情報
                        HasPaymentInformation = !string.IsNullOrEmpty(user.PaymentInformation),
                        // 非構造化データ
                        HasUnstructuredData = !string.IsNullOrEmpty(user.UnstructuredData),
                        // Saml2OAuth2Data
                        HasSaml2OAuth2Data = !string.IsNullOrEmpty(saml2OAuth2Data),
                        // FIDO2PublicKey
                        HasFIDO2Data = new Func<bool>(() =>
                        {
                            if (Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
                            {
                                return !string.IsNullOrEmpty(user.FIDO2PublicKey);
                            }
                            else if (Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                            {
                                return (0 < FIDO.DataProvider.GetCredentialsByUser(user.UserName).Count);
                            }
                            else return false;
                        })(),
                        // Scopes
                        Scopes = Const.StandardScopes
                    };

                    // 管理画面の表示
                    return View(model);
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #region UserName

        /// <summary>
        /// UserNameの編集画面
        /// GET: /Manage/ChangeUserName
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ChangeUserName()
        {
            if (!Config.RequireUniqueEmail
                && Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの取得
                ApplicationUser user = await UserManager.GetUserAsync(User);
                return View(new ManageChangeUserNameViewModel { UserNameForEdit = user.UserName });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// UserNameの編集画面
        /// POST: /Manage/ChangeUserName
        /// </summary>
        /// <param name="model">ManageChangeUserNameViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangeUserName(ManageChangeUserNameViewModel model)
        {
            ApplicationUser user = null;
            Microsoft.AspNetCore.Identity.SignInResult signInResult = null;

            if (!Config.RequireUniqueEmail
                && Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageChangeUserNameViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageChangeUserNameViewModelの検証に成功

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        user = await UserManager.GetUserAsync(User);
                        signInResult = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                          // アカウント(UID)
                            password: model.Password,                                         // アカウント(PWD)
                            isPersistent: false,                                              // アカウント記憶
                            lockoutOnFailure: Config.UserLockoutEnabledByDefault);            // ロックアウト

                        if (signInResult.Succeeded)
                        {
                            // Passwordが一致した。
                            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                            responseCookies.Set(OAuth2AndOIDCConst.auth_time,
                                FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
                            // 処理を継続
                        }
                        else
                        {
                            // Passwordが一致しない。
                            // 再表示
                            return View(model);
                        }
                    }
                    else
                    {
                        // ノーチェック
                        // 処理を継続
                    }

                    // ユーザの取得
                    user = await UserManager.GetUserAsync(User);
                    string oldUserName = user.UserName;

                    // UserNameの更新
                    user.UserName = model.UserNameForEdit;
                    IdentityResult result = await UserManager.UpdateAsync(user);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 再ログイン
                        if (await this.ReSignInAsync(user.Id))
                        {
                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) has changed own user name to {2}.", user.Id, oldUserName, user.UserName));

                            // 再ログインに成功
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeUserNameSuccess });
                        }
                        else
                        {
                            // 再ログインに失敗
                        }
                    }
                    else
                    {
                        // E-mail更新に失敗
                    }

                    return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeUserNameFailure });
                }
                else
                {
                    // ManageChangeUserNameViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Password

        #region Create

        /// <summary>
        /// パスワード設定画面（初期表示）
        /// GET: /Manage/SetPassword
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult SetPassword()
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// パスワード設定画面（パスワード設定）
        /// POST: /Manage/SetPassword
        /// </summary>
        /// <param name="model">ManageSetPasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(ManageSetPasswordViewModel model)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // ManageSetPasswordViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageSetPasswordViewModelの検証に成功
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    // パスワード設定
                    IdentityResult result = await UserManager.AddPasswordAsync(user, model.NewPassword);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync(user.Id);

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has set own local password.", user.Id, user.UserName));

                        // Index - SetPasswordSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.SetPasswordSuccess });
                    }
                    else
                    {
                        // 失敗
                        this.AddErrors(result);
                    }
                }
                else
                {
                    // ManageSetPasswordViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Update

        /// <summary>
        /// パスワード変更画面（初期表示）
        /// GET: /Manage/ChangePassword
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult ChangePassword()
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// パスワード変更画面（パスワード変更）
        /// POST: /Manage/ChangePassword
        /// </summary>
        /// <param name="model">ManageChangePasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ManageChangePasswordViewModel model)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // ManageChangePasswordViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageChangePasswordViewModelの検証に成功
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    // パスワード変更
                    IdentityResult result = await UserManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

                    // パスワードの変更結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync(user.Id);

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has changed own password.", user.Id, user.UserName));

                        // Index - ChangePasswordSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        // 失敗
                        this.AddErrors(result);
                    }
                }
                else
                {
                    // ManageChangePasswordViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region E-mail

        #region Create

        /// <summary>
        /// E-mailの追加画面（初期表示）
        /// GET: /Manage/AddEmail
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AddEmail()
        {
            if (!Config.RequireUniqueEmail
                && Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// E-mailの追加画面（E-mailの追加）
        /// POST: /Manage/AddEmail
        /// </summary>
        /// <param name="model">ManageEmailViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddEmail(ManageEmailViewModel model)
        {
            if (!Config.RequireUniqueEmail
                && Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageEmailViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageEmailViewModelの検証に成功
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        AspNetId.SignInResult result = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                  // アカウント(UID)
                            password: model.Password,                                 // アカウント(PWD)
                            isPersistent: false,                                      // アカウント記憶
                            lockoutOnFailure: Config.UserLockoutEnabledByDefault);    // ロックアウト

                        if (result.Succeeded)
                        {
                            // Passwordが一致した。
                            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                            responseCookies.Set(OAuth2AndOIDCConst.auth_time,
                                FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
                            // 処理を継続
                        }
                        else
                        {
                            // Passwordが一致しない。
                            // 再表示
                            return View(model);
                        }
                    }
                    else
                    {
                        // ノーチェック
                        // 処理を継続
                    }

                    // DB ストアに保存
                    CustomizedConfirmationJson customizedConfirmationJson = new CustomizedConfirmationJson
                    {
                        Code = GetPassword.Base64UrlSecret(128),
                        Email = model.Email // 更新後のメアド
                    };
                    CustomizedConfirmationProvider.GetInstance()
                        .CreateCustomizedConfirmationData(user.Id, customizedConfirmationJson);

                    // 確認メールの送信
                    this.SendConfirmEmail(user.Id, customizedConfirmationJson.Email, customizedConfirmationJson.Code);

                    // 再表示
                    return View("VerifyEmailAddress");
                }
                else
                {
                    // ManageEmailViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Update (Edit/Change)

        /// <summary>
        /// E-mailの編集画面（初期表示）
        /// GET: /Manage/ChangeEmail
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ChangeEmail()
        {
            if (Config.RequireUniqueEmail
                && Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの取得
                ApplicationUser user = await UserManager.GetUserAsync(User);
                return View(new ManageEmailViewModel { Email = user.Email });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// E-mailの編集画面（E-mailの編集）
        /// POST: /Manage/ChangeEmail
        /// </summary>
        /// <param name="model">ManageEmailViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangeEmail(ManageEmailViewModel model)
        {
            if (Config.RequireUniqueEmail
                && Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageEmailViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageEmailViewModelの検証に成功
                    
                    // 先ず、ユーザを取得しておく。
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        AspNetId.SignInResult result = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                // アカウント(UID)
                            password: model.Password,                               // アカウント(PWD)
                            isPersistent: false,                                    // アカウント記憶
                            lockoutOnFailure: Config.UserLockoutEnabledByDefault);  // ロックアウト

                        if (result.Succeeded)
                        {
                            // Passwordが一致した。
                            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                            responseCookies.Set(OAuth2AndOIDCConst.auth_time,
                                FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
                            // 処理を継続
                        }
                        else
                        {
                            // Passwordが一致しない。
                            // 再表示
                            return View(model);
                        }
                    }
                    else
                    {
                        // ノーチェック
                        // 処理を継続
                    }

                    if (user.UserName != model.Email)
                    {
                        // メアドが更新された場合。

                        // 既存のメアドかどうかのチェック
                        ApplicationUser anotherUser = await UserManager.FindByEmailAsync(model.Email);

                        if (anotherUser == null)
                        {
                            // 既存のメアドでない場合。

                            // DB ストアに保存
                            CustomizedConfirmationJson customizedConfirmationJson = new CustomizedConfirmationJson
                            {
                                Code = GetPassword.Base64UrlSecret(128),
                                Email = model.Email // 更新後のメアド
                            };
                            CustomizedConfirmationProvider.GetInstance()
                                .CreateCustomizedConfirmationData(user.Id, customizedConfirmationJson);

                            // 確認メールの送信
                            this.SendConfirmEmail(user.Id, customizedConfirmationJson.Email, customizedConfirmationJson.Code);

                            // 表示
                            return View("VerifyEmailAddress");
                        }
                        else
                        {
                            // 既存のメアドの場合。
                        }
                    }
                    else
                    {
                        // メアドが更新されていない場合。
                    }
                }
                else
                {
                    // ManageEmailViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region メアド検証

        /// <summary>
        /// メアド検証画面（メールからのリンクで結果表示）
        /// GET: /Manage/EmailConfirmation
        /// </summary>
        /// <param name="userId">string</param>
        /// <param name="code">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> EmailConfirmation(string userId, string code)
        {
        	// ユーザの取得
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // 入力の検証 1
                if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
                {
                    // ・・・
                }
                else
                {
                    // 入力の検証 2
                    if (user.Id == userId)
                    {
                        string email = CustomizedConfirmationProvider.GetInstance()
                            .CheckCustomizedConfirmationData(userId, code, out bool isExpired);

                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            // 更新（UserName＝メアドの場合は、UserNameも更新）
                            string oldUserName = "";
                            if (Config.RequireUniqueEmail)
                            {
                                oldUserName = user.UserName;
                                user.UserName = email;
                            }
                            user.Email = email;

                            // 場合によっては、Email & UserName を更新するため。
                            //IdentityResult result = await UserManager.SetEmailAsync(User.Identity.GetUserId(), (string)Session["Email"]);
                            IdentityResult result = await UserManager.UpdateAsync(user);

                            // 結果の確認
                            if (result.Succeeded)
                            {
                                // メアド検証の成功

                                // 再ログイン
                                if (await this.ReSignInAsync(user.Id))
                                {
                                    // 再ログインに成功
                                    if (Config.RequireUniqueEmail)
                                    {
                                        // メールの送信
                                        this.SendChangeCompletedEmail(user);

                                        // オペレーション・トレース・ログ出力
                                        Logging.MyOperationTrace(string.Format(
                                            "{0}({1}) has changed own e-mail address to {2}.", user.Id, oldUserName, user.UserName));
                                        return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeEmailSuccess });
                                    }
                                    else
                                    {
                                        return RedirectToAction("Index", new { Message = EnumManageMessageId.AddEmailSuccess });
                                    }
                                }
                                else
                                {
                                    // 再ログインに失敗
                                }
                            }
                            else
                            {
                                // E-mail更新に失敗
                                if (Config.RequireUniqueEmail)
                                {
                                    return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeEmailFailure });
                                }
                                else
                                {
                                    return RedirectToAction("Index", new { Message = EnumManageMessageId.AddEmailFailure });
                                }
                            }
                        }
                        else
                        {
                            if (isExpired)
                            {
                                // 有効期限切れ
                            }
                            else
                            {
                                // 使用済みリンク
                            }
                        }
                    }
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #region Delete

        /// <summary>
        /// E-mailの削除
        /// POST: /Manage/RemoveEmail
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveEmail()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (!Config.RequireUniqueEmail
                && Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // null クリア
                IdentityResult result = await UserManager.SetEmailAsync(user, "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // E-mail削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveEmailSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // E-mail削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region Phone Number

        #region Createプロセス

        #region Create

        /// <summary>
        /// 電話番号の追加画面（初期表示）
        /// GET: /Manage/AddPhoneNumber
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AddPhoneNumber()
        {
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 電話番号の追加画面（電話番号の追加）
        /// POST: /Manage/AddPhoneNumber
        /// </summary>
        /// <param name="model">ManageAddPhoneNumberViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(ManageAddPhoneNumberViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPhoneNumberViewModelの検証に成功

                    // 検証コード生成
                    string code = await UserManager.GenerateChangePhoneNumberTokenAsync(user, model.Number);

                    // メッセージをSMSで送信する。
                    await SmsSender.SendAsync(model.Number,
                        GetContentOfLetter.Get("AddPhoneNumber",
                        CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code);

                    // 電話番号の検証画面に進む
                    return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.Number });
                }
                else
                {
                    // ManageAddPhoneNumberViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Verify

        /// <summary>
        /// 追加電話番号の検証画面（初期表示）
        /// GET: /Manage/VerifyPhoneNumber
        /// </summary>
        /// <param name="phoneNumber">追加電話番号</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public ActionResult VerifyPhoneNumber(string phoneNumber)
        {
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                return phoneNumber == null ?
                View("Error") :
                View("VerifyPhoneNumber", new ManageVerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 追加電話番号の検証画面（検証コードの検証）
        /// POST: /Manage/VerifyPhoneNumber
        /// </summary>
        /// <param name="model">ManageVerifyPhoneNumberViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(ManageVerifyPhoneNumberViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageVerifyPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageVerifyPhoneNumberViewModelの検証に成功

                    // 電話番号の検証（電話番号の登録の際に、SMSで送信した検証コードを検証）
                    IdentityResult result = await UserManager.ChangePhoneNumberAsync(
                    	user, model.PhoneNumber, model.Code);

                    // 電話番号の検証結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync(user.Id);

                        // Index - AddPhoneSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.AddPhoneSuccess });
                    }
                    else
                    {
                        // 失敗
                        ModelState.AddModelError("", Resources.ManageController.FailedVerifyPhoneNumber);
                    }
                }
                else
                {
                    // ManageVerifyPhoneNumberViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region Delete

        /// <summary>
        /// 電話番号の削除
        /// POST: /Manage/RemovePhoneNumber
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone && Config.EnableEditingOfUserAttribute)
            {
                // null クリア
                IdentityResult result = await UserManager.SetPhoneNumberAsync(user, "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // 電話番号削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemovePhoneSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 電話番号削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region 2FA

        #region 2FAの有効化・無効化

        /// <summary>
        /// 2FAの有効化
        /// POST: /Manage/EnableTwoFactorAuthentication
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの有効化
                await UserManager.SetTwoFactorEnabledAsync(user, true);

                // 再ログイン
                await this.ReSignInAsync(user.Id);

                return RedirectToAction("Index", "Manage");
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 2FAの無効化
        /// POST: /Manage/DisableTwoFactorAuthentication
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの無効化
                await UserManager.SetTwoFactorEnabledAsync(user, false);

                // 再ログイン
                await this.ReSignInAsync(user.Id);

                return RedirectToAction("Index", "Manage");
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region 2FA(TOTP)の有効化・無効化

        #region EnableTwoFactorAuthenticator

        /// <summary>EnableTwoFactorAuthenticator（初期表示）</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> EnableTwoFactorAuthenticator()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            // QRコード生成
            ManageEnableTwoFactorAuthenticatorViewModel model 
                = new ManageEnableTwoFactorAuthenticatorViewModel();

            await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return View(model);
        }

        /// <summary>EnableTwoFactorAuthenticator</summary>
        /// <param name="model">ManageEnableTwoFactorAuthenticatorViewModel</param>
        /// <returns>IActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthenticator(ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (ModelState.IsValid)
            {
                // トークン検証
                bool is2faTokenValid = await UserManager.VerifyTwoFactorTokenAsync(
                    user, UserManager.Options.Tokens.AuthenticatorTokenProvider,
                    model.Code.Replace(" ", string.Empty).Replace("-", string.Empty));

                if (is2faTokenValid)
                {
                    // valid
                    Logging.MyOperationTrace(string.Format(
                        "User with ID {0} has enabled 2FA with an authenticator app.", user.Id));

                    IEnumerable<string> recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

                    return RedirectToAction(nameof(ShowTwoFactorAuthenticatorRecoveryCodes));
                }
                else
                {
                    // invalid
                    ModelState.AddModelError("Code", "Verification code is invalid.");
                    await LoadSharedKeyAndQrCodeUriAsync(user, model);
                    return View(model);
                }
            }
            else
            {
                // リトライ
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }
        }

        /// <summary>ShowTwoFactorAuthenticatorRecoveryCodes（初期表示）</summary>
        /// <returns>IActionResult</returns>
        [HttpGet]
        public ActionResult ShowTwoFactorAuthenticatorRecoveryCodes()
        {
            string[] recoveryCodes = (string[])TempData[RecoveryCodesKey];

            if (recoveryCodes != null)
            {
                ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel model
                = new ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };

                return View(model); 
            }
            else
            {
                return RedirectToAction(nameof(Index));
            }
        }

        #endregion

        #region ManageTwoFactorAuthenticator

        /// <summary>ManageTwoFactorAuthenticator</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> ManageTwoFactorAuthenticator()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            ManageTwoFactorAuthenticationViewModel model
                = new ManageTwoFactorAuthenticationViewModel
            {
                Is2faEnabled = user.TwoFactorEnabled,
                HasAuthenticator = !string.IsNullOrEmpty(await UserManager.GetAuthenticatorKeyAsync(user)),
                RecoveryCodesLeft = await UserManager.CountRecoveryCodesAsync(user),
            };

            return View(model);
        }

        #endregion

        #region ResetTwoFactorAuthenticator

        /// <summary>ResetTwoFactorAuthenticator（初期表示）</summary>
        /// <returns>IActionResult</returns>
        [HttpGet]
        public ActionResult ResetTwoFactorAuthenticator()
        {
            return View();
        }

        /// <summary>ResetTwoFactorAuthenticator</summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetTwoFactorAuthenticator(string x)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            //await UserManager.SetTwoFactorEnabledAsync(user, false); // これ要る？
            // 確かにAuthenticatorKeyはRollingする（が、nullにはならない）。
            //await UserManager.ResetAuthenticatorKeyAsync(user);

            // 自前で、AuthenticatorKeyとTokensを、nullクリアする
            user.TotpTokens = null;
            user.TotpAuthenticatorKey = null;
            await UserManager.UpdateAsync(user);

            Logging.MyOperationTrace(string.Format(
                            "User with id '{0}' has reset their authentication app key.", user.Id));

            return RedirectToAction(nameof(Index));
        }

        #endregion

        #region TwoFactorAuthenticatorRecoveryCodes

        /// <summary>GenerateTwoFactorAuthenticatorRecoveryCodes（初期表示）</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult GenerateTwoFactorAuthenticatorRecoveryCodes()
        {
            return View();
        }

        /// <summary>GenerateTwoFactorAuthenticatorRecoveryCodes</summary>
        /// <param name="s">dummy</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> GenerateTwoFactorAuthenticatorRecoveryCodes(string s)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (user.TwoFactorEnabled)
            {
                IEnumerable<string> recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                Logging.MyOperationTrace(string.Format(
                            "User with ID {0} has generated new 2FA recovery codes.", user.Id));

                ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel model
                    = new ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

                return View("ShowTwoFactorAuthenticatorRecoveryCodes", model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }            
        }

        #endregion

        #endregion

        #endregion

        #region (External) Logins

        /// <summary>
        /// 外部ログイン管理画面（初期表示）
        /// GET: /Manage/ManageLogins
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ManageLogins(EnumManageMessageId? message)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
                    message == EnumManageMessageId.Error ? Resources.ManageController.Error
                    : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                    : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                    : "";

                // 全ての外部ログイン情報
                IEnumerable<AuthenticationScheme> loginProviders = await SignInManager.GetExternalAuthenticationSchemesAsync();

                // 現在の認証ユーザが外部ログイン済みの外部ログイン情報を取得
                IList<UserLoginInfo> userLogins = await UserManager.GetLoginsAsync(user);

                // 現在の認証ユーザが未ログインの外部ログイン情報を取得
                IList<AuthenticationScheme> otherLogins = new List<AuthenticationScheme>();

                foreach (AuthenticationScheme auth in loginProviders)
                {
                    bool flg = true;
                    foreach (UserLoginInfo ul in userLogins)
                    {
                        if (auth.DisplayName == ul.ProviderDisplayName)
                        {
                            flg = false;
                        }
                    }

                    // userLoginsに存在しないものだけ追加
                    if (flg) otherLogins.Add(auth);
                }

                // 削除ボタンを表示するかしないか。
                // 通常ログインがあるか、外部ログイン・カウントが１以上ある場合に表示する。
                ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;

                // 表示
                return View(new ManageLoginsViewModel
                {
                    CurrentLogins = userLogins,
                    OtherLogins = otherLogins
                });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部ログイン削除
        /// POST: /Manage/RemoveLogin
        /// </summary>
        /// <param name="loginProvider">loginProvider</param>
        /// <param name="providerKey">providerKey</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin && Config.EnableEditingOfUserAttribute)
            {
                // メッセージ列挙型
                EnumManageMessageId? message;

                IdentityResult result = null;

                // クレームを削除
                // Memory Provider使用の時
                // 「コレクションが変更されました。列挙操作は実行されない可能性があります。」
                // 問題で若干冗長なコードに。
                List<Claim> lc = new List<Claim>();
                foreach (Claim c in user.Claims)
                {
                    if (c.Issuer == loginProvider)
                    {
                        lc.Add(c);
                    }
                }
                foreach (Claim c in lc)
                {
                    result = await UserManager.RemoveClaimAsync(user, c);
                }

                // ログインを削除
                result = await UserManager.RemoveLoginAsync(user, loginProvider, providerKey);

                // 結果の確認
                if (result.Succeeded)
                {
                    // ログイン削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        message = EnumManageMessageId.RemoveExternalLoginSuccess;
                    }
                    else
                    {
                        // 再ログインに失敗
                        message = EnumManageMessageId.Error;
                    }
                }
                else
                {
                    // ログイン削除の失敗
                    message = EnumManageMessageId.Error;
                }

                // ログイン管理画面（ログイン削除結果
                return RedirectToAction("ManageLogins", new { Message = message });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部ログイン（リダイレクト）の開始
        /// POST: /Manage/ExternalLogin
        /// </summary>
        /// <param name="provider">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLogin(string provider)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // Request a redirect to the external login provider
                string redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Manage");
                AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
                return this.Challenge(properties, provider);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部LoginのCallback（ExternalLoginCallback）
        /// Redirect後、外部Login providerに着信し、そこで、
        /// URL fragmentを切捨てCookieに認証Claim情報を設定、
        /// その後、ココにRedirectされ、認証Claim情報を使用してSign-Inする。
        /// （外部Login providerからRedirectで戻る先のURLのAction method）
        /// GET: /Manage/ExternalLoginCallback
        /// </summary>
        /// <param name="returnUrl">string</param>
        /// <param name="remoteError">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl, string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                return RedirectToAction(nameof(Index));
            }

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // AccountControllerはサインアップかどうかを判定して処理する必要がある。
                // ManageControllerは判定不要だが、サインイン後なので、uidが一致する必要がある。

                // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
                // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

                //// ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
                //AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
                // 外部ログイン・プロバイダからユーザに関する情報を取得する。
                ExternalLoginInfo externalLoginInfo = await SignInManager.GetExternalLoginInfoAsync();
                if (externalLoginInfo == null)
                {
                    return RedirectToAction(nameof(Index));
                }

                ApplicationUser user = null;
                IdentityResult idResult = null;

                // ログイン情報を受け取れた場合、クレーム情報を分析
                ClaimsIdentity identity = externalLoginInfo.Principal.Identities.First();

                // ID情報とe-mail, name情報は必須
                Claim idClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
                Claim emailClaim = identity.FindFirst(ClaimTypes.Email);
                Claim nameClaim = identity.FindFirst(ClaimTypes.Name);

                // 外部ログインで取得するクレームを標準化する。
                // ・・・
                // ・・・
                // ・・・

                if (idClaim != null)
                {
                    // クレーム情報（ID情報とe-mail, name情報）を抽出
                    string id = idClaim.Value;
                    string name = nameClaim.Value;
                    string email = emailClaim.Value;

                    string uid = "";
                    if (Config.RequireUniqueEmail)
                    {
                        uid = email;
                    }
                    else
                    {
                        uid = name;
                    }

                    if (!string.IsNullOrWhiteSpace(email)
                        && !string.IsNullOrWhiteSpace(name))
                    {
                        // クレーム情報（e-mail, name情報）を取得できた。

                        // 既存の外部ログインを確認する。
                        user = await UserManager.FindByLoginAsync(
                            externalLoginInfo.LoginProvider,
                            externalLoginInfo.ProviderKey);

                        if (user != null)
                        {
                            // 既存の外部ログインがある場合。

                            // ユーザーが既に外部ログインしている場合は、クレームをRemove, Addで更新し、
                            idResult = await UserManager.RemoveClaimAsync(user, emailClaim); // del-ins
                            idResult = await UserManager.AddClaimAsync(user, emailClaim);
                            idResult = await UserManager.RemoveClaimAsync(user, nameClaim); // del-ins
                            idResult = await UserManager.AddClaimAsync(user, nameClaim);

                            //// SignInAsyncより、ExternalSignInAsyncが適切。

                            // ManageControllerではサインイン済みなので、何もしない。
                            return RedirectToAction("ManageLogins");
                        }
                        else
                        {
                            // 既存の外部ログインがない。

                            // ManageControllerではサインアップ・サインイン
                            // 済みなので、外部ログインの追加のみ行なう。
                            user = await UserManager.GetUserAsync(User);

                            // uid（e-mail or name情報）が一致している必要がある。
                            //   Manage（サインイン済み）なので、
                            //   RequireUniqueEmail == false時のname and e-mailまでの一致は不要。
                            if (user.NormalizedUserName == uid.ToUpper()) // ★ これでイイのか？
                            {
                                // uid（e-mail, name情報）が一致している。

                                // 外部ログイン（ = UserLoginInfo ）の追加
                                idResult = await UserManager.AddLoginAsync(user, externalLoginInfo);

                                // クレーム（emailClaim, nameClaim, etc.）の追加
                                if (idResult.Succeeded)
                                {
                                    idResult = await UserManager.AddClaimAsync(user, emailClaim);
                                    idResult = await UserManager.AddClaimAsync(user, nameClaim);
                                    // ・・・
                                    // ・・・
                                    // ・・・
                                }

                                // 上記の結果の確認
                                if (idResult.Succeeded)
                                {
                                    // 外部ログインの追加に成功した場合 → サインイン

                                    // SignInAsync、ExternalSignInAsync
                                    // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                    await SignInManager.SignInAsync(
                                        user,
                                        isPersistent: false);//,  // rememberMe は false 固定（外部ログインの場合）
                                        //rememberBrowser: true); // rememberBrowser は true 固定

                                    IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                                    responseCookies.Set(OAuth2AndOIDCConst.auth_time,
                                        FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
                            
                                    // リダイレクト
                                    return RedirectToAction("ManageLogins");
                                }
                                else
                                {
                                    // 外部ログインの追加に失敗した場合

                                    // 結果のエラー情報を追加
                                    this.AddErrors(idResult);
                                }
                            }
                            else
                            {
                                // uid（e-mail, name情報）が一致していない。
                                // 外部ログインのアカウントを間違えている。
                                return RedirectToAction("ManageLogins",
                                    new { Message = EnumManageMessageId.AccountConflictInSocialLogin });

                            } // else処理済
                        } // else処理済
                    } // クレーム情報（e-mail, name情報）を取得できなかった。
                } // クレーム情報（ID情報）を取得できなかった。

                // ログイン情報を受け取れなかった場合や、その他の問題が在った場合。
                return RedirectToAction("ManageLogins", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Payment Information

        #region Create

        /// <summary>
        /// 支払元情報の追加画面（初期表示）
        /// GET: /Manage/AddPaymentInformation
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AddPaymentInformation()
        {
            if (Config.CanEditPayment
                && Config.EnableEditingOfUserAttribute)
            {
                if (Config.EnableStripe)
                {
                    ViewBag.PublishableKey = Config.Stripe_PK;
                    return View("AddPaymentInformationStripe");
                }
                else if (Config.EnablePAYJP)
                {
                    ViewBag.PublishableKey = Config.PAYJP_PK;
                    return View("AddPaymentInformationPAYJP");
                }
                else
                {
                    throw new NotSupportedException("Payment service is not enabled.");
                }
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 支払元情報の追加画面（支払元情報設定）
        /// POST: /Manage/AddPaymentInformation
        /// </summary>
        /// <param name="model">ManageAddPaymentInformationViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPaymentInformation(ManageAddPaymentInformationViewModel model)
        {
            if (Config.CanEditPayment
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPaymentInformationViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPaymentInformationViewModelの検証に成功

                    // ユーザの検索
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    if (user != null)
                    {
                        // ユーザを取得できた。

                        // TokenからClientIDに変換する。
                        JObject jobj = await WebAPIHelper.GetInstance().CreateaOnlinePaymentCustomerAsync(user.Email, model.PaymentInformation);

                        // 支払元情報（ClientID）の設定
                        user.PaymentInformation = (string)jobj["id"];
                        // ユーザーの保存
                        IdentityResult result = await UserManager.UpdateAsync(user);

                        // 結果の確認
                        if (result.Succeeded)
                        {
                            // 成功

                            // 再ログイン
                            await this.ReSignInAsync(user.Id);

                            // Index - SetPasswordSuccess
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.AddPaymentInformationSuccess });
                        }
                        else
                        {
                            // 失敗
                            this.AddErrors(result);
                        }
                    }
                    else
                    {
                        // ユーザを取得できなかった。
                    }
                }
                else
                {
                    // ManageAddPaymentInformationViewModelの検証に失敗
                }

                // 再表示
                if (Config.EnableStripe)
                {
                    ViewBag.PublishableKey = Config.Stripe_PK;
                    return View("AddPaymentInformationStripe");
                }
                else if (Config.EnablePAYJP)
                {
                    ViewBag.PublishableKey = Config.PAYJP_PK;
                    return View("AddPaymentInformationPAYJP");
                }
                else
                {
                    throw new NotSupportedException("Payment service is not enabled.");
                }
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Charge

        /// <summary>
        /// 課金
        /// POST: /Manage/ChargeByPaymentInformation
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChargeByPaymentInformation()
        {
            if (Config.CanEditPayment
                && Config.EnableEditingOfUserAttribute
                && Config.IsDebug)
            {
                string access_token = (string)HttpContext.Session.GetString(OAuth2AndOIDCConst.AccessToken);

                if (!string.IsNullOrEmpty(access_token))
                {
                    // 課金のテスト処理
                    string ret = await Sts.Helper.GetInstance().
                        CallOAuth2ChageToUserWebAPIAsync(access_token, "jpy", "1000");

                    if (ret == "OK")
                    {
                        // 元の画面に戻る
                        return RedirectToAction("Index");
                    }
                    else { }
                }
                else { }
            }
            else { }

            // エラー画面
            return View("Error");
        }

        #endregion

        #region Delete

        /// <summary>
        /// 支払元情報の削除
        /// POST: /Manage/RemovePaymentInformation
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePaymentInformation()
        {
            if (Config.CanEditPayment
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // 支払元情報のクリア
                user.PaymentInformation = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemovePaymentInformationSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 支払元情報 削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region Unstructured Data

        #region Create

        /// <summary>
        /// 非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddUnstructuredData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> AddUnstructuredData()
        {
            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                ManageAddUnstructuredDataViewModel model = null;

                if (string.IsNullOrEmpty(user.UnstructuredData))
                {
                    model = new ManageAddUnstructuredDataViewModel();
                }
                else
                {
                    model = JsonConvert.DeserializeObject<ManageAddUnstructuredDataViewModel>(user.UnstructuredData);
                }

                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 非構造化データの追加・編集画面（非構造化データ設定）
        /// POST: /Manage/AddUnstructuredData
        /// </summary>
        /// <param name="model">ManageAddUnstructuredDataViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddUnstructuredData(ManageAddUnstructuredDataViewModel model)
        {
            // 二重送信防止機能のテスト
            // System.Threading.Thread.Sleep(5000);

            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddUnstructuredDataViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddUnstructuredDataViewModelの検証に成功

                    // ユーザの検索
                    ApplicationUser user = await UserManager.GetUserAsync(User);

                    if (user != null)
                    {
                        // ユーザを取得できた。
                        user.UnstructuredData = JsonConvert.SerializeObject(model);

                        // ユーザーの保存
                        IdentityResult result = await UserManager.UpdateAsync(user);

                        // 結果の確認
                        if (result.Succeeded)
                        {
                            // 成功

                            // 再ログイン
                            await this.ReSignInAsync(user.Id);
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.AddUnstructuredDataSuccess });
                        }
                        else
                        {
                            // 失敗
                            this.AddErrors(result);
                        }
                    }
                    else
                    {
                        // ユーザを取得できなかった。
                    }
                }
                else
                {
                    // ManageAddUnstructuredDataViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Delete

        /// <summary>
        /// 非構造化データの削除
        /// POST: /Manage/RemoveUnstructuredData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveUnstructuredData()
        {
            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // 非構造化データのクリア
                user.UnstructuredData = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveUnstructuredDataSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 非構造化データ 削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region OAuth2 Data

        #region Create

        /// <summary>
        /// OAuth2関連の非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddSaml2OAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddSaml2OAuth2Data()
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                ManageAddSaml2OAuth2DataViewModel model = null;

                string saml2OAuth2Data = Sts.DataProvider.Get(user.ClientID);

                if (!string.IsNullOrEmpty(saml2OAuth2Data))
                {
                    model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                    if (string.IsNullOrEmpty(model.ClientID))
                    {
                        // 空（userから取得
                        model.ClientID = user.ClientID;
                    }
                    else
                    {
                        // 既（user側が先に更新されることは無い。
                    }
                }
                else
                {
                    // 初期
                    model = new ManageAddSaml2OAuth2DataViewModel();
                }

                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// OAuth2関連の非構造化データの追加・編集画面（OAuth2関連の非構造化データ設定）
        /// POST: /Manage/AddSaml2OAuth2Data
        /// </summary>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddSaml2OAuth2Data(ManageAddSaml2OAuth2DataViewModel model)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddSaml2OAuth2DataViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddSaml2OAuth2DataViewModelの検証に成功
                    if (!string.IsNullOrEmpty(Request.Form["submit.ClientID"]))
                    {
                        ModelState.Clear();
                        model.ClientID = Guid.NewGuid().ToString("N");
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.ClientSecret"]))
                    {
                        ModelState.Clear();
                        model.ClientSecret = GetPassword.Base64UrlSecret(32);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Add"]))
                    {
                        // ユーザの検索
                        ApplicationUser user = await UserManager.GetUserAsync(User);

                        if (user != null)
                        {
                            // ユーザを取得できた。
                            model.ClientName = user.UserName; // ClientNameはUser入力ではない。
                            string unstructuredData = JsonConvert.SerializeObject(model);

                            if (user.ClientID == model.ClientID)
                            {
                                // ClientIDに変更がない場合、更新操作
                                Sts.DataProvider.Update(user.ClientID, unstructuredData);

                                // 再ログイン
                                await this.ReSignInAsync(user.Id);
                                return RedirectToAction("Index", new { Message = EnumManageMessageId.AddSaml2OAuth2DataSuccess });
                            }
                            else if (!string.IsNullOrEmpty(model.ClientID))
                            {
                                // ClientIDに変更がある場合、ユーザーを保存してから、
                                string temp = user.ClientID;
                                user.ClientID = model.ClientID;
                                IdentityResult result = await UserManager.UpdateAsync(user);

                                // 結果の確認
                                if (result.Succeeded)
                                {
                                    // 成功

                                    // 追加操作（Memory Provider があるので del -> ins にする。）
                                    if (!string.IsNullOrEmpty(temp)) Sts.DataProvider.Delete(temp);
                                    Sts.DataProvider.Create(user.ClientID, unstructuredData);

                                    // 再ログイン
                                    await this.ReSignInAsync(user.Id);
                                    return RedirectToAction("Index", new { Message = EnumManageMessageId.AddSaml2OAuth2DataSuccess });
                                }
                                else
                                {
                                    // 失敗
                                    this.AddErrors(result);
                                }
                            }
                            else
                            {
                                // ClientIDが入力されていない（model.ClientID）。
                            }
                        }
                        else
                        {
                            // ユーザを取得できなかった。
                        }
                    }
                    else
                    {
                        // 不明なSubmit
                    }
                }
                else
                {
                    // ManageAddSaml2OAuth2DataViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Get token

        /// <summary>
        /// OAuth2アクセストークンの取得
        /// POST: /Manage/GetOAuth2Token
        /// </summary>
        /// <param name="model">ManageIndexViewModel</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public ActionResult GetOAuth2Token(ManageIndexViewModel model)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // OAuth2AuthorizationCodeGrantClientViewModelの検証
                if (ModelState.IsValid)
                {
                    // 認可エンドポイント
                    string oAuthAuthorizeEndpoint =
                    Config.OAuth2AuthorizationServerEndpointsRootURI
                    + Config.OAuth2AuthorizeEndpoint;

                    // client_id
                    string client_id = Sts.Helper.GetInstance().GetClientIdByName(User.Identity.Name);

                    // redirect_uri
                    string redirect_uri = CustomEncode.UrlEncode2(
                        Config.OAuth2ClientEndpointsRootURI
                        + Config.OAuth2AuthorizationCodeGrantClient_Manage);

                    // state (nonce) // 記号は入れない。
                    string state = GetPassword.Generate(10, 0);
                    HttpContext.Session.SetString("get_oauth2_token_state", state);

                    return Redirect(
                        oAuthAuthorizeEndpoint +
                        "?client_id=" + client_id +
                        "&response_type=code" +
                        "&redirect_uri=" + redirect_uri +
                        "&scope=" + model.Scopes +
                        "&state=" + state +
                        "&response_mode=form_post");
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #region Delete

        /// <summary>
        /// OAuth2関連の非構造化データの削除
        /// POST: /Manage/RemoveSaml2OAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> RemoveSaml2OAuth2Data()
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // OAuth2関連の非構造化データのクリア
                Sts.DataProvider.Delete(user.ClientID);

                // ユーザーの保存（ClientIDのクリア）
                //user.ClientID = ""; 一意制約エラーになるので
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveSaml2OAuth2DataSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region FIDO Data

        #region WebAuthn

        /// <summary>
        /// WebAuthn関連の非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddWebAuthnData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> AddWebAuthnData()
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);
                ViewBag.SequenceNo = "0";
                ViewBag.UserName = user.UserName;
                ViewBag.FIDO2Data = "";

                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// WebAuthn関連の非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddWebAuthnData
        /// </summary>
        /// <param name="fido2Data">string</param>
        /// <param name="sequenceNo">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        public async Task<ActionResult> AddWebAuthnData(string fido2Data, string sequenceNo)
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);
                ViewBag.UserName = user.UserName;

                string temp = "";

                if (sequenceNo == "0")
                {
                    CredentialCreateOptions options = null;

                    try
                    {
                        JObject requestJSON = JsonConvert.DeserializeObject<JObject>(fido2Data);
                        string username = (string)requestJSON["username"];
                        string displayName = (string)requestJSON["displayName"];
                        bool residentKey = bool.Parse((string)requestJSON["authenticatorSelection"]["residentKey"]);
                        string authenticatorAttachment = (string)requestJSON["authenticatorSelection"]["authenticatorAttachment"];
                        string userVerification = (string)requestJSON["authenticatorSelection"]["userVerification"];
                        string attestation = (string)requestJSON["attestation"];

                        if (username == user.UserName)
                        {
                            FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();

                            options = webAuthnHelper.CredentialCreationOptions(
                                username, attestation, authenticatorAttachment, residentKey, userVerification);

                            // Sessionに保存
                            temp = options.ToJson();
                            HttpContext.Session.SetString("fido2.CredentialCreateOptions", temp);
                        }
                    }
                    catch (Exception e)
                    {
                        options = new CredentialCreateOptions
                        {
                            Status = OAuth2AndOIDCConst.error,
                            ErrorMessage = FIDO.WebAuthnHelper.FormatException(e)
                        };
                    }

                    // Htmlを返す。
                    ViewBag.SequenceNo = "1";
                    ViewBag.UserName = user.UserName;
                    ViewBag.FIDO2Data = temp;

                    return View();
                }
                else if (sequenceNo == "1")
                {
                    CredentialMakeResult result = null;

                    try
                    {
                        AuthenticatorAttestationRawResponse attestationResponse
                        = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(fido2Data);

                        FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();

                        // Sessionから復元
                        CredentialCreateOptions options =
                            CredentialCreateOptions.FromJson(
                                HttpContext.Session.GetString("fido2.CredentialCreateOptions"));

                        result = await webAuthnHelper.AuthenticatorAttestation(attestationResponse, options);

                    }
                    catch (Exception e)
                    {
                        result = new CredentialMakeResult
                        {
                            Status = OAuth2AndOIDCConst.error,
                            ErrorMessage = FIDO.WebAuthnHelper.FormatException(e)
                        };
                    }
                    // Htmlを返す。
                    ViewBag.SequenceNo = "2";
                    ViewBag.UserName = user.UserName;
                    ViewBag.FIDO2Data = JsonConvert.SerializeObject(result);

                    return View();
                }
                else if (sequenceNo == "2")
                {
                    return RedirectToAction("Index", new { Message = EnumManageMessageId.AddWebAuthnDataSuccess });
                }
            }

            // エラー画面
            return View("Error");
        }

        /// <summary>
        /// WebAuthn関連の非構造化データの削除
        /// POST: /Manage/RemoveWebAuthnData
        /// </summary>

        /// <param name="publicKeys"></param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        public async Task<ActionResult> RemoveWebAuthnData(string publicKeys)
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // 削除処理
                if (!string.IsNullOrEmpty(publicKeys))
                {
                    string[] _publicKeys = publicKeys.Split(',');

                    foreach (string publicKey in _publicKeys)
                    {
                        FIDO.DataProvider.Delete(publicKey, user.UserName);
                    }
                }
                
                // 公開鍵の検索
                List<PublicKeyCredentialDescriptor> existingPubCredDescriptor = FIDO.DataProvider.GetCredentialsByUser(user.UserName);

                // Htmlを返す。
                ViewBag.ExistingPubCredDescriptor = existingPubCredDescriptor;
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region MsPass

        /// <summary>
        /// MsPass関連の非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddMsPassData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> AddMsPassData()
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);
                ViewBag.UserId = user.Id;
                ViewBag.UserName = user.UserName;
                ViewBag.AttestationChallenge = GetPassword.Generate(22, 0);

                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// MsPass関連の非構造化データの追加・編集画面
        /// POST: /Manage/AddMsPassData
        /// </summary>
        /// <param name="msPassUserId">string</param>
        /// <param name="msPassPublickey">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddMsPassData(
            string msPassUserId, string msPassPublickey)
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                if (user != null)
                {
                    // ユーザを取得できた。
                    //if (user.Id == credentialId)
                    if (user.UserName == msPassUserId)
                    {
                        // 公開鍵を保存
                        user.FIDO2PublicKey = msPassPublickey;

                        // ユーザーの保存
                        IdentityResult result = await UserManager.UpdateAsync(user);

                        // 結果の確認
                        if (result.Succeeded)
                        {
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.AddMsPassDataSuccess });
                        }
                    }
                }
            }

            // エラー画面
            return View("Error");
        }

        /// <summary>
        /// MsPass関連の非構造化データの削除
        /// POST: /Manage/RemoveMsPassData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveMsPassData()
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                if (user != null)
                {
                    // ユーザを取得できた

                    // 公開鍵をクリア
                    user.FIDO2PublicKey = null;

                    // ユーザーの保存
                    IdentityResult result = await UserManager.UpdateAsync(user);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index",
                            new { Message = EnumManageMessageId.RemoveMsPassDataSuccess });
                    }
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #endregion

        #region GDPR

        /// <summary>
        /// GDPR対策処理
        /// GET: /Manage/ManageGdprData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public ActionResult ManageGdprData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// GDPR対策のユーザデータ照会処理
        /// POST: /Manage/ReferGdprPersonalData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ReferGdprPersonalData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (StreamWriter streamWriter = new StreamWriter(ms, Encoding.GetEncoding(CustomEncode.UTF_8)))
                    {
                        streamWriter.WriteLine(JsonConvert.SerializeObject(user));
                        streamWriter.Flush();
                    }

                    return File(ms.ToArray(), "application/json", "user.json");
                }
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// GDPR対策のユーザデータ削除処理
        /// POST: /Manage/DeleteGdprPersonalData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteGdprPersonalData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                #region データ消去
                // 既定の属性
                //user.Id = "";
                user.UserName = user.Id;
                user.PasswordHash = "";
                user.Email = user.Id + "@yyy.com";
                user.EmailConfirmed = false;
                user.PhoneNumber = user.Id;
                user.PhoneNumberConfirmed = false;
                user.AccessFailedCount = 0;
                user.LockoutEnabled = false;
                user.LockoutEndDateUtc = DateTime.MaxValue;
                //user.SecurityStamp = user.SecurityStamp;
                user.TwoFactorEnabled = false;
                // Collection
                //user.Roles = null;
                //user.Logins = null;
                //user.Claims = null;

                // 追加の属性
                user.ClientID = user.Id;
                user.PaymentInformation = "";
                user.UnstructuredData = "";
                user.FIDO2PublicKey = "";
                //user.CreatedDate = ;
                //user.PasswordChangeDate = 
                #endregion

                // ユーザ・データの削除
                IdentityResult result = null;

                foreach (UserLoginInfo l in user.Logins)
                {
                    result = await UserManager.RemoveLoginAsync(user, l.LoginProvider, l.ProviderKey);
                }
                user.Logins = null;

                foreach (Claim c in user.Claims)
                {
                    result = await UserManager.RemoveClaimAsync(user, c);
                }
                user.Claims = null;

                result = await UserManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    // サインアウト（Cookieの削除）
                    await SignInManager.SignOutAsync();
                    //// オペレーション・トレース・ログ出力
                    //Logging.MyOperationTrace(string.Format("{0}({1}) has signed out.", user.Id, user.UserName));

                    // リダイレクト "Index", "Home"へ
                    return RedirectToAction("Index", "Home");
                }
                else { }
            }
            else { }

            // エラー画面
            return View("Error");
        }

        #endregion

        #region Client (Redirectエンドポイント)

        #region Authorization Codeグラント種別

        /// <summary>
        /// Authorization Codeグラント種別のClientエンドポイント
        /// 認可レスポンス（仲介コード）を受け取って処理する。
        /// ・仲介コードを使用してAccess Token・Refresh Tokenを取得
        /// </summary>
        /// <param name="code">仲介コード</param>
        /// <param name="state">state</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-resp"/>
        /// <seealso cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req"/>
        [HttpPost]
        //[ValidateAntiForgeryToken] // response_mode=form_postで実装しているためハズす。
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient(string code, string state)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // Tokenエンドポイントにアクセス
                Uri tokenEndpointUri = new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                // 結果を格納する変数。
                Dictionary<string, string> dic = null;
                OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                {
                    Code = code
                };

                //  client_Idから、client_secretを取得。
                string client_id = Sts.Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                // stateの検証
                if (state == (string)HttpContext.Session.GetString("get_oauth2_token_state"))
                {
                    // state正常
                    HttpContext.Session.SetString("get_oauth2_token_state", ""); // 誤動作防止

                    #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri
                        = Config.OAuth2ClientEndpointsRootURI
                        + Config.OAuth2AuthorizationCodeGrantClient_Manage;

                    // Tokenエンドポイントにアクセス
                    model.Response = await Sts.Helper.GetInstance()
                        .GetAccessTokenByCodeAsync(tokenEndpointUri, client_id, client_secret, redirect_uri, code, "");
                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    #endregion

                    // 余談：OpenID Connectであれば、ここで id_token 検証。

                    // 結果の表示
                    model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken] ?? "";
                    model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                           CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                    model.RefreshToken = dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken) ? dic[OAuth2AndOIDCConst.RefreshToken] : "";

                    // 課金処理で使用する。
                    HttpContext.Session.SetString(OAuth2AndOIDCConst.AccessToken, model.AccessToken);
                }
                else
                {
                    // state異常
                }

                // 画面の表示。
                return View(model);
            }
            else
            {
                return View("Error");
            }
        }

        /// <summary>
        /// Tokenを使った処理のテストコード
        /// ・Refresh Tokenを使用してAccess Tokenを更新
        /// ・Access Tokenを使用してResourceServerのWebAPIにアクセス
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="refreshToken"></param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient2(OAuth2AuthorizationCodeGrantClientViewModel model)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // OAuthAuthorizationCodeGrantClientViewModelの検証
                if (ModelState.IsValid)
                {
                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;

                    #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                    Uri tokenEndpointUri = new Uri(
                        Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                    // Tokenエンドポイントにアクセス

                    //  client_Idから、client_secretを取得。
                    string client_id = Sts.Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                    string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                    model.Response = await Sts.Helper.GetInstance().UpdateAccessTokenByRefreshTokenAsync(
                        tokenEndpointUri, client_id, client_secret, model.RefreshToken);
                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    // 結果の表示
                    model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken] ?? "";
                    model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                    model.RefreshToken = dic[OAuth2AndOIDCConst.RefreshToken] ?? "";

                    // 課金処理で使用する。
                    HttpContext.Session.SetString(OAuth2AndOIDCConst.AccessToken, model.AccessToken);

                    #endregion
                }

                // 画面の表示。
                ModelState.Clear();
                return View("OAuth2AuthorizationCodeGrantClient", model);
            }
            else
            {
                return View("Error");
            }
        }

        #endregion

        #endregion

        #endregion

        #region Helper

        #region 再度サインイン

        /// <summary>
        /// 再度サインインする。
        /// Cookie再設定 or SecurityStamp対応
        /// </summary>
        /// <returns>Task</returns>
        private async Task<bool> ReSignInAsync(string userId)
        {
            // 認証されたユーザを取得
            ApplicationUser user = await UserManager.FindByIdAsync(userId);

            // ユーザの確認
            if (user != null)
            {
                // 認証されたユーザが無い
                // 再度サインイン
                await SignInManager.SignInAsync(
                        user,
                        isPersistent: false);//,      // アカウント記憶    // 既定値
                        //rememberBrowser: true);     // ブラウザ記憶(2FA) // 既定値

                IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                responseCookies.Set(OAuth2AndOIDCConst.auth_time,
                    FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);

                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion

        #region Controller → View

        /// <summary>
        /// ModelStateDictionaryに
        /// IdentityResult.Errorsの情報を移送
        /// </summary>
        /// <param name="result">IdentityResult</param>
        private void AddErrors(IdentityResult result)
        {
            foreach (IdentityError error in result.Errors)
            {
                ModelState.AddModelError("", error.Code + ": " + error.Description);
            }
        }

        #endregion

        #region メール送信処理

        /// <summary>
        /// メアド検証で使用するメール送信処理。
        /// </summary>
        /// <param name="uid">string</param>
        /// <param name="email">string</param>
        /// <param name="code">string</param>
        private async void SendConfirmEmail(string uid, string email, string code)
        {
            string callbackUrl;

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Manage",
                    new { userId = uid, code = code }, protocol: HttpContext.Request.Scheme
                );

            await EmailSender.SendAsync(email, Resources.AccountController.SendEmail_emailconfirm,
                string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl));
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendChangeCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            await EmailSender.SendAsync(user.Email, GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, ""),
                string.Format(GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        #endregion

        #region 2FA(TOTP)

        /// <summary>LoadSharedKeyAndQrCodeUriAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="model">EnableAuthenticatorViewModel</param>
        /// <returns>－</returns>
        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            string totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(totpAuthenticatorKey))
            {
                await UserManager.ResetAuthenticatorKeyAsync(user);
                totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = this.FormatKey(totpAuthenticatorKey);
            model.AuthenticatorUri = this.GenerateQrCodeUri(user.Email, totpAuthenticatorKey);
        }

        /// <summary>FormatKey</summary>
        /// <param name="unformattedKey">string</param>
        /// <returns>FormatKey</returns>
        private string FormatKey(string unformattedKey)
        {
            StringBuilder result = new StringBuilder();
            int currentPosition = 0;

            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }

            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        /// <summary>GenerateQrCodeUri</summary>
        /// <param name="email">string</param>
        /// <param name="unformattedKey">string</param>
        /// <returns>QrCodeUri</returns>
        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                UrlEncoder.Encode("MultiPurposeAuthSite"),
                UrlEncoder.Encode(email),
                unformattedKey);
        }

        #endregion

        #endregion
    }
}