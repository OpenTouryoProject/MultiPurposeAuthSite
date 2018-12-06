//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
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
using MultiPurposeAuthSite.Extensions.OAuth2;
using FIDO2 = MultiPurposeAuthSite.Extensions.FIDO2;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
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

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
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
            /// <summary>AddOAuth2DataSuccess</summary>
            AddOAuth2DataSuccess,
            /// <summary>RemoveOAuth2DataSuccess</summary>
            RemoveOAuth2DataSuccess,
            /// <summary>AddFIDO2DataSuccess</summary>
            AddFIDO2DataSuccess,
            /// <summary>RemoveFIDO2DataSuccess</summary>
            RemoveFIDO2DataSuccess,
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
        private UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private RoleManager<ApplicationRole> _roleManager = null;
        /// <summary>SignInManager</summary>
        private SignInManager<ApplicationUser> _signInManager = null;
        #endregion

        #region Else
        /// <summary>IEmailSender</summary>
        private IEmailSender _emailSender = null;
        /// <summary>ISmsSender</summary>
        private ISmsSender _smsSender = null;
        /// <summary>ILogger</summary>
        private ILogger _logger = null;
        /// <summary>UrlEncoder</summary>
        private UrlEncoder _urlEncoder = null;
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="smsSender">ISmsSender</param>
        /// <param name="logger">ILogger</param>
        /// <param name="urlEncoder">UrlEncoder</param>
        public ManageController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILogger<AccountController> logger,
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

        /// <summary>ILogger</summary>
        private ILogger Logger
        {
            get
            {
                return this._logger;
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
                : message == EnumManageMessageId.AddOAuth2DataSuccess ? Resources.ManageController.AddOAuth2DataSuccess
                : message == EnumManageMessageId.RemoveOAuth2DataSuccess ? Resources.ManageController.RemoveOAuth2DataSuccess
                : message == EnumManageMessageId.AddFIDO2DataSuccess ? Resources.ManageController.AddFIDO2DataSuccess
                : message == EnumManageMessageId.RemoveFIDO2DataSuccess ? Resources.ManageController.RemoveFIDO2DataSuccess
                : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                : "";

                // ユーザの取得
                ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

                // モデルの生成
                string oAuth2Data = DataProvider.GetInstance().Get(user.ClientID);

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
                    TwoFactor = user.TwoFactorEnabled,
                    // 支払元情報
                    HasPaymentInformation = !string.IsNullOrEmpty(user.PaymentInformation),
                    // 非構造化データ
                    HasUnstructuredData = !string.IsNullOrEmpty(user.UnstructuredData),
                    // OAuth2Data
                    HasOAuth2Data = !string.IsNullOrEmpty(oAuth2Data),
                    // FIDO2PublicKey
                    HasFIDO2Data = !string.IsNullOrEmpty(user.FIDO2PublicKey),
                    // Scopes
                    Scopes = Const.StandardScopes
                };

                // 管理画面の表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
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
                ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);
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
                        user = await UserManager.FindByNameAsync(User.Identity.Name);
                        signInResult = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                          // アカウント(UID)
                            password: model.Password,                                         // アカウント(PWD)
                            isPersistent: false,                                              // アカウント記憶
                            lockoutOnFailure: Config.UserLockoutEnabledByDefault);            // ロックアウト

                        if (signInResult.Succeeded)
                        {
                            // Passwordが一致した。
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
                    user = await UserManager.FindByNameAsync(User.Identity.Name);
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
                    ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
                    ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
                    ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        Microsoft.AspNetCore.Identity.SignInResult result
                            = await SignInManager.PasswordSignInAsync(
                                userName: user.UserName,                                  // アカウント(UID)
                                password: model.Password,                                 // アカウント(PWD)
                                isPersistent: false,                                      // アカウント記憶
                                lockoutOnFailure: Config.UserLockoutEnabledByDefault);    // ロックアウト

                        if (result.Succeeded)
                        {
                            // Passwordが一致した。
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
                ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);
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
                    ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        Microsoft.AspNetCore.Identity.SignInResult result
                            = await SignInManager.PasswordSignInAsync(
                                userName: user.UserName,                                // アカウント(UID)
                                password: model.Password,                               // アカウント(PWD)
                                isPersistent: false,                                    // アカウント記憶
                                lockoutOnFailure: Config.UserLockoutEnabledByDefault);  // ロックアウト

                        if (result.Succeeded)
                        {
                            // Passwordが一致した。
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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
                        bool isExpired = false;
                        string email = CustomizedConfirmationProvider.GetInstance()
                            .CheckCustomizedConfirmationData(userId, code, out isExpired);

                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            // ユーザの取得

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageVerifyPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageVerifyPhoneNumberViewModelの検証に成功

                    // 電話番号の検証（電話番号の登録の際に、SMSで送信した検証コードを検証）
                    IdentityResult result = await UserManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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
            ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);

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

            await EmailSender.SendAsync(Resources.AccountController.SendEmail_emailconfirm, email,
                string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl));
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendChangeCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            await EmailSender.SendAsync(GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, ""), user.Email,
                string.Format(GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        #endregion

        #endregion

        /*
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(IndexViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var email = user.Email;
            if (model.Email != email)
            {
                var setEmailResult = await _userManager.SetEmailAsync(user, model.Email);
                if (!setEmailResult.Succeeded)
                {
                    throw new ApplicationException($"Unexpected error occurred setting email for user with ID '{user.Id}'.");
                }
            }

            var phoneNumber = user.PhoneNumber;
            if (model.PhoneNumber != phoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    throw new ApplicationException($"Unexpected error occurred setting phone number for user with ID '{user.Id}'.");
                }
            }

            StatusMessage = "Your profile has been updated";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationEmail(IndexViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.EmailConfirmationLink(user.Id.ToString(), code, Request.Scheme);
            var email = user.Email;
            await _emailSender.SendEmailConfirmationAsync(email, callbackUrl);

            StatusMessage = "Verification email sent. Please check your email.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                return RedirectToAction(nameof(SetPassword));
            }

            var model = new ChangePasswordViewModel { StatusMessage = StatusMessage };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                AddErrors(changePasswordResult);
                return View(model);
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            _logger.LogInformation("User changed their password successfully.");
            StatusMessage = "Your password has been changed.";

            return RedirectToAction(nameof(ChangePassword));
        }

        [HttpGet]
        public async Task<IActionResult> SetPassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);

            if (hasPassword)
            {
                return RedirectToAction(nameof(ChangePassword));
            }

            var model = new SetPasswordViewModel { StatusMessage = StatusMessage };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var addPasswordResult = await _userManager.AddPasswordAsync(user, model.NewPassword);
            if (!addPasswordResult.Succeeded)
            {
                AddErrors(addPasswordResult);
                return View(model);
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            StatusMessage = "Your password has been set.";

            return RedirectToAction(nameof(SetPassword));
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLogins()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var model = new ExternalLoginsViewModel { CurrentLogins = await _userManager.GetLoginsAsync(user) };
            model.OtherLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
                .Where(auth => model.CurrentLogins.All(ul => auth.Name != ul.LoginProvider))
                .ToList();
            model.ShowRemoveButton = await _userManager.HasPasswordAsync(user) || model.CurrentLogins.Count > 1;
            model.StatusMessage = StatusMessage;

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LinkLogin(string provider)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // Request a redirect to the external login provider to link a login for the current user
            var redirectUrl = Url.Action(nameof(LinkLoginCallback));
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        public async Task<IActionResult> LinkLoginCallback()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync(user.Id.ToString());
            if (info == null)
            {
                throw new ApplicationException($"Unexpected error occurred loading external login info for user with ID '{user.Id}'.");
            }

            var result = await _userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred adding external login for user with ID '{user.Id}'.");
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            StatusMessage = "The external login was added.";
            return RedirectToAction(nameof(ExternalLogins));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var result = await _userManager.RemoveLoginAsync(user, model.LoginProvider, model.ProviderKey);
            if (!result.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred removing external login for user with ID '{user.Id}'.");
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            StatusMessage = "The external login was removed.";
            return RedirectToAction(nameof(ExternalLogins));
        }

        [HttpGet]
        public async Task<IActionResult> TwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var model = new TwoFactorAuthenticationViewModel
            {
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
                Is2faEnabled = user.TwoFactorEnabled,
                RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
            };

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Disable2faWarning()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Unexpected error occured disabling 2FA for user with ID '{user.Id}'.");
            }

            return View(nameof(Disable2fa));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occured disabling 2FA for user with ID '{user.Id}'.");
            }

            _logger.LogInformation("User with ID {UserId} has disabled 2fa.", user.Id);
            return RedirectToAction(nameof(TwoFactorAuthentication));
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var model = new EnableAuthenticatorViewModel();
            await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            // Strip spaces and hypens
            var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Code", "Verification code is invalid.");
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _logger.LogInformation("User with ID {UserId} has enabled 2FA with an authenticator app.", user.Id);
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

            return RedirectToAction(nameof(ShowRecoveryCodes));
        }

        [HttpGet]
        public IActionResult ShowRecoveryCodes()
        {
            var recoveryCodes = (string[])TempData[RecoveryCodesKey];
            if (recoveryCodes == null)
            {
                return RedirectToAction(nameof(TwoFactorAuthentication));
            }

            var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };
            return View(model);
        }

        [HttpGet]
        public IActionResult ResetAuthenticatorWarning()
        {
            return View(nameof(ResetAuthenticator));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            _logger.LogInformation("User with id '{UserId}' has reset their authentication app key.", user.Id);

            return RedirectToAction(nameof(EnableAuthenticator));
        }

        [HttpGet]
        public async Task<IActionResult> GenerateRecoveryCodesWarning()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Cannot generate recovery codes for user with ID '{user.Id}' because they do not have 2FA enabled.");
            }

            return View(nameof(GenerateRecoveryCodes));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Cannot generate recovery codes for user with ID '{user.Id}' as they do not have 2FA enabled.");
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            _logger.LogInformation("User with ID {UserId} has generated new 2FA recovery codes.", user.Id);

            var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

            return View(nameof(ShowRecoveryCodes), model);
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
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

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode("MultiPurposeAuthSite"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, EnableAuthenticatorViewModel model)
        {
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = FormatKey(unformattedKey);
            model.AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey);
        }

        #endregion
        */
    }
}
