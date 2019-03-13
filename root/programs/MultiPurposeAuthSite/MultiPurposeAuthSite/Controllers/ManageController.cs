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
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using OAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;
using MultiPurposeAuthSite.ViewModels;

using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;
using System.Web.Mvc;
using System.Net.Http;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Facebook;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Pwd;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>ManageController</summary>
    [Authorize]
    public class ManageController : MyBaseMVController
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

        #region constructor

        /// <summary>constructor</summary>
        public ManageController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private ApplicationSignInManager SignInManager
        {
            get
            {
                return HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
        }

        /// <summary>AuthenticationManager</summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

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
                : message == EnumManageMessageId.AddMsPassDataSuccess ? Resources.ManageController.AddMsPassDataSuccess
                : message == EnumManageMessageId.RemoveMsPassDataSuccess ? Resources.ManageController.RemoveMsPassDataSuccess
                : message == EnumManageMessageId.AddWebAuthnDataSuccess ? Resources.ManageController.AddWebAuthnDataSuccess
                : message == EnumManageMessageId.RemoveWebAuthnDataSuccess ? Resources.ManageController.RemoveWebAuthnDataSuccess
                : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                : "";

                // ユーザの取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // モデルの生成
                string oAuth2Data = OAuth2.DataProvider.Get(user.ClientID);

                ManageIndexViewModel model = new ManageIndexViewModel
                {
                    // パスワード
                    HasPassword = await UserManager.HasPasswordAsync(user.Id),
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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
                        user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                        SignInStatus signInResult = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                          // アカウント(UID)
                            password: model.Password,                                         // アカウント(PWD)
                            isPersistent: false,                                              // アカウント記憶
                            shouldLockout: Config.UserLockoutEnabledByDefault); // ロックアウト

                        if (signInResult == SignInStatus.Success)
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
                    user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    string oldUserName = user.UserName;

                    // UserNameの更新
                    user.UserName = model.UserNameForEdit;
                    IdentityResult result = await UserManager.UpdateAsync(user);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 再ログイン
                        if (await this.ReSignInAsync())
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

                    // パスワード設定
                    IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

                        // オペレーション・トレース・ログ出力
                        ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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

                    // パスワード変更
                    IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);

                    // パスワードの変更結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

                        // オペレーション・トレース・ログ出力
                        ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                        SignInStatus result = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                          // アカウント(UID)
                            password: model.Password,                                         // アカウント(PWD)
                            isPersistent: false,                                              // アカウント記憶
                            shouldLockout: Config.UserLockoutEnabledByDefault); // ロックアウト

                        if (result == SignInStatus.Success)
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
                    CustomizedConfirmationProvider.GetInstance().CreateCustomizedConfirmationData(User.Identity.GetUserId(), customizedConfirmationJson);

                    // 確認メールの送信
                    this.SendConfirmEmail(User.Identity.GetUserId(), customizedConfirmationJson.Email, customizedConfirmationJson.Code);

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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック
                        SignInStatus result = await SignInManager.PasswordSignInAsync(
                            userName: user.UserName,                                          // アカウント(UID)
                            password: model.Password,                                         // アカウント(PWD)
                            isPersistent: false,                                              // アカウント記憶
                            shouldLockout: Config.UserLockoutEnabledByDefault); // ロックアウト

                        if (result == SignInStatus.Success)
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
                            CustomizedConfirmationProvider.GetInstance().CreateCustomizedConfirmationData(User.Identity.GetUserId(), customizedConfirmationJson);

                            // 確認メールの送信
                            this.SendConfirmEmail(User.Identity.GetUserId(), customizedConfirmationJson.Email, customizedConfirmationJson.Code);

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
                    if (User.Identity.GetUserId() == userId)
                    {
                        bool isExpired = false;
                        string email = CustomizedConfirmationProvider.GetInstance().CheckCustomizedConfirmationData(userId, code, out isExpired);

                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            // ユーザの取得
                            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());


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
                                if (await this.ReSignInAsync())
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
            if (!Config.RequireUniqueEmail
                && Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // null クリア
                IdentityResult result = await UserManager.SetEmailAsync(User.Identity.GetUserId(), "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // E-mail削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPhoneNumberViewModelの検証に成功

                    // 検証コード生成
                    string code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), model.Number);

                    // メッセージをSMSで送信する。
                    if (UserManager.SmsService != null)
                    {
                        IdentityMessage message = new IdentityMessage
                        {
                            Destination = model.Number,
                            Body = GetContentOfLetter.Get(
                                "AddPhoneNumber", CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code
                        };
                        await UserManager.SmsService.SendAsync(message);
                    }

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
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageVerifyPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageVerifyPhoneNumberViewModelの検証に成功

                    // 電話番号の検証（電話番号の登録の際に、SMSで送信した検証コードを検証）
                    IdentityResult result = await UserManager.ChangePhoneNumberAsync(
                        User.Identity.GetUserId(), model.PhoneNumber, model.Code);

                    // 電話番号の検証結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

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
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // null クリア
                IdentityResult result = await UserManager.SetPhoneNumberAsync(User.Identity.GetUserId(), "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // 電話番号削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの有効化
                await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), true);

                // 再ログイン
                await this.ReSignInAsync();

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
            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの無効化
                await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), false);

                // 再ログイン
                await this.ReSignInAsync();

                return RedirectToAction("Index", "Manage");
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

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
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
               message == EnumManageMessageId.Error ? Resources.ManageController.Error
               : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
               : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
               : "";

                // 認証されたユーザを取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // 現在の認証ユーザが外部ログイン済みの外部ログイン情報を取得
                IList<UserLoginInfo> userLogins = await UserManager.GetLoginsAsync(User.Identity.GetUserId());

                // 現在の認証ユーザが未ログインの外部ログイン情報を取得
                List<AuthenticationDescription> otherLogins = new List<AuthenticationDescription>();

                #region Collect otherLogins
                //// auth : AuthenticationDescription
                //// ul   : UserLoginInfo
                //otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().
                //    Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();

                // 以下と等価（どっちが楽？）

                IEnumerable<AuthenticationDescription> allExternalLogins = AuthenticationManager.GetExternalAuthenticationTypes();
                foreach (AuthenticationDescription auth in allExternalLogins)
                {
                    bool flg = true;
                    foreach (UserLoginInfo ul in userLogins)
                    {
                        if (auth.AuthenticationType == ul.LoginProvider)
                        {
                            flg = false;
                        }
                    }

                    // userLoginsに存在しないものだけ追加
                    if (flg) otherLogins.Add(auth);
                }
                #endregion

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
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // メッセージ列挙型
                EnumManageMessageId? message;

                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                    result = await UserManager.RemoveClaimAsync(user.Id, c);
                }

                // ログインを削除
                result = await UserManager.RemoveLoginAsync(
                    User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));

                // 結果の確認
                if (result.Succeeded)
                {
                    // ログイン削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
        public ActionResult ExternalLogin(string provider)
        {
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // Request a redirect to the external login provider
                //  to link a login for the current user.
                // 現在のユーザーのログインをリンクするために
                // 外部ログイン プロバイダーへのリダイレクトを要求します。
                return new ExternalLoginStarter(
                provider,
                Url.Action("ExternalLoginCallback", "Manage"), User.Identity.GetUserId());
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
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // AccountControllerはサインアップかどうかを判定して処理する必要がある。
                // ManageControllerは判定不要だが、サインイン後なので、uidが一致する必要がある。

                // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
                // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

                // ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
                AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
                // 外部ログイン・プロバイダからユーザに関する情報を取得する。
                ExternalLoginInfo externalLoginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();

                IdentityResult result = null;
                //SignInStatus signInStatus = SignInStatus.Failure;

                if (authenticateResult != null
                    && authenticateResult.Identity != null
                    && externalLoginInfo != null)
                {
                    // ログイン情報を受け取れた場合、クレーム情報を分析
                    ClaimsIdentity identity = authenticateResult.Identity;

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
                        // UserLoginInfoの生成
                        UserLoginInfo login = new UserLoginInfo(idClaim.Issuer, idClaim.Value);

                        // クレーム情報（ID情報とe-mail, name情報）を抽出
                        string id = idClaim.Value;
                        string name = nameClaim.Value;
                        string email = "";

                        #region nameClaim対策 (今の所無し)
                        //・・・
                        #endregion

                        #region emailClaim対策 (Facebook & Twitter)
                        if (emailClaim == null)
                        {
                            // emailClaimが取得できなかった場合、
                            if (externalLoginInfo.Login.LoginProvider == "Facebook")
                            {
                                ClaimsIdentity excIdentity = AuthenticationManager.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);
                                string access_token = excIdentity.FindFirstValue("FacebookAccessToken");
                                FacebookClient facebookClient = new FacebookClient(access_token);

                                // e.g. :
                                // "/me?fields=id,email,gender,link,locale,name,timezone,updated_time,verified,last_name,first_name,middle_name"
                                dynamic myInfo = facebookClient.Get("/me?fields=email,name,last_name,first_name,middle_name,gender");

                                email = myInfo.email; // Microsoft.Owin.Security.Facebookでは、emailClaimとして取得できない。
                                emailClaim = new Claim(ClaimTypes.Email, email); // emailClaimとして生成
                            }
                            else if (externalLoginInfo.Login.LoginProvider == "Twitter")
                            {
                                string access_token = externalLoginInfo.ExternalIdentity.Claims.Where(
                                    x => x.Type == "urn:twitter:access_token").Select(x => x.Value).FirstOrDefault();
                                string access_secret = externalLoginInfo.ExternalIdentity.Claims.Where(
                                    x => x.Type == "urn:twitter:access_secret").Select(x => x.Value).FirstOrDefault();

                                JObject myInfo = await WebAPIHelper.GetInstance().GetTwitterAccountInfo(
                                    "include_email=true",
                                    access_token, access_secret,
                                    Config.TwitterAuthenticationClientId,
                                    Config.TwitterAuthenticationClientSecret);

                                email = (string)myInfo[OAuth2AndOIDCConst.Scope_Email]; // Microsoft.Owin.Security.Twitterでは、emailClaimとして取得できない。
                                emailClaim = new Claim(ClaimTypes.Email, email); // emailClaimとして生成
                            }
                        }
                        else
                        {
                            // emailClaimが取得できた場合、
                            email = emailClaim.Value;
                        }
                        #endregion

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
                            ApplicationUser user = await UserManager.FindAsync(login);

                            if (user != null)
                            {
                                // 既存の外部ログインがある場合。

                                // ユーザーが既に外部ログインしている場合は、クレームをRemove, Addで更新し、
                                result = await UserManager.RemoveClaimAsync(user.Id, emailClaim); // del-ins
                                result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                                result = await UserManager.RemoveClaimAsync(user.Id, nameClaim); // del-ins
                                result = await UserManager.AddClaimAsync(user.Id, nameClaim);

                                // ManageControllerではサインイン済みなので、何もしない。
                                return RedirectToAction("ManageLogins");
                            }
                            else
                            {
                                // 既存の外部ログインがない。

                                // ManageControllerではサインアップ・サインイン
                                // 済みなので、外部ログインの追加のみ行なう。

                                // サインアップ済みの可能性を探る
                                user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                                // uid（e-mail or name情報）が一致している必要がある。
                                //   Manage（サインイン済み）なので、
                                //   RequireUniqueEmail == false時のname and e-mailまでの一致は不要。
                                if (user.UserName == uid)
                                {
                                    // uid（e-mail, name情報）が一致している。

                                    // 外部ログイン（ = UserLoginInfo ）の追加
                                    result = await UserManager.AddLoginAsync(user.Id, externalLoginInfo.Login);

                                    // クレーム（emailClaim, nameClaim, etc.）の追加
                                    if (result.Succeeded)
                                    {
                                        result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                                        result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                                        // ・・・
                                        // ・・・
                                        // ・・・
                                    }

                                    // 上記の結果の確認
                                    if (result.Succeeded)
                                    {
                                        // 外部ログインの追加に成功した場合 → サインイン

                                        // SignInAsync、ExternalSignInAsync
                                        // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                        await SignInManager.SignInAsync(
                                            user,
                                            isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                            rememberBrowser: true); // rememberBrowser は true 固定

                                        // リダイレクト
                                        return RedirectToAction("ManageLogins");
                                    }
                                    else
                                    {
                                        // 外部ログインの追加に失敗した場合

                                        // 結果のエラー情報を追加
                                        this.AddErrors(result);
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
                } // ログイン情報を取得できなかった。

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
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                            await this.ReSignInAsync();

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
                // 課金のテスト処理
                string ret = (string)JsonConvert.DeserializeObject(
                    await OAuth2.Helper.GetInstance().CallOAuth2ChageToUserWebAPIAsync(
                    (string)Session[OAuth2AndOIDCConst.AccessToken], "jpy", "1000"));

                if (ret == "OK")
                {
                    // 元の画面に戻る
                    return RedirectToAction("Index");
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                // 支払元情報のクリア
                user.PaymentInformation = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                            await this.ReSignInAsync();
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                // 非構造化データのクリア
                user.UnstructuredData = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
        /// GET: /Manage/AddOAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddOAuth2Data()
        {
            if (Config.CanEditOAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                ManageAddOAuth2DataViewModel model = null;

                string oAuth2Data = OAuth2.DataProvider.Get(user.ClientID);

                if (!string.IsNullOrEmpty(oAuth2Data))
                {
                    model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
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
                    model = new ManageAddOAuth2DataViewModel();
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
        /// POST: /Manage/AddOAuth2Data
        /// </summary>
        /// <param name="model">ManageAddOAuth2DataViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddOAuth2Data(ManageAddOAuth2DataViewModel model)
        {
            if (Config.CanEditOAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddOAuth2DataViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddOAuth2DataViewModelの検証に成功
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.ClientID")))
                    {
                        ModelState.Clear();
                        model.ClientID = Guid.NewGuid().ToString("N");
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.ClientSecret")))
                    {
                        ModelState.Clear();
                        model.ClientSecret = GetPassword.Base64UrlSecret(32);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Add")))
                    {
                        // ユーザの検索
                        ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                        if (user != null)
                        {
                            // ユーザを取得できた。
                            model.ClientName = user.UserName; // ClientNameはUser入力ではない。
                            string unstructuredData = JsonConvert.SerializeObject(model);

                            if (user.ClientID == model.ClientID)
                            {
                                // ClientIDに変更がない場合、更新操作
                                OAuth2.DataProvider.Update(user.ClientID, unstructuredData);

                                // 再ログイン
                                await this.ReSignInAsync();
                                return RedirectToAction("Index", new { Message = EnumManageMessageId.AddOAuth2DataSuccess });
                            }
                            else
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
                                    if (!string.IsNullOrEmpty(temp)) OAuth2.DataProvider.Delete(temp);
                                    OAuth2.DataProvider.Create(user.ClientID, unstructuredData);

                                    // 再ログイン
                                    await this.ReSignInAsync();
                                    return RedirectToAction("Index", new { Message = EnumManageMessageId.AddOAuth2DataSuccess });
                                }
                                else
                                {
                                    // 失敗
                                    this.AddErrors(result);
                                }
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
                    // ManageAddOAuth2DataViewModelの検証に失敗
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
            if (Config.CanEditOAuth2Data
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
                    string client_id = OAuth2.Helper.GetInstance().GetClientIdByName(User.Identity.Name);

                    // redirect_uri
                    string redirect_uri = CustomEncode.UrlEncode2(
                        Config.OAuth2ClientEndpointsRootURI
                        + Config.OAuth2AuthorizationCodeGrantClient_Manage);

                    // state (nonce) // 記号は入れない。
                    string state = GetPassword.Generate(10, 0);
                    Session["get_oauth2_token_state"] = state;

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
        /// POST: /Manage/RemoveOAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> RemoveOAuth2Data()
        {
            if (Config.CanEditOAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // OAuth2関連の非構造化データのクリア
                OAuth2.DataProvider.Delete(user.ClientID);

                // ユーザーの保存（ClientIDのクリア）
                //user.ClientID = ""; 一意制約エラーになるので
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveOAuth2DataSuccess });
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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
        /// WebAuthn関連の非構造化データの削除
        /// GET: /Manage/RemoveWebAuthnData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> RemoveWebAuthnData()
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveMsPassDataSuccess });
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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
                    result = await UserManager.RemoveLoginAsync(user.Id, l);
                }
                user.Logins = null;
                
                foreach (Claim c in user.Claims)
                {
                    result = await UserManager.RemoveClaimAsync(user.Id, c);
                }
                user.Claims = null;

                result = await UserManager.UpdateAsync(user);
                
                if (result.Succeeded)
                {
                    // サインアウト（Cookieの削除）
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
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
            if (Config.CanEditOAuth2Data
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
                string client_id = OAuth2.Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                // stateの検証
                if (state == (string)Session["get_oauth2_token_state"])
                {
                    // state正常
                    Session["get_oauth2_token_state"] = ""; // 誤動作防止

                    #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri
                        = Config.OAuth2ClientEndpointsRootURI
                        + Config.OAuth2AuthorizationCodeGrantClient_Manage;

                    // Tokenエンドポイントにアクセス
                    model.Response = await OAuth2.Helper.GetInstance()
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
                    Session[OAuth2AndOIDCConst.AccessToken] = model.AccessToken;
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
            if (Config.CanEditOAuth2Data
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
                    string client_id = OAuth2.Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                    string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                    model.Response = await OAuth2.Helper.GetInstance().UpdateAccessTokenByRefreshTokenAsync(
                        tokenEndpointUri, client_id, client_secret, model.RefreshToken);
                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    // 結果の表示
                    model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken] ?? "";
                    model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                    model.RefreshToken = dic[OAuth2AndOIDCConst.RefreshToken] ?? "";

                    // 課金処理で使用する。
                    Session[OAuth2AndOIDCConst.AccessToken] = model.AccessToken;

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

        #region Dispose

        /// <summary>Dispose</summary>
        /// <param name="disposing">bool</param>
        protected override void Dispose(bool disposing)
        {
            // メンバのdisposingを実装しているらしい。
            if (disposing)
            {
            }

            base.Dispose(disposing);
        }

        #endregion

        #region Helper

        #region 再度サインイン

        /// <summary>
        /// 再度サインインする。
        /// Cookie再設定 or SecurityStamp対応
        /// </summary>
        /// <returns>Task</returns>
        private async Task<bool> ReSignInAsync()
        {
            // 認証されたユーザを取得
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            // ユーザの確認
            if (user != null)
            {
                // 認証されたユーザが無い
                // 再度サインイン
                await SignInManager.SignInAsync(
                        user,
                        isPersistent: false,        // アカウント記憶    // 既定値
                        rememberBrowser: true);     // ブラウザ記憶(2FA) // 既定値

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
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError("", error);
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
                    new { userId = uid, code = code }, protocol: Request.Url.Scheme
                );

            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = Resources.AccountController.SendEmail_emailconfirm;
            idmsg.Destination = email;
            idmsg.Body = string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl);

            await ems.SendAsync(idmsg);
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendChangeCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, "");
            idmsg.Destination = user.Email;
            idmsg.Body = string.Format(GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName);

            await ems.SendAsync(idmsg);
        }

        #endregion

        #endregion
    }
}