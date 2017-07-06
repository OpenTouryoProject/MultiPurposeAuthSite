//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.Util;
using MultiPurposeAuthSite.Models.ViewModels;
using MultiPurposeAuthSite.Models.ASPNETIdentity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.ExternalLoginHelper;
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>AccountのController（テンプレート）</summary>
    [Authorize]
    public class AccountController : MyBaseMVController
    {
        #region constructor

        /// <summary>constructor</summary>
        public AccountController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        public ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        public ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        public ApplicationSignInManager SignInManager
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

        #region サインイン

        /// <summary>
        /// サインイン画面（初期表示）
        /// GET: /Account/Login
        /// </summary>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> Login(string returnUrl)
        {
            // データの生成
            await this.CreateData();

            // ReturnUrl
            ViewBag.ReturnUrl = returnUrl;

            // サインイン画面（初期表示）
            return View();
        }

        /// <summary>
        /// サインイン画面でサインイン
        /// POST: /Account/Login
        /// </summary>
        /// <param name="model">LoginViewModel</param>
        /// <param name="returnUrl">returnUrl</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(AccountLoginViewModel model, string returnUrl)
        {
            // AccountLoginViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountLoginViewModelの検証に成功

                string uid = "";
                // サインアップしたユーザを取得
                if (ASPNETIdentityConfig.RequireUniqueEmail)
                {
                    uid = model.Email;
                }
                else
                {
                    uid = model.Name;
                }

                ApplicationUser user = await UserManager.FindByNameAsync(uid);

                if (user == null)
                {
                    // メッセージを設定
                    ModelState.AddModelError("", Resources.AccountController.Login);
                }
                else
                {
                    // EmailConfirmedになっているか確認する。
                    if (await UserManager.IsEmailConfirmedAsync(user.Id))
                    {
                        // EmailConfirmed == true の場合、
                        // パスワード入力失敗回数に基づいてアカウントがロックアウトされるように設定するには、shouldLockout: true に変更する
                        SignInStatus result = await SignInManager.PasswordSignInAsync(
                                                userName: uid,                                                    // アカウント(UID)
                                                password: model.Password,                                         // アカウント(PWD)
                                                isPersistent: model.RememberMe,                                   // アカウント記憶
                                                shouldLockout: ASPNETIdentityConfig.UserLockoutEnabledByDefault); // ロックアウト

                        // SignInStatus
                        switch (result)
                        {
                            case SignInStatus.Success:
                                // サインイン成功

                                if (ASPNETIdentityConfig.IsLockedDownRedirectEndpoint)
                                {
                                    // AppScan指摘の反映
                                    this.FxSessionAbandon();
                                    // SessionIDの切換にはこのコードが必要である模様。
                                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                    Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));
                                }
                                else
                                {
                                    // テスト段階ではテストに仕様が出るのでSessionクリアしない。
                                }

                                // イベント・ログ出力
                                Log.MyOperationTrace(string.Format("{0}({1}) did sign in.", user.Id, user.UserName));

                                return RedirectToLocal(returnUrl);

                            case SignInStatus.LockedOut:
                                // ロックアウト
                                return View("Lockout");

                            case SignInStatus.RequiresVerification:
                                // EmailConfirmedとは別の2FAが必要。

                                // 検証を求める（2FAなど）。
                                return this.RedirectToAction(
                                    "SendCode", new
                                    {
                                        ReturnUrl = returnUrl,        // 戻り先のURL
                                        RememberMe = model.RememberMe // アカウント記憶
                                    });

                            case SignInStatus.Failure:
                            // サインイン失敗

                            default:
                                // その他
                                // "無効なログイン試行です。"
                                ModelState.AddModelError("", Resources.AccountController.Login);
                                break;
                        }
                    }
                    else
                    {
                        // EmailConfirmed == false の場合、

                        // メアド検証用のメールを送信して、
                        this.SendConfirmEmail(
                            user: user,
                            isConfirmEmail_InsteadOf_PasswordReset: true);

                        // メッセージを設定
                        ModelState.AddModelError("", Resources.AccountController.Login_emailconfirm);
                    }
                }
            }
            else
            {
                // AccountLoginViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        #endregion

        #region サインアウト

        /// <summary>
        /// サインアウト
        /// Get: /Account/LogOff
        /// </summary>
        /// <returns>ActionResult(RedirectToAction)</returns>
        [HttpGet]
        [AllowAnonymous] // 空振りできるように。
        public async Task<ActionResult> LogOff()
        {
            if (User.Identity.IsAuthenticated) // 空振りできるように。
            {
                // サインアウト（Cookieの削除）
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                // イベント・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                Log.MyOperationTrace(string.Format("{0}({1}) did sign out.", user.Id, user.UserName));
            }

            // リダイレクト "Index", "Home"へ
            return RedirectToAction("Index", "Home");
        }

        #endregion

        #region サインアップ プロセス

        #region サインアップ

        /// <summary>
        /// サインアップ画面（初期表示）
        /// GET: /Account/Register
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> Register()
        {
            // データの生成
            await this.CreateData();

            // サインアップ画面（初期表示）
            return View(new AccountRegisterViewModel());
        }

        /// <summary>
        /// サインアップ画面でサインアップ
        /// POST: /Account/Register
        /// </summary>
        /// <param name="model">RegisterViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(AccountRegisterViewModel model)
        {
            // AccountRegisterViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountRegisterViewModelの検証に成功

                string uid = "";
                // サインアップしたユーザを取得
                if (ASPNETIdentityConfig.RequireUniqueEmail)
                {
                    // model.Emailはチェック済み。
                    uid = model.Email;
                }
                else
                {
                    // model.Nameのカスタムのチェック処理は必要か？
                    uid = model.Name;
                }

                if (!string.IsNullOrEmpty(uid))
                {
                    // uidが空文字列でない場合。

                    #region サインアップ

                    // ユーザを作成
                    ApplicationUser user = await ApplicationUser.CreateBySignup(uid, false);

                    // ApplicationUserManagerのCreateAsync
                    IdentityResult result = await UserManager.CreateAsync(
                            user,
                            model.Password // Passwordはハッシュ化される。
                        );

                    #endregion

                    #region サインイン or メアド検証

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // イベント・ログ出力
                        Log.MyOperationTrace(string.Format("{0}({1}) did sign up.", user.Id, user.UserName));

                        #region サインアップ成功

                        // ロールに追加。
                        if (result.Succeeded)
                        {
                            await this.UserManager.AddToRoleAsync(user.Id, ASPNETIdentityConst.Role_User);
                            await this.UserManager.AddToRoleAsync(user.Id, ASPNETIdentityConst.Role_Admin);
                        }

                        if (ASPNETIdentityConfig.RequireUniqueEmail)
                        {
                            // サインインの前にメアド検証用のメールを送信して、
                            this.SendConfirmEmail(
                                user: user,
                                isConfirmEmail_InsteadOf_PasswordReset: true);

                            // VerifyEmailAddress画面へ遷移
                            return View("VerifyEmailAddress");
                        }
                        else
                        {
                            // Login画面へ遷移
                            return View("Login");
                        }

                        #endregion
                    }
                    else
                    {
                        #region サインアップ失敗

                        // メアド検証の再送について
                        if (ASPNETIdentityConfig.RequireUniqueEmail)
                        {
                            // サインアップ済みの可能性を探る
                            ApplicationUser oldUser = await UserManager.FindByNameAsync(uid);

                            if (oldUser == null)
                            {
                                // サインアップ済みでない。

                                // 作成(CreateAsync)に失敗
                                AddErrors(result);
                                // 再表示
                                return View(model);
                            }
                            else
                            {
                                #region サインアップ済み

                                // userを確認する。
                                if (oldUser.EmailConfirmed)
                                {
                                    // EmailConfirmed済み。

                                    // 作成(CreateAsync)に失敗
                                    AddErrors(result);
                                    // 再表示
                                    return View(model);
                                }
                                else if (oldUser.Logins.Count != 0)
                                {
                                    // ExternalLogin済み。

                                    // 作成(CreateAsync)に失敗
                                    AddErrors(result);
                                    // 再表示
                                    return View(model);
                                }
                                else
                                {
                                    // oldUserは存在するが
                                    // ・EmailConfirmed済みでない。
                                    // 若しくは、
                                    // ・ExternalLogin済みでない。

                                    // 既存レコードを再作成

                                    // 削除して
                                    result = await UserManager.DeleteAsync(oldUser);

                                    // 結果の確認
                                    if (result.Succeeded)
                                    {
                                        // ApplicationUserManagerのCreateAsync
                                        result = await UserManager.CreateAsync(
                                                user,
                                                model.Password // Passwordはハッシュ化される。
                                            );

                                        // 結果の確認
                                        if (result.Succeeded)
                                        {
                                            // 再度、メアド検証

                                            // メアド検証用のメールを送信して、
                                            this.SendConfirmEmail(
                                                user: user,
                                                isConfirmEmail_InsteadOf_PasswordReset: true);

                                            // VerifyEmailAddress

                                            //ViewBag.Link = callbackUrl;
                                            return View("VerifyEmailAddress");
                                        }
                                        else
                                        {
                                            // 再作成(CreateAsync)に失敗
                                            AddErrors(result);
                                            // 再表示
                                            return View(model);
                                        }
                                    }
                                    else
                                    {
                                        // 削除(DeleteAsync)に失敗
                                        AddErrors(result);
                                        // 再表示
                                        return View(model);
                                    }
                                }

                                #endregion
                            }
                        }

                        #endregion
                    }

                    // UserManager.CreateAsyncの
                    // resultのエラー情報を追加
                    AddErrors(result);
                    // 再表示
                    return View(model);

                    #endregion

                }
                else
                {
                    // uidが空文字列の場合。
                }
            }
            else
            {
                // AccountRegisterViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        #endregion

        // → 「サインアップ」から遷移

        #region メアド検証

        /// <summary>
        /// メアド検証画面（メールからのリンクで結果表示）
        /// GET: /Account/EmailConfirmation
        /// </summary>
        /// <param name="userId">string</param>
        /// <param name="code">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> EmailConfirmation(string userId, string code)
        {
            // 入力の検証
            if (userId == null || code == null)
            {
                // エラー画面
                return View("Error");
            }
            else
            {
                if (ASPNETIdentityConfig.DisplayAgreementScreen)
                {
                    // 約款画面を表示
                    return View(
                        "Agreement",
                         new AccountAgreementViewModel
                         {
                             UserId = userId,
                             Code = code,
                             Agreement = GetContentOfLetter.Get("Agreement", CustomEncode.UTF_8, null),
                             AcceptedAgreement = false
                         });
                }
                else
                {
                    // アクティベーション
                    IdentityResult result = await UserManager.ConfirmEmailAsync(userId, code);

                    // メアド検証結果 ( "EmailConfirmation" or "Error"
                    if (result.Succeeded)
                    {
                        // イベント・ログ出力
                        ApplicationUser user = await UserManager.FindByIdAsync(userId);
                        Log.MyOperationTrace(string.Format("{0}({1}) did confirmed.", user.Id, user.UserName));

                        return View("EmailConfirmation");
                    }
                    else
                    {
                        return View("Error");
                    }
                }
            }
        }

        /// <summary>
        /// メアド検証画面（約款）
        /// POST: /Account/EmailConfirmation
        /// </summary>
        /// <param name="userId">string</param>
        /// <param name="code">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EmailConfirmation(AccountAgreementViewModel model)
        {
            if (ASPNETIdentityConfig.DisplayAgreementScreen)
            {
                // AccountAgreementViewModelの検証
                if (ModelState.IsValid)
                {
                    // AccountAgreementViewModelの検証に成功

                    if (model.AcceptedAgreement)
                    {
                        // 同意された。

                        // アクティベーション
                        IdentityResult result = await UserManager.ConfirmEmailAsync(model.UserId, model.Code);

                        // メアド検証結果 ( "EmailConfirmation" or "Error"
                        if (result.Succeeded)
                        {
                            // イベント・ログ出力
                            ApplicationUser user = await UserManager.FindByIdAsync(model.UserId);
                            Log.MyOperationTrace(string.Format("{0}({1}) did confirmed.", user.Id, user.UserName));

                            return View("EmailConfirmation");
                        }
                        else
                        {
                            return View("Error");
                        }
                    }
                    else
                    {
                        // 同意されていない。
                    }
                }
                else
                {
                    // AccountAgreementViewModelの検証に失敗
                }

                // 再表示
                return View("Agreement", model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region パスワードの失念・変更プロセス

        #region パスワードの失念

        /// <summary>
        /// ForgotPassword画面（初期表示）
        /// GET: /Account/ForgotPassword
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            // ForgotPassword画面（初期表示）
            return View();
        }

        /// <summary>
        /// ForgotPassword画面（メールの送信）
        /// POST: /Account/ForgotPassword
        /// </summary>
        /// <param name="model">ForgotPasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(AccountForgotPasswordViewModel model)
        {
            // AccountForgotPasswordViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountForgotPasswordViewModelの検証に成功

                // ユーザの取得（サインインできないので、User.Identity.GetUserId()は使用不可能）
                ApplicationUser user = await UserManager.FindByEmailAsync(model.Email);

                // 補足 : EmailConfirmedされて無くても、PasswordResetを可能にした。
                // 理由 : EmailConfirmed前にForgotPasswordすると、復帰する方法がなくなるので。
                if (user == null) // || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // ユーザが取得できなかった場合。

                    // Security的な意味で
                    //  - ユーザーが存在しないことや
                    //  - E-mail未確認であることを
                    // （UI経由で）公開しない。
                }
                else
                {
                    // ユーザが取得できた場合。

                    // パスワード リセット用のメールを送信
                    this.SendConfirmEmail(
                            user: user,
                            isConfirmEmail_InsteadOf_PasswordReset: false
                        );

                    // "パスワードの失念の確認"画面を表示 
                    return View("ForgotPasswordConfirmation");
                }
            }
            else
            {
                // AccountForgotPasswordViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        #endregion

        // → 「パスワードの失念」から遷移

        #region パスワード・リセット

        /// <summary>
        /// パスワード・リセット画面（メールからのリンクで初期表示）
        /// GET: /Account/ResetPassword
        /// </summary>
        /// <param name="userId">string</param>
        /// <param name="code">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ResetPassword(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId)
                || string.IsNullOrEmpty(code))
            {
                // パラメタが無い場合はエラー
                return View("Error");
            }
            else
            {
                ApplicationUser user = await UserManager.FindByIdAsync(userId);

                // User情報をResetPassword画面に表示することも可能。

                return View(new AccountResetPasswordViewModel
                {
                    UserId = user.Id,
                    Email = user.Email,
                    Code = code
                });
            }
        }

        /// <summary>
        /// パスワード・リセット画面でリセット
        /// POST: /Account/ResetPassword
        /// </summary>
        /// <param name="model">ResetPasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(AccountResetPasswordViewModel model)
        {
            // AccountResetPasswordViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountResetPasswordViewModelの検証に成功

                // パスワードのリセット
                IdentityResult result = await UserManager.ResetPasswordAsync(model.UserId, model.Code, model.Password);

                // 結果の確認
                if (result.Succeeded)
                {
                    // パスワードのリセットの成功

                    // イベント・ログ出力
                    ApplicationUser user = await UserManager.FindByIdAsync(model.UserId);
                    Log.MyOperationTrace(string.Format("{0}({1}) did reset own password.", user.Id, user.UserName));

                    // "パスワードのリセットの確認"画面を表示 
                    return View("ResetPasswordConfirmation");
                }
                else
                {
                    // パスワードのリセットの失敗

                    // 結果のエラー情報を追加
                    AddErrors(result);
                }

            }
            else
            {
                // ResetPasswordViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        #endregion

        #endregion

        #region 2FA (2 要素認証)

        #region 2FA画面のコード送信

        /// <summary>
        /// 2FA画面のコード送信画面（初期表示）
        /// GET: /Account/SendCode
        /// </summary>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            // 検証されたアカウントのUIDを取得
            string userId = await SignInManager.GetVerifiedUserIdAsync();

            if (userId == null)
            {
                // UID == null

                // エラー
                return View("Error");
            }
            else
            {
                // UID != null

                // UIDから、2FAのプロバイダを取得する。
                IList<string> userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);

                // 2FAのプロバイダの一覧を取得する
                List<SelectListItem> factorOptions = userFactors.Select(
                    purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();

                // 2FA画面のコード送信画面に遷移
                return View(new AccountSendCodeViewModel
                {
                    Providers = factorOptions,  // 2FAのプロバイダの一覧
                    ReturnUrl = returnUrl,      // 戻り先のURL
                    RememberMe = rememberMe     // アカウント記憶
                });
            }
        }

        /// <summary>
        /// 2FA画面のコード送信画面でコード送信
        /// POST: /Account/SendCode
        /// </summary>
        /// <param name="model">SendCodeViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        // 
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(AccountSendCodeViewModel model)
        {
            // AccountSendCodeViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountSendCodeViewModelの検証に成功

                // Generate the token and send it
                // トークンを生成して送信します。
                if (await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
                {
                    // 成功

                    // 2FA画面でコードの検証用のViewへ
                    return RedirectToAction("VerifyCode", new
                    {
                        Provider = model.SelectedProvider,  // 2FAプロバイダ
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                        RememberBrowser = true              // ブラウザ記憶(2FA)
                    });
                }
                else
                {
                    // 失敗
                }
            }
            else
            {
                // AccountSendCodeViewModelの検証に失敗
            }

            // 再表示
            return View();
        }

        #endregion

        #region 2FA画面のコード検証

        /// <summary>
        /// 2FA画面のコード検証（初期表示）
        /// GET: /Account/VerifyCode
        /// </summary>
        /// <param name="provider">2FAプロバイダ</param>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <param name="rememberBrowser">ブラウザ記憶(2FA)</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe, bool rememberBrowser)
        {
            // Require that the user has already logged in via username/password or external login
            // ユーザーが既にユーザ名/パスワードまたは外部ログイン経由でログイン済みであることが必要。
            bool hasBeenVerified = await SignInManager.HasBeenVerifiedAsync();

            if (!hasBeenVerified)
            {
                // エラー画面
                return View("Error");
            }
            else
            {
                // 2FA画面のコード検証（初期表示）
                return View(
                    new AccountVerifyCodeViewModel
                    {
                        Provider = provider,                    // 2FAプロバイダ
                        ReturnUrl = returnUrl,                  // 戻り先のURL
                        RememberMe = rememberMe,                // アカウント記憶
                        RememberBrowser = rememberBrowser       // ブラウザ記憶(2FA)
                    });
            }
        }

        /// <summary>
        /// 2FA画面のコード検証
        /// POST: /Account/VerifyCode
        /// </summary>
        /// <param name="model">VerifyCodeViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(AccountVerifyCodeViewModel model)
        {
            // AccountVerifyCodeViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountVerifyCodeViewModelの検証に成功

                // The following code protects for brute force attacks against the two factor codes. 
                // If a user enters incorrect codes for a specified amount of time then the user account will be locked out for a specified amount of time. 
                // You can configure the account lockout settings in IdentityConfig( = ApplicationSignInManager, ApplicationUserManager, SmsService, EmailService)

                // 次のコードは、2FAコードに対するブルートフォース攻撃から保護します。
                // 指定時間の間にコード入力の誤りが指定の回数に達すると、アカウントは、指定時間の間ロックアウトされる。
                // IdentityConfig.cs(ApplicationUserManager.Create)でアカウントロックアウトの設定を行うことができる。
                SignInStatus result = await SignInManager.TwoFactorSignInAsync(
                        provider: model.Provider,                                  // 2FAプロバイダ
                        code: model.Code,                                          // 2FAコ－ド
                        isPersistent: model.RememberBrowser, // model.RememberMe,  // アカウント記憶 ( ・・・仕様として解り難いので、RememberBrowserを使用 )
                        rememberBrowser: model.RememberBrowser                     // ブラウザ記憶(2FA)
                        );

                // SignInStatus
                switch (result)
                {
                    case SignInStatus.Success:
                        // サインイン成功

                        // AppScan指摘の反映
                        this.FxSessionAbandon();
                        // SessionIDの切換にはこのコードが必要である模様。
                        // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                        Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

                        //// イベント・ログ出力 できない（User.Identity.GetUserId() == null
                        //ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                        //Log.MyOperationTrace(string.Format("{0}({1}) did 2fa sign in.", user.Id, user.UserName));

                        return RedirectToLocal(model.ReturnUrl);

                    case SignInStatus.LockedOut:
                        // ロックアウト
                        return View("Lockout");

                    case SignInStatus.Failure:
                    // サインイン失敗
                    default:
                        // その他
                        // "無効なコード。"
                        ModelState.AddModelError("", Resources.AccountController.InvalidCode);
                        break;
                }
            }
            else
            {
                // VerifyCodeViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        #endregion      

        #endregion

        #region 外部ログイン

        /// <summary>
        /// 外部Login（Redirect）の開始
        /// POST: /Account/ExternalLogin
        /// </summary>
        /// <param name="provider">string</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            // 外部ログイン プロバイダーへのリダイレクトを要求します
            return new ExternalLoginStarter(
                provider,
                Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        #region ExternalLoginCallback

        /// <summary>
        /// 外部LoginのCallback（ExternalLoginCallback）
        /// Redirect後、外部Login providerに着信し、そこで、
        /// URL fragmentを切捨てCookieに認証Claim情報を設定、
        /// その後、ココにRedirectされ、認証Claim情報を使用してSign-Inする。
        /// （外部Login providerからRedirectで戻る先のURLのAction method）
        /// GET: /Account/ExternalLoginCallback
        /// </summary>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            // ManageControllerはサインイン後なので、uidが一致する必要がある。
            // AccountControllerはサインイン前なので、uidの一致は不要だが、
            // サインアップかどうかを判定して処理する必要がある。

            // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
            // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

            // ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
            AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
            // 外部ログイン・プロバイダからユーザに関する情報を取得する。
            ExternalLoginInfo externalLoginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();

            IdentityResult result = null;
            SignInStatus signInStatus = SignInStatus.Failure;

            if (authenticateResult != null
                && authenticateResult.Identity != null
                && externalLoginInfo != null)
            {
                // ログイン情報を受け取れた場合、クレーム情報を分析
                ClaimsIdentity claims = authenticateResult.Identity;

                // ID情報とe-mail, name情報は必須
                Claim idClaim = claims.FindFirst(ClaimTypes.NameIdentifier);
                Claim emailClaim = claims.FindFirst(ClaimTypes.Email);
                Claim nameClaim = claims.FindFirst(ClaimTypes.Name);

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

                    #region emailClaim対策 (Facebook)
                    if (emailClaim == null)
                    {
                        // emailClaimが取得できなかった場合、
                        if (externalLoginInfo.Login.LoginProvider == "Facebook")
                        {
                            var identity = AuthenticationManager.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);
                            var access_token = identity.FindFirstValue("FacebookAccessToken");
                            var fb = new Facebook.FacebookClient(access_token);
                            dynamic myInfo = fb.Get("/me?fields=email"); // specify the email field
                            email = myInfo.email; // Facebookでは、emailClaimを取得できない。
                        }
                    }
                    else
                    {
                        // emailClaimが取得できた場合、
                        email = emailClaim.Value;
                    }
                    #endregion

                    string uid = "";
                    if (ASPNETIdentityConfig.RequireUniqueEmail)
                    {
                        uid = email;
                    }
                    else
                    {
                        uid = name;
                    }

                    if (!string.IsNullOrEmpty(email)
                        && !string.IsNullOrEmpty(name))
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

                            // SignInAsyncより、ExternalSignInAsyncが適切。

                            //// 通常のサインイン
                            //await SignInManager.SignInAsync(

                            // 既存の外部ログイン・プロバイダでサインイン
                            signInStatus = await SignInManager.ExternalSignInAsync(
                                                 loginInfo: externalLoginInfo,
                                                 isPersistent: false); // 外部ログインの Cookie 永続化は常に false.

                            // AppScan指摘の反映
                            this.FxSessionAbandon();
                            // SessionIDの切換にはこのコードが必要である模様。
                            // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                            Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

                            // イベント・ログ出力
                            Log.MyOperationTrace(string.Format("{0}({1}) did ext sign in.", user.Id, user.UserName));

                            return RedirectToLocal(returnUrl);
                        }
                        else
                        {
                            // 既存の外部ログインがない。

                            // AccountControllerで、ユーザーが既に外部ログインしていない場合は、
                            // 外部ログインだけで済むか、サインアップからかを確認する必要がある。

                            // サインアップ済みの可能性を探る
                            user = await UserManager.FindByNameAsync(uid);

                            if (user != null)
                            {
                                // サインアップ済み → 外部ログイン追加だけで済む

                                // 外部ログイン（ = UserLoginInfo ）の追加
                                if (ASPNETIdentityConfig.RequireUniqueEmail)
                                {
                                    result = await UserManager.AddLoginAsync(user.Id, externalLoginInfo.Login);
                                }
                                else
                                {
                                    if (email == user.Email)
                                    {
                                        // メアドも一致
                                        result = await UserManager.AddLoginAsync(user.Id, externalLoginInfo.Login);
                                    }
                                    else
                                    {
                                        // メアド不一致
                                        result = new IdentityResult();
                                    }
                                } 

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
                                    // SignInAsync、ExternalSignInAsync
                                    // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                    await SignInManager.SignInAsync(
                                        user,
                                        isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                        rememberBrowser: true); // rememberBrowser は true 固定

                                    //// この外部ログイン・プロバイダでサインイン
                                    //signInStatus = await SignInManager.ExternalSignInAsync(

                                    // AppScan指摘の反映
                                    this.FxSessionAbandon();
                                    // SessionIDの切換にはこのコードが必要である模様。
                                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                    Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

                                    // イベント・ログ出力
                                    Log.MyOperationTrace(string.Format("{0}({1}) did ext sign in.", user.Id, user.UserName));

                                    // リダイレクト
                                    return RedirectToLocal(returnUrl);
                                }
                                else
                                {
                                    // 外部ログインの追加に失敗した場合

                                    // 結果のエラー情報を追加
                                    AddErrors(result);
                                }
                            }
                            else
                            {
                                // サインアップ済みでない → サインアップから行なう。
                                // If the user does not have an account, then prompt the user to create an account
                                // ユーザがアカウントを持っていない場合、アカウントを作成するようにユーザに促します。
                                ViewBag.ReturnUrl = returnUrl;
                                ViewBag.LoginProvider = login.LoginProvider;

                                //// メアドを返さないので、ExternalLoginConfirmationで
                                //// メアドを手入力して外部ログインと関連付けを行なう。
                                ////return View("ExternalLoginConfirmation");
                                //return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });

                                // 外部ログイン プロバイダのユーザー情報でユーザを作成
                                // uid = 連携先メアドの場合、E-mail confirmationはしない（true）。
                                user = await ApplicationUser.CreateBySignup(uid, true);

                                // サインアップ時のみ、メアドも追加
                                //（RequireUniqueEmail = false時を想定）
                                user.Email = email;
                                user.EmailConfirmed = true;

                                // ユーザの新規作成（パスワードは不要）
                                result = await UserManager.CreateAsync(user);

                                // 結果の確認
                                if (result.Succeeded)
                                {
                                    // ユーザの新規作成が成功した場合

                                    // 外部ログイン（ = idClaim）の追加
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

                                    // 結果の確認
                                    if (result.Succeeded)
                                    {
                                        // 外部ログインの追加に成功した場合 → サインイン

                                        // SignInAsync、ExternalSignInAsync
                                        // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                        await SignInManager.SignInAsync(
                                           user: user,
                                           isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                           rememberBrowser: true); // rememberBrowser は true 固定

                                        //// この外部ログイン・プロバイダでサインイン
                                        // signInStatus = await SignInManager.ExternalSignInAsync(

                                        // AppScan指摘の反映
                                        this.FxSessionAbandon();
                                        // SessionIDの切換にはこのコードが必要である模様。
                                        // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                        Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

                                        // イベント・ログ出力
                                        Log.MyOperationTrace(string.Format("{0}({1}) did ext sign up.", user.Id, user.UserName));

                                        // リダイレクト
                                        return RedirectToLocal(returnUrl);
                                    }
                                    else
                                    {
                                        // 外部ログインの追加に失敗した場合

                                        // 結果のエラー情報を追加
                                        AddErrors(result);
                                    }
                                }
                                else
                                {
                                    // ユーザの新規作成が失敗した場合

                                    // 結果のエラー情報を追加
                                    AddErrors(result);
                                } // else処理済
                            } // else処理済
                        } // else処理済
                    } // クレーム情報（e-mail, name情報）を取得できなかった。
                } // クレーム情報（ID情報）を取得できなかった。
            } // ログイン情報を取得できなかった。

            // ログイン情報を受け取れなかった場合や、その他の問題が在った場合。
            return View("ExternalLoginFailure");
        }

        #endregion

        #endregion

        #region OAuth Endpoint

        #region Authorize（認可エンドポイント）

        #region 認可エンドポイントでサインインして、EmptyResultを返した後のRedirect先について。

        // この後のRedirect先をdebug proxyにかけて分析した所、
        // --------------------------------------------------
        // HTTP / 1.1 302 Found
        // Location: http://localhost:nnnnn/・・・/#access_token=・・・
        // --------------------------------------------------
        // と言う感じで、RedirectエンドポイントへのRedirect処理になっていた。

        // Redirect先のURLは、
        // facebook - Setting the redirect_uri in Asp.Net Identity - Stack Overflow
        // http://stackoverflow.com/questions/20693082/setting-the-redirect-uri-in-asp-net-identity
        // の情報からして、

        // ApplicationOAuthProvider.ValidateClientRedirectUri() メソッドの中の
        // OAuthValidateClientRedirectUriContext.Validated(String redirectUri) メソッドで設定されている模様。

        #endregion

        /// <summary>
        ///  認可エンドポイントで認可リクエストを受け取って処理する。
        ///  ・Authorization Codeグラント種別（仲介コードの発行）
        ///  　の処理を行ない、 権限付与画面の確認画面を表示する。
        ///  ・Implicitグラント種別（Access Tokenの発行）
        ///  　の処理を行ない、 RedirectエンドポイントへRedirect。
        ///  redirect_uriは使用しない。
        ///  </summary>
        /// <param name="response_type">response_type（必須）</param>
        /// <param name="client_id">client_id（必須）</param>
        /// <param name="scope">scope（任意）</param>
        /// <param name="state">state（推奨）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpGet]
        public async Task<ActionResult> OAuthAuthorize(string response_type, string client_id, string scope, string state)
        {
            // Cookie認証チケットからClaimsIdentityを取得しておく。
            AuthenticateResult ticket = this.AuthenticationManager
                .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
            ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

            // scopeパラメタ
            string[] scopes = (scope ?? "").Split(' ');
            
            if (response_type.ToLower() == "code")
            {
                // Authorization Codeグラント種別（仲介コードの発行）
                ViewBag.Name = identity.Name;
                ViewBag.Scopes = scopes;

                if (scopes.Any(x => x.ToLower() == ASPNETIdentityConst.Scope_Auth))
                {
                    // 認可画面をスキップ

                    // アクセス要求を保存して、仲介コードを発行する。
                    identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                    //ClaimsIdentity identity = new ClaimsIdentity(new ClaimsPrincipal(User).Claims.ToArray(), "Bearer");

                    // ClaimsIdentityに、その他、所定のClaimを追加する
                    // ただし、認可画面をスキップする場合は、scopeをフィルタする。
                    OAuthProviderHelper.AddClaim(identity, client_id, state,
                        OAuthProviderHelper.FilterClaimAtAuth(scopes).ToArray());

                    // ClaimsIdentityでサインインして、仲介コードを発行
                    this.AuthenticationManager.SignIn(identity);

                    // イベント・ログ出力
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    Log.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of auth by {2}({3}).",
                        user.Id, user.UserName, client_id, OAuthProviderHelper.GetInstance().GetClientName(client_id)));

                    // RedirectエンドポイントへRedirect
                    return new EmptyResult();
                }
                else
                {
                    // アクセス要求の許可/拒否を訪ねるViewを表示
                    return View();
                }
            }
            else if (response_type.ToLower() == "token")
            {
                // Implicitグラント種別（Access Tokenの発行）
                if (scopes.Any(x => x.ToLower() == ASPNETIdentityConst.Scope_Auth))
                {
                    // authの場合、Implicitグラント種別はNGとする。
                }
                else
                {
                    // アクセス要求の許可
                    identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                    //ClaimsIdentity identity = new ClaimsIdentity(new ClaimsPrincipal(User).Claims.ToArray(), "Bearer");

                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    OAuthProviderHelper.AddClaim(identity, client_id, state, scopes);

                    // ClaimsIdentityでサインインして、Access Tokenを発行
                    AuthenticationManager.SignIn(identity);

                    // イベント・ログ出力
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    Log.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of token by {2}({3}).",
                            user.Id, user.UserName, client_id, OAuthProviderHelper.GetInstance().GetClientName(client_id)));
                }

                // RedirectエンドポイントへRedirect
                return new EmptyResult();
            }
            else
            {
                // ・・・
            }

            // 再表示
            return View();
        }

        /// <summary>
        ///  Authorization Codeグラント種別の権限付与画面の結果を受け取り、
        ///  仲介コードを発行してRedirectエンドポイントへRedirect。
        ///  ※ パラメタは、認可レスポンスのURL中に残っているものを使用。
        ///  </summary>
        /// <param name="client_id">client_id（必須）</param>
        /// <param name="scope">scope（任意）</param>
        /// <param name="state">state（推奨）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuthAuthorize(string client_id, string state, string scope)
        {
            // Cookie認証チケットからClaimsIdentityを取得しておく。
            AuthenticateResult ticket = this.AuthenticationManager
                .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
            ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

            // 次に、アクセス要求を保存して、仲介コードを発行する。

            // scopeパラメタ
            string[] scopes = (scope ?? "").Split(' ');

            if (!string.IsNullOrEmpty(Request.Form.Get("submit.Login")))
            {
                // 別のアカウントでログイン
                //（サインアウトしてリダイレクト）
                this.AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                return new RedirectResult(Request.RawUrl);
            }
            else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
            {
                // アクセス要求を保存して、仲介コードを発行する。
                identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                //ClaimsIdentity identity = new ClaimsIdentity(new ClaimsPrincipal(User).Claims.ToArray(), "Bearer");

                // ClaimsIdentityに、その他、所定のClaimを追加する。
                OAuthProviderHelper.AddClaim(identity, client_id, state, scopes);

                // ClaimsIdentityでサインインして、仲介コードを発行
                this.AuthenticationManager.SignIn(identity);

                // イベント・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                Log.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of code by {2}({3}).",
                        user.Id, user.UserName, client_id, OAuthProviderHelper.GetInstance().GetClientName(client_id)));

                // RedirectエンドポイントへRedirect
                return new EmptyResult();
            }
            else
            {
                // ・・・
            }

            // 再表示
            return View();
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
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> OAuthAuthorizationCodeGrantClient(string code, string state)
        {
            if (!ASPNETIdentityConfig.IsLockedDownRedirectEndpoint)
            {
                // Tokenエンドポイントにアクセス
                Uri tokenEndpointUri = new Uri(
                ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                + ASPNETIdentityConfig.OAuthBearerTokenEndpoint);

                // 結果を格納する変数。
                Dictionary<string, string> dic = null;
                OAuthAuthorizationCodeGrantClientViewModel model = new OAuthAuthorizationCodeGrantClientViewModel
                {
                    Code = code
                };

                //  client_Idから、client_secretを取得。
                string client_id = OAuthProviderHelper.GetInstance().GetClientIdByName("TestClient");
                string client_secret = OAuthProviderHelper.GetInstance().GetClientSecret(client_id);

                #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                // メニューに入れたら上手く行かなくなった、
                // テスト用なのでstate検証はコメントアウトする。

                // stateの検証
                //if (state == (string)Session["state"])
                //{
                // state正常

                // 仲介コードからAccess Tokenを取得する。
                string redirect_uri
                    = ASPNETIdentityConfig.OAuthClientEndpointsRootURI
                    + ASPNETIdentityConfig.OAuthAuthorizationCodeGrantClient_Account;

                // Tokenエンドポイントにアクセス
                model.Response = await OAuthProviderHelper.GetInstance()
                    .GetAccessTokenByCodeAsync(tokenEndpointUri, client_id, client_secret, redirect_uri, code);
                dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                // 余談：OpenID Connectであれば、ここで id_token 検証。

                // 結果の表示
                if (ASPNETIdentityConfig.EnableCustomTokenFormat)
                {
                    model.AccessToken = dic["access_token"] ?? "";
                    model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                           CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                    model.RefreshToken = dic.ContainsKey("refresh_token") ? dic["refresh_token"] : "";
                }
                else
                {
                    model.AccessToken = dic["access_token"] ?? "";
                    model.RefreshToken = dic.ContainsKey("refresh_token") ? dic["refresh_token"] : "";
                }
                //}
                //else
                //{
                //    // state異常
                //}

                ViewBag.QS_State = state;
                //ViewBag.SS_State = (string)Session["state"];

                //Session["state"] = ""; // 誤動作防止

                #endregion

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
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuthAuthorizationCodeGrantClient(OAuthAuthorizationCodeGrantClientViewModel model)
        {
            if (!ASPNETIdentityConfig.IsLockedDownRedirectEndpoint)
            {
                // AccountVerifyCodeViewModelの検証
                if (ModelState.IsValid)
                {
                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;

                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.Refresh")))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                            + ASPNETIdentityConfig.OAuthBearerTokenEndpoint);

                        // Tokenエンドポイントにアクセス
                        model.Response = await OAuthProviderHelper.GetInstance()
                            .UpdateAccessTokenByRefreshTokenAsync(tokenEndpointUri, model.RefreshToken);
                        dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                        // 結果の表示
                        if (ASPNETIdentityConfig.EnableCustomTokenFormat)
                        {
                            model.AccessToken = dic["access_token"] ?? "";
                            model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                                CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                            model.RefreshToken = dic["refresh_token"] ?? "";
                        }
                        else
                        {
                            model.AccessToken = dic["access_token"] ?? "";
                            model.RefreshToken = dic["refresh_token"] ?? "";
                        }

                        #endregion
                    }
                    else
                    {
                        #region Access Tokenを使用してResourceServerのWebAPIにアクセス

                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.GetUserClaims")))
                        {
                            // WebAPIのエンドポイントにアクセス

                            // Response
                            model.Response = await OAuthProviderHelper.GetInstance()
                                .CallOAuthGetUserClaimsWebAPIAsync(model.AccessToken);
                        }
                        else
                        {
                            // ・・・
                        }

                        #endregion
                    }
                }

                // 画面の表示。
                ModelState.Clear();
                return View(model);
            }
            else
            {
                return View("Error");
            }
        }

        #endregion

        #region Implicitグラント種別

        /// <summary>
        /// Implicitグラント種別
        /// Access Token発行後のAccess Token利用画面を返す。
        /// Parameterは、Fragment以下のQueryStringとして返り、これをUserAgent側で処理する。
        /// 
        /// "・・・#access_token=XXXXX&state=YYYY&token_type=Bearer&expires_in=nnnn"
        /// 
        /// 色々調査した所、Fragmentは、ServerからをRedirect可能だが、
        /// Server Side CodeやDebug ProxyからではFragmentを捕捉できない模様。
        /// 従って、Fragmentは、UserAgent側でしか取得＆処理できない。
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#implicit-authz-resp"/>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult OAuthImplicitGrantClient()
        {
            if (!ASPNETIdentityConfig.IsLockedDownRedirectEndpoint)
            {
                // ココでstateの検証を予定していたが、コメントヘッダに有るように、ココでは実装できなかった。
                // stateは、JWTにnonce Claimとして格納してあるため、必要であれば、UserAgent側で検証できる。

                // Access Token利用画面を返す。
                return View();
            }
            else
            {
                return View("Error");
            }
        }

        #endregion

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

        /// <summary>RedirectToActionする。</summary>
        /// <param name="returnUrl">returnUrl</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        #endregion

        #region メアド検証、パスワード リセットのメール送信処理

        /// <summary>
        /// メアド検証、パスワード リセットで使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="isConfirmEmail_InsteadOf_PasswordReset">bool</param>
        private async void SendConfirmEmail(ApplicationUser user, bool isConfirmEmail_InsteadOf_PasswordReset)
        {
            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
            // アカウント確認とパスワード リセットを有効にする方法の詳細については、http://go.microsoft.com/fwlink/?LinkID=320771 を参照してください

            // Account Confirmation and Password Recovery with ASP.NET Identity (C#) | The ASP.NET Site
            // http://www.asp.net/identity/overview/features-api/account-confirmation-and-password-recovery-with-aspnet-identity

            string code;
            string callbackUrl;

            if (isConfirmEmail_InsteadOf_PasswordReset)
            {
                // メアド検証用のメールを送信
                code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);

                // URLの生成
                callbackUrl = this.Url.Action(
                        "EmailConfirmation", "Account",
                        new { userId = user.Id, code = code }, protocol: Request.Url.Scheme
                    );

                // E-mailの送信
                await UserManager.SendEmailAsync(
                        user.Id,
                        GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm),
                        string.Format(GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg), callbackUrl));
            }
            else
            {
                // パスワード リセット用のメールを送信
                code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);

                // URLの生成
                callbackUrl = Url.Action(
                        "ResetPassword", "Account",
                        new { userId = user.Id, code = code }, protocol: Request.Url.Scheme
                    );

                // E-mailの送信
                await UserManager.SendEmailAsync(
                        user.Id,
                        GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
                        string.Format(GetContentOfLetter.Get("PasswordResetMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset_msg), callbackUrl));
            }
        }

        #endregion

        #region ユーザとロールの初期化（テストコード）

        /// <summary>初期化処理のクリティカルセクション化</summary>
        private static SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        /// <summary>テストコード</summary>
        private static volatile bool HasCreated = false;

        /// <summary>
        /// manager.PasswordHasher = new CustomPasswordHasher();
        /// より後に動く処理の実装位置が不明だったので、巡り巡って
        /// MvcApplication(Global.asax).Application_Startからコチラに移動してきた。
        /// </summary>
        private async Task CreateData()
        {
            // ロックを取得する
            await _semaphoreSlim.WaitAsync();

            try
            {
                if (ASPNETIdentityConfig.UserStoreType == EnumUserStoreType.Memory)
                {
                    // Memory Providerの場合、
                    if (AccountController.HasCreated)
                    {
                        // 初期化済み。
                        return; // break;
                    }
                    else
                    {
                        // 未処理化
                        // continue;
                        AccountController.HasCreated = true; // 初期化済みに変更。
                    }
                }
                else if (ASPNETIdentityConfig.UserStoreType == EnumUserStoreType.SqlServer
                    || ASPNETIdentityConfig.UserStoreType == EnumUserStoreType.OracleMD
                    || ASPNETIdentityConfig.UserStoreType == EnumUserStoreType.PostgreSQL)
                {
                    // DBMS Providerの場合、
                    if (await UserStore.IsDBMSInitialized())
                    {
                        // 初期化済み。
                        return; // break;
                    }
                    else
                    {
                        // 未処理化
                        // continue;
                    }
                }

                #region 初期化コード

                ApplicationUser user = null;
                IdentityResult result = null;

                #region システム共通ロール

                await this.RoleManager.CreateAsync(ApplicationRole.CreateForCommon(name: ASPNETIdentityConst.Role_SystemAdmin));
                await this.RoleManager.CreateAsync(ApplicationRole.CreateForCommon(name: ASPNETIdentityConst.Role_Admin));
                await this.RoleManager.CreateAsync(ApplicationRole.CreateForCommon(name: ASPNETIdentityConst.Role_User));

                #endregion

                #region システム管理者ユーザ

                user = await ApplicationUser.CreateBySignup(ASPNETIdentityConfig.AdministratorUID, true);
                result = await this.UserManager.CreateAsync(user, ASPNETIdentityConfig.AdministratorPWD);
                if (result.Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(user.Id, ASPNETIdentityConst.Role_SystemAdmin);
                    await this.UserManager.AddToRoleAsync(user.Id, ASPNETIdentityConst.Role_User);
                    await this.UserManager.AddToRoleAsync(user.Id, ASPNETIdentityConst.Role_Admin);
                }

                #endregion

                #region テスト・ユーザ

                string password = ASPNETIdentityConfig.TestUserPWD;
                string parentId = "";

                if (ASPNETIdentityConfig.IsDebug
                    && !string.IsNullOrEmpty(password))
                {
                    #region 田中テナント

                    #region 管理者ユーザ

                    // 管理者ユーザを作成
                    user = await ApplicationUser.CreateBySignup("super_tanaka@gmail.com", true);
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("super_tanaka@gmail.com")).Id, ASPNETIdentityConst.Role_User);
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("super_tanaka@gmail.com")).Id, ASPNETIdentityConst.Role_Admin);
                    }

                    parentId = user.Id;

                    #endregion

                    #region 一般ユーザ

                    // 一般ユーザを作成
                    user = await ApplicationUser.CreateByRegister(parentId, "tanaka@gmail.com");
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("tanaka@gmail.com")).Id, ASPNETIdentityConst.Role_User);
                    }

                    #endregion

                    #region テナント・ロール

                    await this.RoleManager.CreateAsync(
                        ApplicationRole.CreateForIndividual((await this.UserManager.FindByNameAsync("super_tanaka@gmail.com")), "hyper_tanaka"));

                    #endregion

                    #endregion

                    #region 佐藤テナント

                    #region 管理者ユーザ

                    // 管理者ユーザを作成
                    user = await ApplicationUser.CreateBySignup("super_sato@gmail.com", true);
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("super_sato@gmail.com")).Id, ASPNETIdentityConst.Role_User);
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("super_sato@gmail.com")).Id, ASPNETIdentityConst.Role_Admin);
                    }

                    parentId = user.Id;

                    #endregion

                    #region 一般ユーザ

                    // 一般ユーザを作成
                    user = await ApplicationUser.CreateByRegister(parentId, "sato@gmail.com");
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("sato@gmail.com")).Id, ASPNETIdentityConst.Role_User);
                    }

                    #endregion

                    #region テナント・ロール

                    await this.RoleManager.CreateAsync(
                        ApplicationRole.CreateForIndividual((await this.UserManager.FindByNameAsync("super_sato@gmail.com")), "miracle_sato"));

                    #endregion

                    #endregion
                }

                #endregion

                #endregion
            }
            finally
            {
                // ロックを解放する。
                _semaphoreSlim.Release();
            }
        }

        #endregion

        #endregion
    }
}