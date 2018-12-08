//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountController
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
    /// <summary>AccountController</summary>
    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : MyBaseMVControllerCore
    {
        #region members & constructor

        #region members

        /// <summary>ErrorMessage</summary>
        [TempData]
        public string ErrorMessage { get; set; }

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
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="smsSender">ISmsSender</param>
        public AccountController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender)
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

        #endregion

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

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            string cmnPattern = "";

            #region ReturnUrl

            cmnPattern = "ReturnUrl=";

            string rawUrl = UriHelper.GetEncodedUrl(Request);
            
            if (string.IsNullOrEmpty(returnUrl)
                && rawUrl.IndexOf(cmnPattern) != -1)
            {
                if (rawUrl.Contains('&'))
                {
                    // 正規表現でreturnUrlを抜き出す。
                    string regexPattern = "(" + cmnPattern + ")(?<returnUrl>.+?)(\\&)";
                    returnUrl = CustomEncode.UrlDecode(Regex.Match(rawUrl, regexPattern).Groups["returnUrl"].Value);
                }
                else
                {
                    // IndexOf & SubstringでreturnUrlを抜き出す。
                    returnUrl = CustomEncode.UrlDecode(rawUrl.Substring(rawUrl.IndexOf(cmnPattern) + cmnPattern.Length));
                }
            }

            // ReturnUrl
            ViewBag.ReturnUrl = returnUrl;

            #endregion

            #region LoginHint

            string loginHint = "";
            cmnPattern = "login_hint=";

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (returnUrl.IndexOf(cmnPattern) != -1)
                {
                    // IndexOf & SubstringでloginHintを抜き出す。
                    loginHint = returnUrl.Substring(returnUrl.IndexOf(cmnPattern) + cmnPattern.Length);
                    if (loginHint.IndexOf('&') != -1)
                    {
                        loginHint = loginHint.Substring(0, loginHint.IndexOf('&'));
                    }
                }

                // ReturnUrl
                ViewBag.LoginHint = loginHint;
            }

            #endregion

            // サインイン画面（初期表示）
            string fido2Challenge = GetPassword.Generate(22, 0);
            HttpContext.Session.SetString("fido2Challenge", fido2Challenge);

            // サインアップしたユーザを取得
            if (Config.RequireUniqueEmail)
            {
                return View(new AccountLoginViewModel
                {
                    ReturnUrl = returnUrl,
                    Email = loginHint,
                    Fido2Challenge = fido2Challenge
                });
            }
            else
            {
                return View(new AccountLoginViewModel
                {
                    ReturnUrl = returnUrl,
                    Name = loginHint,
                    Fido2Challenge = fido2Challenge
                });
            }
        }

        /// <summary>
        /// サインイン画面でサインイン
        /// POST: /Account/Login
        /// </summary>
        /// <param name="model">LoginViewModel</param>
        /// <param name="submitButtonName">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(AccountLoginViewModel model, string submitButtonName)
        {
            // AccountLoginViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountLoginViewModelの検証に成功

                if (submitButtonName == "normal_signin")
                {
                    // 通常のサインイン

                    if (!string.IsNullOrWhiteSpace(model.Password))
                    {
                        string uid = "";
                        // サインアップしたユーザを取得
                        if (Config.RequireUniqueEmail)
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
                            ModelState.AddModelError("", Resources.AccountController.Login_Error);
                        }
                        else
                        {
                            // EmailConfirmedになっているか確認する。
                            if (await UserManager.IsEmailConfirmedAsync(user))
                            {
                                // EmailConfirmed == true の場合、
                                // パスワード入力失敗回数に基づいてアカウントがロックアウトされるように設定するには、lockoutOnFailure: true に変更する
                                Microsoft.AspNetCore.Identity.SignInResult result
                                    = await SignInManager.PasswordSignInAsync(
                                        userName: uid,                                                    // アカウント(UID)
                                        password: model.Password,                                         // アカウント(PWD)
                                        isPersistent: model.RememberMe,                                   // アカウント記憶
                                        lockoutOnFailure: Config.UserLockoutEnabledByDefault);            // ロックアウト

                                // SignInStatus
                                if (result.Succeeded)// == SignInResult.Success)
                                {
                                    // サインイン成功

                                    // テスト機能でSession["state"]のチェックを止めたので不要になった。
                                    // また、ManageControllerの方はログイン済みアクセスになるので。

                                    // AppScan指摘の反映
                                    this.FxSessionAbandon();
                                    // SessionIDの切換にはこのコードが必要である模様。
                                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                    Response.Cookies.Set(this.SessionCookieName, "");

                                    // オペレーション・トレース・ログ出力
                                    Logging.MyOperationTrace(string.Format("{0}({1}) has signed in.", user.Id, user.UserName));

                                    // Open-Redirect対策
                                    if (!string.IsNullOrEmpty(model.ReturnUrl)
                                        && Config.OAuth2AuthorizationServerEndpointsRootURI.IndexOf(model.ReturnUrl) != 1)
                                    {
                                        return RedirectToLocal(model.ReturnUrl);
                                    }
                                    else
                                    {
                                        return RedirectToAction("Index", "Home");
                                    }
                                }
                                else if (result.IsLockedOut)// == SignInResult.LockedOut)
                                {
                                    // ロックアウト
                                    return View("Lockout");
                                }
                                else if (result.RequiresTwoFactor)// == SignInResult.TwoFactorRequired)
                                {
                                    // EmailConfirmedとは別の2FAが必要。

                                    // 検証を求める（2FAなど）。
                                    if (user.Tokens == null)
                                    {
                                        // Email, SMS
                                        return this.RedirectToAction(
                                            "SendCode", new
                                            {
                                                ReturnUrl = model.ReturnUrl,  // 戻り先のURL
                                                RememberMe = model.RememberMe // アカウント記憶
                                            });
                                    }
                                    else
                                    {
                                        // TOTP
                                        return this.RedirectToAction(
                                            nameof(LoginWithTwoFactorAuthenticator),
                                            new { model.ReturnUrl, model.RememberMe });
                                    }
                                }
                                else if (result.IsNotAllowed)// == SignInResult.Failed)
                                {
                                    // サインイン失敗
                                }
                                else
                                {
                                    // その他
                                    // "無効なログイン試行です。"
                                    ModelState.AddModelError("", Resources.AccountController.Login_Error);
                                }
                            }
                            else
                            {
                                // EmailConfirmed == false の場合、

                                // メアド検証用のメールを送信して、
                                this.SendConfirmEmail(user);

                                // メッセージを設定
                                ModelState.AddModelError("", Resources.AccountController.Login_emailconfirm);
                            }
                        }
                    }
                    else
                    {
                        // パスワード入力が無い
                    }
                }
                else if (submitButtonName == "id_federation_signin")
                {
                    // ID連携のサインイン

                    string uid = "";
                    // サインアップしたユーザを取得
                    if (Config.RequireUniqueEmail)
                    {
                        uid = model.Email;
                    }
                    else
                    {
                        uid = model.Name;
                    }

                    // 認可エンドポイント
                    string oAuthAuthorizeEndpoint =
                    Config.OAuth2AuthorizationServerEndpointsRootURI
                    + Config.OAuth2AuthorizeEndpoint;

                    // client_id
                    string client_id = OAuth2AndOIDCParams.ClientID;
                    //OAuth2Helper.GetInstance().GetClientIdByName("IdFederation");

                    // state // 記号は入れない。
                    string state = GetPassword.Generate(10, 0);
                    HttpContext.Session.SetString("id_federation_signin_state", state);

                    // nonce // 記号は入れない。
                    string nonce = GetPassword.Generate(20, 0);
                    HttpContext.Session.SetString("id_federation_signin_nonce", state);

                    // ID連携に必要なscope
                    string scope = Const.IdFederationScopes;

                    return Redirect(
                        Config.IdFederationAuthorizeEndPoint +
                        "?client_id=" + client_id +
                        "&response_type=code" +
                        "&scope=" + scope +
                        "&state=" + state +
                        "&response_mode=form_post" +
                        "&login_hint=" + uid +
                        "&prompt=none");
                }
                else if (submitButtonName == "fido2_signin")
                {
                    // FIDO2のサインイン

                    //ApplicationUser user = await UserManager.FindByIdAsync(model.Fido2UserId);
                    ApplicationUser user = await UserManager.FindByNameAsync(model.Fido2UserId);

                    if (user == null)
                    {
                        // メッセージを設定
                        ModelState.AddModelError("", Resources.AccountController.Login_Error);
                    }
                    if (string.IsNullOrEmpty(user.FIDO2PublicKey))
                    {
                        // メッセージを設定
                        ModelState.AddModelError("", Resources.AccountController.Login_Error);
                    }
                    else
                    {
                        // EmailConfirmedだけでなく、ロックアウト、2FAについて検討が必要
                        if (await UserManager.IsEmailConfirmedAsync(user))
                        {
                            Microsoft.AspNetCore.Identity.SignInResult result;

                            // ロックアウト
                            if (user.LockoutEndDateUtc != null
                                && DateTime.Now <= user.LockoutEndDateUtc)
                            {
                                result = Microsoft.AspNetCore.Identity.SignInResult.LockedOut;
                            }
                            // 2FAは不要（デバイス特定されているため）
                            //else if (true) { }
                            else
                            {
                                string fido2Challenge = (string)HttpContext.Session.GetString("fido2Challenge");

                                //Debug.WriteLine("Windows Hello: ");
                                //Debug.WriteLine("publicKey: " + user.FIDO2PublicKey);
                                //Debug.WriteLine("challenge: " + fido2Challenge);
                                //Debug.WriteLine("clientData: " + model.Fido2ClientData);
                                //Debug.WriteLine("authenticatorData: " + model.Fido2AuthenticatorData);
                                //Debug.WriteLine("signature: " + model.Fido2Signature);

                                FIDO2.Helper fido2Helper = new FIDO2.Helper(user.FIDO2PublicKey, fido2Challenge);
                                if (fido2Helper.ValidateSignature(
                                    model.Fido2ClientData, model.Fido2AuthenticatorData, model.Fido2Signature))
                                {
                                    await SignInManager.SignInAsync(user, false); //, false);
                                    result = Microsoft.AspNetCore.Identity.SignInResult.Success;
                                }
                                else
                                {
                                    result = Microsoft.AspNetCore.Identity.SignInResult.Failed;
                                }
                            }

                            // SignInStatus
                            if (result == Microsoft.AspNetCore.Identity.SignInResult.Success)
                            {
                                // サインイン成功

                                // テスト機能でSession["state"]のチェックを止めたので不要になった。
                                // また、ManageControllerの方はログイン済みアクセスになるので。

                                // AppScan指摘の反映
                                this.FxSessionAbandon();
                                // SessionIDの切換にはこのコードが必要である模様。
                                // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                Response.Cookies.Set(this.SessionCookieName, "");

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format("{0}({1}) has signed in.", user.Id, user.UserName));

                                // Open-Redirect対策
                                if (!string.IsNullOrEmpty(model.ReturnUrl)
                                    && Config.OAuth2AuthorizationServerEndpointsRootURI.IndexOf(model.ReturnUrl) != 1)
                                {
                                    return RedirectToLocal(model.ReturnUrl);
                                }
                                else
                                {
                                    return RedirectToAction("Index", "Home");
                                }
                            }
                            else if (result == Microsoft.AspNetCore.Identity.SignInResult.Success)
                            {
                            }
                            else if (result == Microsoft.AspNetCore.Identity.SignInResult.LockedOut)
                            {
                                // ロックアウト
                                return View("Lockout");
                            }
                            else if (result == Microsoft.AspNetCore.Identity.SignInResult.Failed)
                            {
                                // サインイン失敗
                            }
                            else
                            {
                                // その他
                                // "無効なログイン試行です。"
                                ModelState.AddModelError("", Resources.AccountController.Login_Error);
                            }
                        }
                        else
                        {
                            // EmailConfirmed == false の場合、

                            // メアド検証用のメールを送信して、
                            this.SendConfirmEmail(user);

                            // メッセージを設定
                            ModelState.AddModelError("", Resources.AccountController.Login_emailconfirm);
                        }
                    }
                }
                else
                {
                    // 不明なボタン
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
                await SignInManager.SignOutAsync(); // DefaultAuthenticationTypes.ApplicationCookie);

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.GetUserAsync(User);
                Logging.MyOperationTrace(string.Format("{0}({1}) has signed out.", user.Id, user.UserName));
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
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> Register()
        {
            if (Config.EnableSignupProcess)
            {
                // データの生成
                await this.CreateData();

                // サインアップ画面（初期表示）
                return View(new AccountRegisterViewModel());
            }
            else
            {
                // エラー画面
                return View("Error");
            }
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
            if (Config.EnableSignupProcess)
            {
                // AccountRegisterViewModelの検証
                if (ModelState.IsValid)
                {
                    // AccountRegisterViewModelの検証に成功

                    string uid = "";
                    // サインアップしたユーザを取得
                    if (Config.RequireUniqueEmail)
                    {
                        // model.Emailはチェック済み。
                        uid = model.Email;
                    }
                    else
                    {
                        // model.Nameのカスタムのチェック処理は必要か？
                        uid = model.Name;
                    }

                    if (!string.IsNullOrWhiteSpace(uid))
                    {
                        // uidが空文字列でない場合。

                        #region サインアップ

                        // ユーザを作成
                        ApplicationUser user = ApplicationUser.CreateUser(uid, false);

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
                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format("{0}({1}) has signed up.", user.Id, user.UserName));

                            #region サインアップ成功

                            // ロールに追加。
                            if (result.Succeeded)
                            {
                                await this.UserManager.AddToRoleAsync(user, Const.Role_User);
                                await this.UserManager.AddToRoleAsync(user, Const.Role_Admin);
                            }

                            if (Config.RequireUniqueEmail)
                            {
                                // サインインの前にメアド検証用のメールを送信して、
                                this.SendConfirmEmail(user);

                                // VerifyEmailAddress画面へ遷移
                                return View("VerifyEmailAddress");
                            }
                            else
                            {
                                if (Config.DisplayAgreementScreen)
                                {
                                    // 約款あり
                                    // 約款画面を表示
                                    return View(
                                        "Agreement",
                                         new AccountAgreementViewModel
                                         {
                                             UserId = user.Id,
                                             Code = "dummy",
                                             Agreement = GetContentOfLetter.Get("Agreement", CustomEncode.UTF_8, null),
                                             AcceptedAgreement = false
                                         });
                                }
                                else
                                {
                                    // Login画面へ遷移
                                    return View("Login");
                                }
                            }

                            #endregion
                        }
                        else
                        {
                            #region サインアップ失敗

                            // サインアップ済みの可能性を探る
                            ApplicationUser oldUser = await UserManager.FindByNameAsync(uid);

                            if (oldUser == null)
                            {
                                // サインアップ済みでない。

                                // 作成(CreateAsync)に失敗
                                this.AddErrors(result);
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
                                    this.AddErrors(result);
                                    // 再表示
                                    return View(model);
                                }
                                else if (oldUser.Logins.Count != 0)
                                {
                                    // ExternalLogin済み。

                                    // 作成(CreateAsync)に失敗
                                    this.AddErrors(result);
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
                                            // メアド検証の再送について
                                            if (Config.RequireUniqueEmail)
                                            {
                                                // 再度、メアド検証

                                                // メアド検証用のメールを送信して、
                                                this.SendConfirmEmail(user);

                                                // VerifyEmailAddress
                                                //ViewBag.Link = callbackUrl;
                                                return View("VerifyEmailAddress");
                                            }
                                            else
                                            {
                                                if (Config.DisplayAgreementScreen)
                                                {
                                                    // 約款あり
                                                    // 約款画面を表示
                                                    return View(
                                                        "Agreement",
                                                         new AccountAgreementViewModel
                                                         {
                                                             UserId = user.Id,
                                                             Code = "dummy",
                                                             Agreement = GetContentOfLetter.Get("Agreement", CustomEncode.UTF_8, null),
                                                             AcceptedAgreement = false
                                                         });
                                                }
                                                else
                                                {
                                                    // Login画面へ遷移
                                                    return View("Login");
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // 再作成(CreateAsync)に失敗
                                            this.AddErrors(result);
                                            // 再表示
                                            return View(model);
                                        }
                                    }
                                    else
                                    {
                                        // 削除(DeleteAsync)に失敗
                                        this.AddErrors(result);
                                        // 再表示
                                        return View(model);
                                    }
                                }

                                #endregion
                            }


                            #endregion
                        }

                        #endregion
                    }
                    else
                    {
                        // uidが空文字列の場合。
                        // todo: 必要に応じて、エラーメッセージの表示を検討してください。
                    }
                }
                else
                {
                    // AccountRegisterViewModelの検証に失敗
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
            if (string.IsNullOrWhiteSpace(userId)
                || string.IsNullOrWhiteSpace(code))
            {
                // エラー画面
                return View("Error");
            }
            else
            {
                ApplicationUser user = await UserManager.FindByIdAsync(userId);

                if (Config.DisplayAgreementScreen)
                {
                    //　約款あり
                    if (user == null)
                    {
                        // 削除済み
                        // todo: 必要に応じて、エラーメッセージの表示を検討してください。
                    }
                    else if (user.EmailConfirmed)
                    {
                        // 確認済み
                        // todo: 必要に応じて、エラーメッセージの表示を検討してください。
                    }
                    else
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

                    // エラー画面
                    return View("Error");
                }
                else
                {
                    //　約款なし

                    // アクティベーション
                    IdentityResult result = await UserManager.ConfirmEmailAsync(user, code);

                    // メアド検証結果 ( "EmailConfirmation" or "Error"
                    if (result.Succeeded)
                    {
                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has confirmed.", user.Id, user.UserName));

                        return View("EmailConfirmation");
                    }
                    else
                    {
                        // エラー画面
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
            if (Config.DisplayAgreementScreen)
            {
                // AccountAgreementViewModelの検証
                if (ModelState.IsValid)
                {
                    // AccountAgreementViewModelの検証に成功

                    if (Config.RequireUniqueEmail)
                    {
                        if (model.AcceptedAgreement)
                        {
                            // 同意された。
                            ApplicationUser user = await UserManager.FindByIdAsync(model.UserId);

                            // アクティベーション
                            IdentityResult result = await UserManager.ConfirmEmailAsync(user, model.Code);

                            // メアド検証結果 ( "EmailConfirmation" or "Error"
                            if (result.Succeeded)
                            {
                                // メールの送信
                                this.SendRegisterCompletedEmail(user);

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format("{0}({1}) has been activated.", user.Id, user.UserName));

                                // 完了画面
                                return View("EmailConfirmation");
                            }
                            else
                            {
                                // 失敗
                                this.AddErrors(result);
                            }
                        }
                        else
                        {
                            // 同意されていない。
                            // todo: 必要に応じて、エラーメッセージの表示を検討してください。
                        }
                    }
                    else
                    {
                        if (model.AcceptedAgreement)
                        {
                            // 同意された。

                            // アクティベーション
                            ApplicationUser user = await UserManager.FindByIdAsync(model.UserId);
                            user.EmailConfirmed = true;
                            IdentityResult result = await UserManager.UpdateAsync(user);

                            if (result.Succeeded)
                            {
                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format("{0}({1}) has been activated.", user.Id, user.UserName));

                                // Login画面へ遷移
                                return View("Login");
                            }
                            else
                            {
                                // 失敗
                                this.AddErrors(result);
                            }
                        }
                        else
                        {
                            // 同意されていない。
                            // todo: 必要に応じて、エラーメッセージの表示を検討してください。
                        }
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
                    this.SendConfirmEmailForPasswordReset(user);

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
            if (string.IsNullOrWhiteSpace(userId)
                || string.IsNullOrWhiteSpace(code))
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
                ApplicationUser user = await UserManager.FindByIdAsync(model.UserId);
                IdentityResult result = await UserManager.ResetPasswordAsync(user, model.Code, model.Password);

                // 結果の確認
                if (result.Succeeded)
                {
                    // パスワードのリセットの成功

                    // メールの送信
                    this.SendPasswordResetCompletedEmail(user);

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format("{0}({1}) has reset own password.", user.Id, user.UserName));

                    // "パスワードのリセットの確認"画面を表示 
                    return View("ResetPasswordConfirmation");
                }
                else
                {
                    // パスワードのリセットの失敗

                    // 結果のエラー情報を追加
                    this.AddErrors(result);
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

        #region Email, SMS

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
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                // user == null

                // エラー
                return View("Error");
            }
            else
            {
                // user != null

                // UIDから、2FAのプロバイダを取得する。
                IList<string> userFactors = await UserManager.GetValidTwoFactorProvidersAsync(user);

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

                // 検証されたアカウントのUIDを取得
                ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                // Generate the token and send it
                // トークンを生成して送信します。
                string code = await UserManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);

                // Identity2.0 では、GenerateTwoFactorTokenAsyncの中で
                // 自動送信されていたが3.0では手動送信に変更された模様。
                if (model.SelectedProvider == "Email")
                {
                    await EmailSender.SendAsync(user.Email, "Two factor authentication code", code);
                }
                else
                {
                    await SmsSender.SendAsync(user.PhoneNumber, code);
                }

                if (!string.IsNullOrEmpty(code))
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
            // 検証されたアカウントのUIDを取得
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
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
                Microsoft.AspNetCore.Identity.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                    provider: model.Provider,                                  // 2FAプロバイダ
                    code: model.Code,                                          // 2FAコ－ド
                    isPersistent: model.RememberBrowser, // model.RememberMe,  // アカウント記憶 ( ・・・仕様として解り難いので、RememberBrowserを使用 )
                    rememberClient: model.RememberBrowser                      // ブラウザ記憶(2FA)
                    );

                // SignInStatus
                if (result.Succeeded)
                {
                    // サインイン成功

                    // AppScan指摘の反映
                    this.FxSessionAbandon();
                    // SessionIDの切換にはこのコードが必要である模様。
                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                    Response.Cookies.Set(this.SessionCookieName, "");

                    //// オペレーション・トレース・ログ出力 できない（User.Identity.GetUserId() == null
                    //ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    //Logging.MyOperationTrace(string.Format("{0}({1}) did 2fa sign in.", user.Id, user.UserName));

                    return RedirectToLocal(model.ReturnUrl);
                }
                else if (result.IsLockedOut)
                {
                    // ロックアウト
                    return View("Lockout");
                }
                else if (result.IsNotAllowed)
                {
                    // サインイン失敗
                    // その他 "無効なコード。"
                    ModelState.AddModelError("", Resources.AccountController.InvalidCode);
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

        #region TOTP

        #region With authenticator

        /// <summary>LoginWithTwoFactorAuthenticator</summary>
        /// <param name="rememberMe">bool</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult LoginWithTwoFactorAuthenticator(bool rememberMe, string returnUrl = null)
        {
            //// Ensure the user has gone through the username & password screen first
            //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            AccountLoginWithTwoFactorAuthenticatorViewModel model 
                = new AccountLoginWithTwoFactorAuthenticatorViewModel { RememberMe = rememberMe };

            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        /// <summary>LoginWithTwoFactorAuthenticator</summary>
        /// <param name="model">AccountLoginWithTwoFactorAuthenticatorViewModel</param>
        /// <param name="rememberMe">bool</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> LoginWithTwoFactorAuthenticator(
            AccountLoginWithTwoFactorAuthenticatorViewModel model,
            bool rememberMe, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                //// Ensure the user has gone through the username & password screen first
                //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                Microsoft.AspNetCore.Identity.SignInResult result
                    = await SignInManager.TwoFactorAuthenticatorSignInAsync(
                        model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty),
                        rememberMe, model.RememberMachine);

                if (result.Succeeded)
                {
                    //_logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                    return RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    //_logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    return RedirectToAction("Lockout");
                }
                else
                {
                    //_logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                    return View();
                }
            }
            else
            {
                return View(model);
            }
        }

        #endregion

        #region With recovery code

        /// <summary>LoginWithTwoFactorAuthenticatorRecoveryCode</summary>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult LoginWithTwoFactorAuthenticatorRecoveryCode(string returnUrl = null)
        {
            //// Ensure the user has gone through the username & password screen first
            //var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>LoginWithTwoFactorAuthenticatorRecoveryCode</summary>
        /// <param name="model">AccountLoginWithTwoFactorAuthenticatorRecoveryCodeViewModel</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithTwoFactorAuthenticatorRecoveryCode(
            AccountLoginWithTwoFactorAuthenticatorRecoveryCodeViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                //// Ensure the user has gone through the username & password screen first
                //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                Microsoft.AspNetCore.Identity.SignInResult result
                    = await SignInManager.TwoFactorRecoveryCodeSignInAsync(
                        model.RecoveryCode.Replace(" ", string.Empty));

                if (result.Succeeded)
                {
                    //_logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                    return RedirectToLocal(returnUrl);
                }
                if (result.IsLockedOut)
                {
                    //_logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    return RedirectToAction("Lockout");
                }
                else
                {
                    //_logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                    return View();
                }
            }
            else
            {
                return View(model);
            }
        }

        #endregion

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
            string redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return this.Challenge(properties, provider);
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
        /// <param name="remoteError">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl, string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                return RedirectToAction(nameof(Login));
            }

            // ManageControllerはサインイン後なので、uidが一致する必要がある。
            // AccountControllerはサインイン前なので、uidの一致は不要だが、
            // サインアップかどうかを判定して処理する必要がある。

            // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
            // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

            //// ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
            //AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
            // 外部ログイン・プロバイダからユーザに関する情報を取得する。
            ExternalLoginInfo externalLoginInfo = await SignInManager.GetExternalLoginInfoAsync();
            if (externalLoginInfo == null)
            {
                return RedirectToAction(nameof(Login));
            }

            IdentityResult idResult = null;
            Microsoft.AspNetCore.Identity.SignInResult siResult = null;

            // Sign in the user with this external login provider if the user already has a login.
            //siResult = await SignInManager.ExternalLoginSignInAsync(
            //    externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey,
            //    isPersistent: false, bypassTwoFactor: true);
            //if (siResult.Succeeded)
            //{

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
                    ApplicationUser user = await UserManager.FindByLoginAsync(
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

                        // SignInAsyncより、ExternalSignInAsyncが適切。

                        //// 通常のサインイン
                        //await SignInManager.SignInAsync(

                        // 既存の外部ログイン・プロバイダでサインイン
                        siResult = await SignInManager.ExternalLoginSignInAsync(
                            externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey,
                            isPersistent: false, bypassTwoFactor: true); // 外部ログインの Cookie 永続化は常に false.

                        // AppScan指摘の反映
                        this.FxSessionAbandon();
                        // SessionIDの切換にはこのコードが必要である模様。
                        // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                        Response.Cookies.Set(this.SessionCookieName, "");

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

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
                            if (Config.RequireUniqueEmail)
                            {
                                idResult = await UserManager.AddLoginAsync(user, externalLoginInfo);
                            }
                            else
                            {
                                if (email == user.Email)
                                {
                                    // メアドも一致
                                    idResult = await UserManager.AddLoginAsync(user, externalLoginInfo);
                                }
                                else
                                {
                                    // メアド不一致
                                    idResult = new IdentityResult();
                                }
                            }

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
                                // SignInAsync、ExternalSignInAsync
                                // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                await SignInManager.SignInAsync(
                                    user,
                                    isPersistent: false);//,  // rememberMe は false 固定（外部ログインの場合）
                                    //rememberBrowser: true); // rememberBrowser は true 固定

                                // AppScan指摘の反映
                                this.FxSessionAbandon();
                                // SessionIDの切換にはこのコードが必要である模様。
                                // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                Response.Cookies.Set(this.SessionCookieName, "");

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                                // リダイレクト
                                return RedirectToLocal(returnUrl);
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
                            // サインアップ済みでない → サインアップから行なう。
                            // If the user does not have an account, then prompt the user to create an account
                            // ユーザがアカウントを持っていない場合、アカウントを作成するようにユーザに促します。
                            ViewBag.ReturnUrl = returnUrl;
                            ViewBag.LoginProvider = externalLoginInfo.LoginProvider;

                            // 外部ログイン プロバイダのユーザー情報でユーザを作成
                            // uid = 連携先メアドの場合、E-mail confirmationはしない（true）。
                            user = ApplicationUser.CreateUser(uid, true);

                            // サインアップ時のみ、メアドも追加
                            //（RequireUniqueEmail = false時を想定）
                            user.Email = email;
                            user.EmailConfirmed = true;

                            // ユーザの新規作成（パスワードは不要）
                            idResult = await UserManager.CreateAsync(user);

                            // 結果の確認
                            if (idResult.Succeeded)
                            {
                                // ユーザの新規作成が成功した場合

                                // 外部ログイン（ = idClaim）の追加
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

                                // 結果の確認
                                if (idResult.Succeeded)
                                {
                                    // 外部ログインの追加に成功した場合 → サインイン

                                    // SignInAsync、ExternalSignInAsync
                                    // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                    await SignInManager.SignInAsync(
                                       user: user,
                                       isPersistent: false);//,  // rememberMe は false 固定（外部ログインの場合）
                                       //rememberBrowser: true); // rememberBrowser は true 固定
                                       
                                    // AppScan指摘の反映
                                    this.FxSessionAbandon();
                                    // SessionIDの切換にはこのコードが必要である模様。
                                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                                    Response.Cookies.Set(this.SessionCookieName, "");

                                    // オペレーション・トレース・ログ出力
                                    Logging.MyOperationTrace(string.Format("{0}({1}) has signed up with a verified external account.", user.Id, user.UserName));

                                    // リダイレクト
                                    return RedirectToLocal(returnUrl);
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
                                // ユーザの新規作成が失敗した場合

                                // 結果のエラー情報を追加
                                this.AddErrors(idResult);
                            } // else処理済
                        } // else処理済
                    } // else処理済
                    
                } // クレーム情報（e-mail, name情報）を取得できなかった。
            } // クレーム情報（ID情報）を取得できなかった。
            //} // ログイン情報を取得できなかった。

            // ログイン情報を受け取れなかった場合や、その他の問題が在った場合。
            return View("ExternalLoginFailure");
        }

        #endregion

        #endregion

        #region ID連携

        /// <summary>
        /// IDFederationRedirectEndPoint
        /// OIDC, response_type=code, response_mode=form_post
        /// </summary>
        /// <param name="code">仲介コード</param>
        /// <param name="state">state</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-resp"/>
        /// <seealso cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req"/>
        [AllowAnonymous]
        public async Task<ActionResult> IDFederationRedirectEndPoint(string code, string state)
        {
            if (!Config.IsLockedDownRedirectEndpoint)
            {
                // 結果を格納する変数。
                Dictionary<string, string> dic = null;
                OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                {
                    State = state,
                    Code = code
                };

                //  client_Idから、client_secretを取得。
                string client_id = OAuth2AndOIDCParams.ClientID;
                //OAuth2Helper.GetInstance().GetClientIdByName("IdFederation");
                string client_secret = OAuth2AndOIDCParams.ClientSecret;
                //OAuth2Helper.GetInstance().GetClientSecret(client_id);

                // stateの検証
                if (state == (string)HttpContext.Session.GetString("id_federation_signin_state"))
                {
                    // state正常
                    HttpContext.Session.SetString("id_federation_signin_state", ""); // 誤動作防止

                    #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri = Config.IdFederationRedirectEndPoint;

                    // Tokenエンドポイントにアクセス
                    model.Response = await Helper.GetInstance()
                        .GetAccessTokenByCodeAsync(
                             new Uri(Config.IdFederationTokenEndPoint),
                            client_id, client_secret, redirect_uri, code, "");

                    #endregion

                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    #region id_tokenの検証コード

                    string sub = "";
                    List<string> roles = null;
                    List<string> scopes = null;
                    JObject jobj = null;

                    if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                    {
                        // id_tokenがある。
                        string id_token = dic[OAuth2AndOIDCConst.IDToken];

                        if (AccessToken.Verify(id_token, out sub, out roles, out scopes, out jobj)
                            && jobj[OAuth2AndOIDCConst.nonce].ToString() == (string)HttpContext.Session.GetString("id_federation_signin_nonce"))
                        {
                            // id_token検証OK。
                        }
                        else
                        {
                            // id_token検証NG。
                            return View("Error");
                        }

                        HttpContext.Session.SetString("id_federation_signin_nonce", ""); // 誤動作防止                            
                    }
                    else
                    {
                        // id_tokenがない。
                        return View("Error");
                    }

                    #endregion

                    #region /userinfoエンドポイント
                    //// /userinfoエンドポイントにアクセスする場合
                    //string response = await OAuth2AndOIDCClient.CallUserInfoEndpointAsync(
                    //    new Uri(Config.IdFederationUserInfoEndPoint), dic[OAuth2AndOIDCConst.AccessToken]);
                    #endregion

                    #region ユーザの登録・更新

                    // {
                    //     "aud": " = ClientID", 
                    //     "email": "e-mail address", 
                    //     "email_verified": "True or False", 
                    //     "exp": "nnnnnnnnnn", 
                    //     "iat": "nnnnnnnnnn", 
                    //     "iss": "http://jwtssoauth.opentouryo.com", 
                    //     "nonce": "xxxxxxxx", 
                    //     "phone_number": "xxxxxxxx", 
                    //     "phone_number_verified": "True or False", 
                    //     "sub": "uid", 
                    //     "userid": "・・・guid・・・"
                    //     "parentid": "・・・guid・・・"
                    //     "roles": [
                    //         "aaa", 
                    //         "bbb", 
                    //         "ccc"
                    //     ], 
                    // }

                    IdentityResult result = null;
                    ApplicationUser user = await UserManager.FindByIdAsync((string)jobj[OAuth2AndOIDCConst.Scope_UserID]);

                    if (user == null)
                    {
                        // 新規作成
                        user = new ApplicationUser()
                        {
                            Id = (string)jobj[OAuth2AndOIDCConst.Scope_UserID],

                            UserName = sub,

                            Email = (string)jobj[OAuth2AndOIDCConst.Scope_Email],
                            EmailConfirmed = (bool)Convert.ToBoolean((string)jobj[OAuth2AndOIDCConst.email_verified]),

                            PhoneNumber = (string)jobj[OAuth2AndOIDCConst.phone_number],
                            PhoneNumberConfirmed = (bool)Convert.ToBoolean((string)jobj[OAuth2AndOIDCConst.phone_number_verified]),

                            CreatedDate = DateTime.Now
                        };

                        result = await UserManager.CreateAsync(user);

                        // Roles(追加)
                        foreach (string roleName in roles)
                        {
                            await this.UserManager.AddToRoleAsync(user, roleName);
                        }
                    }
                    else
                    {
                        // 属性更新
                        user.UserName = sub;

                        user.Email = (string)jobj[OAuth2AndOIDCConst.Scope_Email];
                        user.EmailConfirmed = (bool)Convert.ToBoolean((string)jobj[OAuth2AndOIDCConst.email_verified]);

                        user.PhoneNumber = (string)jobj[OAuth2AndOIDCConst.phone_number];
                        user.PhoneNumberConfirmed = (bool)Convert.ToBoolean((string)jobj[OAuth2AndOIDCConst.phone_number_verified]);

                        result = await UserManager.UpdateAsync(user);

                        // Roles
                        IList<string> currentRoles = await UserManager.GetRolesAsync(user);

                        // 追加
                        foreach (string roleName in roles)
                        {
                            if (currentRoles.Any(x => x == roleName))
                            {
                                // currentにある ---> 何もしない
                            }
                            else
                            {
                                // currentにない ---> 追加
                                await this.UserManager.AddToRoleAsync(user, roleName);
                            }
                        }

                        // 削除
                        foreach (string roleName in currentRoles)
                        {
                            if (roles.Any(x => x == roleName))
                            {
                                // 連携先にある ---> 何もしない
                            }
                            else
                            {
                                // 連携先にない ---> 削除
                                await this.UserManager.RemoveFromRoleAsync(user, roleName);
                            }
                        }
                    }

                    #region サインイン

                    if (result.Succeeded == true)
                    {
                        // EmailConfirmed == true の場合、
                        // パスワード入力失敗回数に基づいてアカウントがロックアウトされるように設定するには、shouldLockout: true に変更する
                        await SignInManager.SignInAsync(user, isPersistent: false);//, rememberBrowser: false);

                        // AppScan指摘の反映
                        this.FxSessionAbandon();
                        // SessionIDの切換にはこのコードが必要である模様。
                        // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                        Response.Cookies.Set(this.SessionCookieName, "");

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a id federation.", user.Id, user.UserName));
                    }

                    #endregion

                    return RedirectToAction("Index", "Home");

                    #endregion
                }
                else
                {
                    // state異常
                    return View("Error");
                }
            }
            else
            {
                return View("Error");
            }
        }

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
        /// <param name="nonce">nonce（OIDC）</param>
        /// <param name="prompt">認可画面の扱い</param>
        /// <param name="code_challenge">OAuth PKCE</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpGet]
        public async Task<ActionResult> OAuth2Authorize(string response_type, string client_id, string scope, string state,
            string nonce, string prompt, // OpenID Connect
            string code_challenge, string code_challenge_method) // OAuth PKCE
        {
            // 何らかの方法でidentityを取得
            ClaimsIdentity identity = null;

            // scopeパラメタ
            string[] scopes = (scope ?? "").Split(' ');

            if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
            {
                // Authorization Codeグラント種別（仲介コードの発行）
                ViewBag.Name = ""; //identity.Name;
                ViewBag.Scopes = scopes;

                // 認証の場合、余計なscopeをfilterする。
                bool isAuth = scopes.Any(x => x.ToLower() == OAuth2AndOIDCConst.Scope_Auth);

                if (string.IsNullOrWhiteSpace(prompt)) prompt = "";

                if (isAuth                           // OAuth2 拡張仕様
                    || prompt.ToLower() == "none")   // OIDC   RFC仕様
                                                     // OIDC Hybrid Flowはresponse_type=codeに書換、識別できないので、prompt=noneを設定。
                {
                    // 認可画面をスキップ

                    // アクセス要求を保存して、仲介コードを発行する。
                    
                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    // ただし、認可画面をスキップする場合は、scopeをフィルタする。
                    if (isAuth)
                    {
                        scopes = Helper.FilterClaimAtAuth(scopes).ToArray();
                    }

                    Helper.AddClaim(identity, client_id, state, scopes, nonce);

                    // 仲介コードを発行

                    // オペレーション・トレース・ログ出力
                    ApplicationUser user = await UserManager.GetUserAsync(User);
                    Logging.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of auth by {2}({3}).",
                        user.Id, user.UserName, client_id, Helper.GetInstance().GetClientName(client_id)));

                    // RedirectエンドポイントへRedirect
                    return new EmptyResult();
                }
                else
                {
                    // アクセス要求の許可/拒否を訪ねるViewを表示
                    return View();
                }
            }
            else if ((response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType))
            // OIDC Implicit Flowはresponse_type=tokenに書換、識別できないので、prompt=noneを設定。
            {
                // Implicitグラント種別（Access Tokenの発行）
                if (scopes.Any(x => x.ToLower() == OAuth2AndOIDCConst.Scope_Auth))
                {
                    // authの場合、Implicitグラント種別はNGとする。
                }
                else
                {
                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    Helper.AddClaim(identity, client_id, state, scopes, nonce);

                    // Access Tokenを発行

                    // オペレーション・トレース・ログ出力
                    ApplicationUser user = await UserManager.GetUserAsync(User);
                    Logging.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of token by {2}({3}).",
                            user.Id, user.UserName, client_id, Helper.GetInstance().GetClientName(client_id)));
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
        /// <param name="nonce">nonce（OIDC）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuth2Authorize(string client_id, string scope, string state, string nonce)
        {
            // 何らかの方法でidentityを取得
            ClaimsIdentity identity = null;

            // 次に、アクセス要求を保存して、仲介コードを発行する。

            // scopeパラメタ
            string[] scopes = (scope ?? "").Split(' ');

            if (!string.IsNullOrEmpty(Request.Form["submit.Login"]))
            {
                // 別のアカウントでログイン
                //（サインアウトしてリダイレクト）
                await SignInManager.SignOutAsync();
                return new RedirectResult(UriHelper.GetEncodedUrl(Request));
            }
            else if (!string.IsNullOrEmpty(Request.Form["submit.Grant"]))
            {
                // アクセス要求を保存して、仲介コードを発行する。
                
                // ClaimsIdentityに、その他、所定のClaimを追加する。
                Helper.AddClaim(identity, client_id, state, scopes, nonce);

                // 仲介コードを発行

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.GetUserAsync(User);
                Logging.MyOperationTrace(string.Format("{0}({1}) passed the authorization endpoint of code by {2}({3}).",
                        user.Id, user.UserName, client_id, Helper.GetInstance().GetClientName(client_id)));

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
        [AllowAnonymous]
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient(string code, string state)
        {
            #region テスト用

            IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            // state
            string state_InSessionOrCookie = (string)HttpContext.Session.GetString("test_state");
            if (string.IsNullOrEmpty(state_InSessionOrCookie))
            {
                state_InSessionOrCookie = requestCookies.Get("test_state");
            }

            // nonce
            string nonce_InSessionOrCookie = (string)HttpContext.Session.GetString("test_nonce");
            if (string.IsNullOrEmpty(nonce_InSessionOrCookie))
            {
                nonce_InSessionOrCookie = requestCookies.Get("test_nonce");
            }

            // code_verifier
            string code_verifier_InSessionOrCookie = (string)HttpContext.Session.GetString("test_code_verifier");
            if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
            {
                code_verifier_InSessionOrCookie = requestCookies.Get("test_code_verifier");
            }

            // クリア
            HttpContext.Session.SetString("test_state", null);
            responseCookies.Set("test_state", "");
            HttpContext.Session.SetString("test_code_verifier", null);
            responseCookies.Set("test_code_verifier", "");

            #endregion

            if (!Config.IsLockedDownRedirectEndpoint)
            {
                // Tokenエンドポイントにアクセス
                Uri tokenEndpointUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.OAuth2BearerTokenEndpoint);

                // 結果を格納する変数。
                Dictionary<string, string> dic = null;
                OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                {
                    State = state,
                    Code = code
                };

                //  client_Idから、client_secretを取得。
                string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
                string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                //stateの検証
                if (state == state_InSessionOrCookie
                    || state == "fapi1:" + state_InSessionOrCookie)
                {
                    //state正常

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri
                    = Config.OAuth2ClientEndpointsRootURI
                    + Config.OAuth2AuthorizationCodeGrantClient_Account;

                    // Tokenエンドポイントにアクセス
                    if (!state.StartsWith("fapi1:"))
                    {
                        if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
                        {
                            // 通常
                            model.Response = await Helper.GetInstance()
                                .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                client_id, client_secret, redirect_uri, code);
                        }
                        else
                        {
                            // PKCE
                            model.Response = await Helper.GetInstance()
                               .GetAccessTokenByCodeAsync(tokenEndpointUri,
                               client_id, client_secret, redirect_uri,
                               code, code_verifier_InSessionOrCookie);
                        }
                    }
                    else
                    {
                        // FAPI1

                        // Tokenエンドポイントにアクセス
                        string aud = Config.OAuth2AuthorizationServerEndpointsRootURI
                                 + Config.OAuth2BearerTokenEndpoint;

                        // ClientNameから、client_id(iss)を取得。
                        string iss = "";

                        // Client Accountのみ
                        iss = Helper.GetInstance().GetClientIdByName("TestClient");

                        // テストなので秘密鍵は共通とする。
                        string privateKey = OAuth2AndOIDCParams.OAuth2JwtAssertionPrivatekey;
                        privateKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(privateKey), CustomEncode.us_ascii);

                        model.Response = await Helper.GetInstance().GetAccessTokenByCodeAsync(
                            tokenEndpointUri, redirect_uri, code, JwtAssertion.CreateJwtBearerTokenFlowAssertionJWK(
                                iss, aud, new TimeSpan(0, 0, 30), Const.StandardScopes, privateKey));
                    }

                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken];
                    model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                           CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);

                    // 余談：OpenID Connectであれば、ここで id_token 検証。                    
                    if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                    {
                        model.IdToken = dic[OAuth2AndOIDCConst.IDToken];
                        model.IdTokenJwtToJson = CustomEncode.ByteToString(
                            CustomEncode.FromBase64UrlString(model.IdToken.Split('.')[1]), CustomEncode.UTF_8);
                    }

                    model.RefreshToken = dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken) ? dic[OAuth2AndOIDCConst.RefreshToken] : "";
                }
                else
                {
                    // state異常
                }

                #region 各種Token検証

                string out_sub = "";
                JObject out_jobj = null;

                if (!string.IsNullOrEmpty(model.AccessToken))
                {
                    List<string> out_roles = null;
                    List<string> out_scopes = null;

                    if (!AccessToken.Verify(model.AccessToken, out out_sub, out out_roles, out out_scopes, out out_jobj))
                    {
                        throw new Exception("AccessToken検証エラー");
                    }
                }

                if (!string.IsNullOrEmpty(model.IdToken))
                {
                    string out_nonce = "";

                    if (!IdToken.Verify(model.IdToken, model.AccessToken, code, state, out out_sub, out out_nonce, out out_jobj)
                        && out_nonce == nonce_InSessionOrCookie)
                    {
                        throw new Exception("IdToken検証エラー");
                    }
                }

                #endregion

                #endregion

                // 画面の表示。
                return View(model);
            }
            else
            {
                // エラー
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
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient2(OAuth2AuthorizationCodeGrantClientViewModel model)
        {
            if (!Config.IsLockedDownRedirectEndpoint)
            {
                // AccountVerifyCodeViewModelの検証
                if (ModelState.IsValid)
                {
                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;

                    if (!string.IsNullOrEmpty(Request.Form["submit.GetUserClaims"]))
                    {
                        // UserInfoエンドポイントにアクセス
                        model.Response = await Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Refresh"]))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI
                            + Config.OAuth2BearerTokenEndpoint);

                        // Tokenエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().
                            UpdateAccessTokenByRefreshTokenAsync(
                            tokenEndpointUri, client_id, client_secret, model.RefreshToken);
                        dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                        if (dic.ContainsKey(OAuth2AndOIDCConst.AccessToken))
                        {
                            model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken];
                            model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                                CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);
                        }

                        if (dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken))
                        {
                            model.RefreshToken = dic[OAuth2AndOIDCConst.RefreshToken] ?? "";
                        }

                        #endregion
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.RevokeAccess"])
                        || !string.IsNullOrEmpty(Request.Form["submit.RevokeRefresh"]))
                    {
                        #region Revokeエンドポイントで、Tokenを無効化

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form["submit.RevokeAccess"]))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form["submit.RevokeRefresh"]))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri revokeTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI
                            + Config.OAuth2RevokeTokenWebAPI);

                        // Revokeエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().RevokeTokenAsync(
                            revokeTokenEndpointUri, client_id, client_secret, token, token_type_hint);

                        #endregion
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectAccess"])
                        || !string.IsNullOrEmpty(Request.Form["submit.IntrospectRefresh"]))
                    {
                        #region Introspectエンドポイントで、Token情報を取得

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectAccess"]))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form["submit.IntrospectRefresh"]))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri introspectTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI
                            + Config.OAuth2IntrospectTokenWebAPI);

                        // Introspectエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
                        string client_secret = Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Helper.GetInstance().IntrospectTokenAsync(
                            introspectTokenEndpointUri, client_id, client_secret, token, token_type_hint);

                        #endregion
                    }
                    else
                    {
                        // ・・・
                    }
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
        public ActionResult OAuth2ImplicitGrantClient()
        {
            if (!Config.IsLockedDownRedirectEndpoint)
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

        #region Helper

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

        /// <summary>
        /// ModelStateDictionaryに
        /// IEnumerable(string)の情報を移送
        /// </summary>
        /// <param name="errors">IEnumerable<string></param>
        private void AddErrors(IEnumerable<string> errors)
        {
            foreach (string error in errors)
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
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion

        #region
        
        #region メール送信処理

        #region メアド検証、パスワード リセット

        /// <summary>
        /// メアド検証で使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendConfirmEmail(ApplicationUser user)
        {
            string code;
            string callbackUrl;

            // メアド検証用のメールを送信
            code = await UserManager.GenerateEmailConfirmationTokenAsync(user);

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Account",
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

            // E-mailの送信
            string subject = GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm);
            string body = GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg);
            await EmailSender.SendAsync(user.Email, subject, string.Format(body, callbackUrl, user.UserName));
        }

        /// <summary>
        /// パスワード リセットで使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendConfirmEmailForPasswordReset(ApplicationUser user)
        {
            string code;
            string callbackUrl;

            // パスワード リセット用のメールを送信
            code = await UserManager.GeneratePasswordResetTokenAsync(user);

            // URLの生成
            callbackUrl = Url.Action(
                    "ResetPassword", "Account",
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme
                );

            // E-mailの送信
            await EmailSender.SendAsync(
                    user.Email, GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
                    string.Format(GetContentOfLetter.Get("PasswordResetMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset_msg), callbackUrl));
        }

        #endregion

        #region 完了メール送信処理

        /// <summary>
        /// アカウント登録の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendRegisterCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            await EmailSender.SendAsync(
                user.Email, GetContentOfLetter.Get("RegistationWasCompletedEmailTitle", CustomEncode.UTF_8, ""), 
                string.Format(GetContentOfLetter.Get("RegistationWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        /// <summary>
        /// パスワード リセットの完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendPasswordResetCompletedEmail(ApplicationUser user)
        {
            // パスワード リセット用のメールを送信
            await EmailSender.SendAsync(
                user.Email, GetContentOfLetter.Get("PasswordResetWasCompletedEmailTitle", CustomEncode.UTF_8, ""),
                string.Format(GetContentOfLetter.Get("PasswordResetWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        #endregion

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
                if (OnlySts.STSOnly_P)
                {
                    // STS専用モードなので。
                    return; // break;
                }

                if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    // Memory Providerの場合、
                    if (AccountController.HasCreated)
                    {
                        // 初期化済み。
                        return; // break;
                    }
                    else
                    {
                        AccountController.HasCreated = true; // 初期化済みに変更。
                    }
                }
                else if (Config.UserStoreType == EnumUserStoreType.SqlServer
                    || Config.UserStoreType == EnumUserStoreType.ODPManagedDriver
                    || Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                {
                    // DBMS Providerの場合、
                    if (await DataAccess.IsDBMSInitialized())
                    {
                        // 初期化済み。
                        return; // break;
                    }
                }

                #region 初期化コード

                ApplicationUser user = null;
                IdentityResult result = null;

                #region ロール

                await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_SystemAdmin });
                await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_Admin });
                await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_User });

                #endregion

                #region 管理者ユーザ

                user = ApplicationUser.CreateUser(Config.AdministratorUID, true);
                result = await this.UserManager.CreateAsync(user, Config.AdministratorPWD);
                if (result.Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(user, Const.Role_SystemAdmin);
                    await this.UserManager.AddToRoleAsync(user, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(user, Const.Role_Admin);
                }

                #endregion

                #region テスト・ユーザ

                string password = Config.TestUserPWD;

                if (Config.IsDebug
                    && !string.IsNullOrWhiteSpace(password))
                {
                    // 管理者ユーザを作成
                    user = ApplicationUser.CreateUser("super_tanaka@gmail.com", true);

                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            await this.UserManager.FindByNameAsync("super_tanaka@gmail.com"), Const.Role_User);
                        await this.UserManager.AddToRoleAsync(
                            await this.UserManager.FindByNameAsync("super_tanaka@gmail.com"), Const.Role_Admin);
                    }

                    // 一般ユーザを作成
                    user = ApplicationUser.CreateUser("tanaka@gmail.com", true);
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            await this.UserManager.FindByNameAsync("tanaka@gmail.com"), Const.Role_User);
                    }

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

        #endregion

        #endregion

        #region hoge
        /*
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return View();
            }
        }
        */
        #endregion
    }
}
