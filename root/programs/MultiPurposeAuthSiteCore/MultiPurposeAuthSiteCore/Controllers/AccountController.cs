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

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
//using MultiPurposeAuthSite.Models.AccountViewModels;
using MultiPurposeAuthSite.Data;
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
        /// <summary>IEmailSender</summary>
        private IEmailSender _emailSender = null;
        /// <summary>ILogger</summary>
        private ILogger _logger = null;
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="logger">ILogger</param>
        public AccountController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
            // SignInManager
            this._signInManager = signInManager;
            // IEmailSender
            this._emailSender = emailSender;
            // ILogger
            this._logger = logger;
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

        /// <summary>IEmailSender</summary>
        private IEmailSender EmailSender
        {
            get
            {
                return this._emailSender;
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
                                    return this.RedirectToAction(
                                        "SendCode", new
                                        {
                                            ReturnUrl = model.ReturnUrl,  // 戻り先のURL
                                                RememberMe = model.RememberMe // アカウント記憶
                                        });
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
                ApplicationUser user = await UserManager.FindByNameAsync(User.Identity.Name);
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
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme 
                );

            // E-mailの送信
            string subject = GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm);
            string body = GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg);
            await EmailSender.SendAsync(user.Id, subject, string.Format(body, callbackUrl, user.UserName));
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
                    user.Id,
                    GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
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
                GetContentOfLetter.Get("RegistationWasCompletedEmailTitle", CustomEncode.UTF_8, ""), user.Email,
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
                GetContentOfLetter.Get("PasswordResetWasCompletedEmailTitle", CustomEncode.UTF_8, ""), user.Email,
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
        
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToAction(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["LoginProvider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(nameof(ExternalLogin), model);
        }
        */
        #endregion
    }
}
