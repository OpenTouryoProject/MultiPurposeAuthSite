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
//*  2018/11/30  西野 大介         新規
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/02/28  西野 大介         エラーメッセージ通知の改善
//*  2020/03/04  西野 大介         CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2020/11/12  西野 大介         SameSiteCookie対応 (.NET Fx側は対策不要)
//*  2020/12/21  西野 大介         Device AuthZ対応実施
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
using Token = MultiPurposeAuthSite.TokenProviders;
using Saml = MultiPurposeAuthSite.SamlProviders;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;

using System.Web;

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

using Fido2NetLib;
using Fido2NetLib.Objects;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>AccountController</summary>
    [Authorize]
    public class AccountController : MyBaseMVControllerCore
    {
        #region members & constructor

        #region members

        /// <summary>ErrorMessage</summary>
        [TempData]
        public string ErrorMessage { get; set; }

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

        #endregion

        #endregion

        #region Action Method

        #region IdP (Identity Provider)

        /// <summary>InitSessionAfterlogin</summary>
        private void InitSessionAfterlogin()
        {
            // AppScan指摘の反映
            this.FxSessionAbandon();
            // SessionIDの切換にはこのコードが必要である模様。
            // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
            Response.Cookies.Set(this.SessionCookieName, "", this._cookieOptions);
            Response.Cookies.Set(OAuth2AndOIDCConst.auth_time,
                FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
        }

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
            string fido2Challenge = "";
            string sequenceNo = "";

            if (Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
            {
                sequenceNo = "0";
            }
            else if (Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
            {
                fido2Challenge = GetPassword.Generate(22, 0);
                HttpContext.Session.SetString("fido2Challenge", fido2Challenge);
            }

            // サインアップしたユーザを取得
            if (Config.RequireUniqueEmail)
            {
                return View(new AccountLoginViewModel
                {
                    ReturnUrl = returnUrl,
                    Email = loginHint,
                    Fido2Data = fido2Challenge,
                    SequenceNo = sequenceNo
                });
            }
            else
            {
                return View(new AccountLoginViewModel
                {
                    ReturnUrl = returnUrl,
                    Name = loginHint,
                    Fido2Data = fido2Challenge,
                    SequenceNo = sequenceNo
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
            AspNetId.SignInResult signInStatus = AspNetId.SignInResult.Failed;

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
                                signInStatus = await SignInManager.PasswordSignInAsync(
                                    userName: uid,                                      // アカウント(UID)
                                    password: model.Password,                           // アカウント(PWD)
                                    isPersistent: model.RememberMe,                     // アカウント記憶
                                    lockoutOnFailure: Config.UserLockoutEnabledByDefault); // ロックアウト

                                return VerifySignInStatus(signInStatus, model, user);
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

                    // redirect_uri
                    string redirect_uri = Config.IdFederationRedirectEndPoint;

                    // nonce // 記号は入れない。
                    string nonce = GetPassword.Generate(20, 0);
                    HttpContext.Session.SetString("id_federation_signin_nonce", nonce);

                    // ID連携に必要なscope
                    string scope = Const.IdFederationScopes;

                    return Redirect(
                        Config.IdFederationAuthorizeEndPoint +
                        "?client_id=" + client_id +
                        "&response_type=code" +
                        "&scope=" + scope +
                        "&state=" + state +
                        "&nonce=" + nonce +
                        "&redirect_uri=" + CustomEncode.UrlEncode(redirect_uri) +
                        "&response_mode=form_post" +
                        "&login_hint=" + uid + "&prompt=none");
                }
                else if (submitButtonName == "webauthn_signin"
                    && Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                {
                    // WebAuthnのサインイン
                    if (model.SequenceNo == "0")
                    {
                        AssertionOptions options = null;
                        JObject requestJSON = JsonConvert.DeserializeObject<JObject>(model.Fido2Data);

                        string username = (string)requestJSON["username"];
                        string userVerification = (string)requestJSON["userVerification"];
                        // ※ userVerification を使ってない。

                        try
                        {
                            FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();
                            options = webAuthnHelper.CredentialGetOptions(username);

                            // Sessionに保存
                            HttpContext.Session.SetString("fido2.AssertionOptions", options.ToJson());
                        }
                        catch (Exception e)
                        {
                            options = new AssertionOptions
                            {
                                Status = OAuth2AndOIDCConst.error,
                                ErrorMessage = FIDO.WebAuthnHelper.FormatException(e)
                            };
                        }

                        ModelState.Clear();
                        model.SequenceNo = "1";
                        model.Fido2Data = JsonConvert.SerializeObject(options);
                    }
                    else if(model.SequenceNo == "1")
                    {
                        AssertionVerificationResult result = null;

                        try
                        {
                            AuthenticatorAssertionRawResponse clientResponse 
                                = JsonConvert.DeserializeObject<AuthenticatorAssertionRawResponse>(model.Fido2Data);

                            FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();

                            // Sessionから復元
                            AssertionOptions options = AssertionOptions.FromJson(
                                HttpContext.Session.GetString("fido2.AssertionOptions"));

                            result = await webAuthnHelper.AuthenticatorAssertion(clientResponse, options);

                            if (result.Status.ToLower() == "ok")
                            {
                                ApplicationUser user = await UserManager.FindByNameAsync(
                                    FIDO.DataProvider.GetUserByCredential(clientResponse.RawId).Name);

                                // ロックアウト
                                if (user.LockoutEndDateUtc != null
                                    && DateTime.Now <= user.LockoutEndDateUtc)
                                {
                                    signInStatus = AspNetId.SignInResult.LockedOut;
                                }
                                // 2FAは不要（デバイス特定されているため）
                                //else if (true) { }
                                else
                                {
                                    await SignInManager.SignInAsync(user, false); //, false);
                                    signInStatus = AspNetId.SignInResult.Success;
                                }

                                return VerifySignInStatus(signInStatus, model, user);
                            }
                        }
                        catch (Exception e)
                        {
                            result = new AssertionVerificationResult
                            {
                                Status = OAuth2AndOIDCConst.error,
                                ErrorMessage = FIDO.WebAuthnHelper.FormatException(e)
                            };
                        }

                        ModelState.Clear();
                        model.SequenceNo = "2";
                        model.Fido2Data = JsonConvert.SerializeObject(result);
                    }
                }
                else if (submitButtonName == "mspass_signin"
                    && Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
                {
                    // Microsoft Passportのサインイン
                    JObject fido2Data = JsonConvert.DeserializeObject<JObject>(model.Fido2Data);
                    ApplicationUser user = await UserManager.FindByNameAsync((string)fido2Data["fido2UserId"]);

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
                            // ロックアウト
                            if (user.LockoutEndDateUtc != null
                                && DateTime.Now <= user.LockoutEndDateUtc)
                            {
                                signInStatus = AspNetId.SignInResult.LockedOut;
                            }
                            // 2FAは不要（デバイス特定されているため）
                            //else if (true) { }
                            else
                            {
                                string fido2Challenge = (string)HttpContext.Session.GetString("fido2Challenge");

                                FIDO.MsPassHelper msPassHelper = new FIDO.MsPassHelper(user.FIDO2PublicKey, fido2Challenge);
                                if (msPassHelper.ValidateSignature(
                                    (string)fido2Data["fido2ClientData"],
                                    (string)fido2Data["fido2AuthenticatorData"],
                                    (string)fido2Data["fido2Signature"]))
                                {
                                    await SignInManager.SignInAsync(user, false); //, false);
                                    signInStatus = AspNetId.SignInResult.Success;
                                }
                                else
                                {
                                    signInStatus = AspNetId.SignInResult.Failed;
                                }
                            }

                            return VerifySignInStatus(signInStatus, model, user);
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

        /// <summary>VerifySignInStatus</summary>
        /// <param name="signInStatus">SignInResult</param>
        /// <param name="model">AccountLoginViewModel</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ActionResult</returns>
        private ActionResult VerifySignInStatus(AspNetId.SignInResult signInStatus, AccountLoginViewModel model, ApplicationUser user)
        {
            // SignInStatus

            if (signInStatus.Succeeded)
            {
                // サインイン成功

                // テスト機能でSession["state"]のチェックを止めたので不要になった。
                // また、ManageControllerの方はログイン済みアクセスになるので。

                // セッションの初期化
                this.InitSessionAfterlogin();

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
            else if (signInStatus.IsLockedOut)
            {
                // ロックアウト
                return View("Lockout");
            }
            else if (signInStatus.RequiresTwoFactor)
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
            else // if (signInStatus.Failure)
            {
                // サインイン失敗 or その他
                // "無効なログイン試行です。"
                ModelState.AddModelError("", Resources.AccountController.Login_Error);
                // 再表示
                return View(model);
            }
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
                if (user != null)
                    // .NET Coreのデバッガが、Cookieが別スコープになるように上げないので、
                    // 「デバッグ時にユーザ登録していない状態で、ログインしている状態になる」の対策コード
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

        #region 2 要素認証 (2FA :2 factor authentication)

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
                    // Email
                    await EmailSender.SendAsync(user.Email, "Two factor authentication code", code);
                }
                else if (model.SelectedProvider == "Phone")
                {
                    // SMS
                    await SmsSender.SendAsync(user.PhoneNumber, code);
                }
                else
                {
                    // TOTP authenticator
                    code = "";
                }

                if (!string.IsNullOrEmpty(code))
                {
                    // Email or SMS
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
                    // TOTP authenticator
                    return RedirectToAction("LoginWithTwoFactorAuthenticator", new
                    {
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                    });
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
                AspNetId.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                    provider: model.Provider,                                  // 2FAプロバイダ
                    code: model.Code,                                          // 2FAコ－ド
                    isPersistent: model.RememberBrowser, // model.RememberMe,  // アカウント記憶 ( ・・・仕様として解り難いので、RememberBrowserを使用 )
                    rememberClient: model.RememberBrowser                      // ブラウザ記憶(2FA)
                    );

                // SignInStatus
                if (result.Succeeded)
                {
                    // サインイン成功

                    // セッションの初期化
                    this.InitSessionAfterlogin();

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

                AspNetId.SignInResult result
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

                AspNetId.SignInResult result
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

        #region 外部ログイン (ExternalLogin)

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
            AspNetId.SignInResult siResult = null;

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

                        // セッションの初期化
                        this.InitSessionAfterlogin();

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

                                // セッションの初期化
                                this.InitSessionAfterlogin();

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

                                // ロールに追加。
                                await this.UserManager.AddToRoleAsync(user, Const.Role_User);
                                await this.UserManager.AddToRoleAsync(user, Const.Role_Admin);

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
                                       
                                    // セッションの初期化
                                    this.InitSessionAfterlogin();

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

        #region ID連携 (ID Federation)

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
                    model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                             new Uri(Config.IdFederationTokenEndPoint),
                            client_id, client_secret, redirect_uri, code, "");

                    #endregion

                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    #region id_tokenの検証コード

                    string sub = "";
                    string nonce = "";
                    JObject jobj = null;

                    if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                    {
                        // id_tokenがある。
                        string id_token = dic[OAuth2AndOIDCConst.IDToken];
                        string access_token = dic[OAuth2AndOIDCConst.AccessToken];

                        if (IdToken.Verify(id_token, access_token, code, state, out sub, out nonce, out jobj)
                            && nonce == (string)HttpContext.Session.GetString("id_federation_signin_nonce"))
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
                    // /userinfoエンドポイントにアクセスする場合
                    string response = await OAuth2AndOIDCClient.GetUserInfoAsync(
                        new Uri(Config.IdFederationUserInfoEndPoint), dic[OAuth2AndOIDCConst.AccessToken]);
                    #endregion

                    #region ユーザの登録・更新

                    IdentityResult idResult = null;
                    AspNetId.SignInResult siResult = null;

                    // クレーム情報（ID情報とe-mail, name情報）を抽出
                    jobj = (JObject)JsonConvert.DeserializeObject(response);
                    string id = (string)jobj[OAuth2AndOIDCConst.Scope_UserID];
                    string name = (string)jobj[OAuth2AndOIDCConst.sub];
                    string email = (string)jobj[OAuth2AndOIDCConst.Scope_Email];

                    Claim nameClaim = new Claim(OAuth2AndOIDCConst.UrnSubjectClaim, name);
                    Claim emailClaim = new Claim(OAuth2AndOIDCConst.UrnEmailClaim, email);

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
                        ApplicationUser user = await UserManager.FindByLoginAsync("MultiPurposeAuthSite", id);

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
                                "MultiPurposeAuthSite", id,
                                isPersistent: false, bypassTwoFactor: true); // 外部ログインの Cookie 永続化は常に false.

                            // セッションの初期化
                            this.InitSessionAfterlogin();

                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                            return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
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

                                UserLoginInfo externalLoginInfo = new UserLoginInfo(
                                    "MultiPurposeAuthSite", id, "MultiPurposeAuthSite");

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

                                    // セッションの初期化
                                    this.InitSessionAfterlogin();

                                    // オペレーション・トレース・ログ出力
                                    Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                                    // リダイレクト
                                    return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
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
                                ViewBag.ReturnUrl = Config.OAuth2AuthorizationServerEndpointsRootURI;
                                ViewBag.LoginProvider = "MultiPurposeAuthSite";

                                // 外部ログイン プロバイダのユーザー情報でユーザを作成
                                // uid = 連携先メアドの場合、E-mail confirmationはしない（true）。
                                user = ApplicationUser.CreateUser(uid, true);

                                // サインアップ時のみ、メアドも追加
                                //（RequireUniqueEmail = false時を想定）
                                user.Email = email;
                                user.EmailConfirmed = true;

                                // ユーザの新規作成（パスワードは不要）
                                idResult = await UserManager.CreateAsync(user);

                                UserLoginInfo externalLoginInfo = new UserLoginInfo(
                                    "MultiPurposeAuthSite", id, "MultiPurposeAuthSite");

                                // 結果の確認
                                if (idResult.Succeeded)
                                {
                                    // ユーザの新規作成が成功した場合

                                    // ロールに追加。
                                    await this.UserManager.AddToRoleAsync(user, Const.Role_User);
                                    await this.UserManager.AddToRoleAsync(user, Const.Role_Admin);

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

                                        // セッションの初期化
                                        this.InitSessionAfterlogin();

                                        // オペレーション・トレース・ログ出力
                                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                                        // リダイレクト
                                        return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
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

                    #endregion
                }
            }

            return View("Error");
        }

        #endregion

        #endregion

        #region STS (Security Token Service)

        #region Saml Endpoint

        #region Saml2 Request

        /// <summary>Saml2Request</summary>
        /// <param name="samlRequest">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult</returns>
        public async Task<ActionResult> Saml2Request(string samlRequest, string relayState, string sigAlg)
        {
            bool verified = false;

            string queryString = "";
            string decodeSaml = "";

            XmlDocument samlRequest2 = null;
            XmlNamespaceManager samlNsMgr = null;

            string iss = "";
            string id = "";
            string rtnUrl = "";

            // Cookie認証チケットからClaimsPrincipalを取得しておく。
            AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
            ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

            // ClaimsIdentityを生成
            ClaimsIdentity identity = new ClaimsIdentity(principal.Claims,
                 OAuth2AndOIDCConst.Bearer, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

            string samlResponse = "";
            SAML2Enum.StatusCode statusCode = SAML2Enum.StatusCode.Success;

            try
            {
                //// ここでエラーになった場合、返る？
                //throw new Exception("test");
                if (Request.Method.ToLower() == "get")
                {
                    // DecodeRedirect
                    string rawUrl = Request.GetEncodedUrl();
                    queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);
                    decodeSaml = SAML2Bindings.DecodeRedirect(queryString);

                    // XmlDocument
                    samlRequest2 = new XmlDocument();
                    samlRequest2.PreserveWhitespace = false;
                    samlRequest2.LoadXml(decodeSaml);

                    // XmlNamespaceManager
                    samlNsMgr = SAML2Bindings.CreateNamespaceManager(samlRequest2);

                    // VerifySamlRequest
                    //if (SAML2Const.RSAwithSHA1 == sigAlg) // 無い場合も通るようにする。
                    verified = Saml.CmnEndpoints.VerifySamlRequest(
                        queryString, decodeSaml, out iss, out id, samlRequest2, samlNsMgr);
                }
                else if (Request.Method.ToLower() == "post")
                {
                    // DecodePost
                    decodeSaml = SAML2Bindings.DecodePost(samlRequest);

                    // XmlDocument
                    samlRequest2 = new XmlDocument();
                    samlRequest2.PreserveWhitespace = false;
                    samlRequest2.LoadXml(decodeSaml);

                    // XmlNamespaceManager
                    samlNsMgr = SAML2Bindings.CreateNamespaceManager(samlRequest2);

                    // VerifySamlRequest
                    verified = Saml.CmnEndpoints.VerifySamlRequest(
                        "", decodeSaml, out iss, out id, samlRequest2, samlNsMgr);
                }

                //// ここでエラーになった場合、返る？
                //throw new Exception("test");

                // レスポンス生成
                if (verified)
                {
                    // Assertion > AttributeStatement > Attribute > AttributeValueに
                    // クレームを足すなら、ココで、identity.Claimsに値を詰めたりする。

                    if (Saml.CmnEndpoints.CreateSamlResponse(identity,
                        SAML2Enum.AuthnContextClassRef.PasswordProtectedTransport, statusCode,
                        iss, relayState, id, out rtnUrl, out samlResponse, out queryString, samlRequest2, samlNsMgr)
                        == SAML2Enum.ProtocolBinding.HttpRedirect)
                    {
                        // Redirect
                        return Redirect(rtnUrl + "?" + queryString);
                    }
                    else
                    {
                        // Post
                        ViewData["RelayState"] = relayState;
                        ViewData["SAMLResponse"] = samlResponse;
                        ViewData["Action"] = rtnUrl;

                        return View("PostBinding");
                    }
                }
                else
                {
                    // Error Response
                    statusCode = SAML2Enum.StatusCode.Requester;
                }
            }
            catch
            {
                // Error Response
                statusCode = SAML2Enum.StatusCode.Responder;
            }

            // Error Response
            try
            {
                if (Saml.CmnEndpoints.CreateSamlResponse(identity,
                    SAML2Enum.AuthnContextClassRef.PasswordProtectedTransport, statusCode,
                    iss, relayState, id, out rtnUrl, out samlResponse, out queryString, samlRequest2, samlNsMgr)
                    == SAML2Enum.ProtocolBinding.HttpRedirect)
                {
                    // Redirect
                    return Redirect(rtnUrl + "?" + queryString);
                }
                else
                {
                    // Post
                    ViewData["RelayState"] = relayState;
                    ViewData["SAMLResponse"] = samlResponse;
                    ViewData["Action"] = rtnUrl;

                    return View("PostBinding");
                }
            }
            catch
            {
                // issなどが取れていないと返せない。
                return null;
            }
        }

        #endregion

        #region Saml2 Response

        /// <summary>AssertionConsumerService</summary>
        /// <param name="samlResponse">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult</returns>
        [AllowAnonymous]
        public ActionResult AssertionConsumerService(string samlResponse, string relayState, string sigAlg)
        {
            if (!Config.IsLockedDownRedirectEndpoint)
            {
                bool verified = false;

                string nameId = "";
                string iss = "";
                string aud = "";
                string inResponseTo = "";
                string recipient = "";
                DateTime? notOnOrAfter = null;

                SAML2Enum.StatusCode? statusCode = null;
                SAML2Enum.NameIDFormat? nameIDFormat = null;
                SAML2Enum.AuthnContextClassRef? authnContextClassRef = null;

                XmlDocument samlResponse2 = null;

                if (Request.Method.ToLower() == "get")
                {
                    string rawUrl = Request.GetEncodedUrl();
                    string queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);

                    if (SAML2Const.RSAwithSHA1 == sigAlg)
                        if (SAML2Client.VerifyResponse(
                            queryString, samlResponse, out nameId, out iss, out aud,
                            out inResponseTo, out recipient, out notOnOrAfter,
                            out statusCode, out nameIDFormat, out authnContextClassRef, out samlResponse2))
                        {
                            if (iss == Config.IssuerId) verified = true;
                        }
                }
                else if (Request.Method.ToLower() == "post")
                {
                    if (SAML2Client.VerifyResponse(
                        "", samlResponse, out nameId, out iss, out aud,
                        out inResponseTo, out recipient, out notOnOrAfter,
                        out statusCode, out nameIDFormat, out authnContextClassRef, out samlResponse2))
                    {
                        if (iss == Config.IssuerId) verified = true;
                    }
                }

                // LoadRequestParameters
                string clientId_InSessionOrCookie = "";
                string state_InSessionOrCookie = "";
                string redirect_uri_InSessionOrCookie = "";
                string nonce_InSessionOrCookie = "";
                string code_verifier_InSessionOrCookie = "";
                this.LoadRequestParameters(
                    out clientId_InSessionOrCookie,
                    out state_InSessionOrCookie,
                    out redirect_uri_InSessionOrCookie,
                    out nonce_InSessionOrCookie,
                    out code_verifier_InSessionOrCookie);

                // レスポンス生成
                if (verified)
                {
                    // 認証完了。

                    // 必要に応じてチェックしてもイイ
                    // relayStateをstateに利用したケース
                    if (relayState == state_InSessionOrCookie) { }

                    // 必要に応じてsamlResponse2を読んで拡張処理を実装可能。
                    return Redirect(
                        Config.OAuth2AuthorizationServerEndpointsRootURI
                        + "?ret=" + CustomEncode.UrlEncode(string.Format("認証完了（nameId={0}）", nameId)));
                }
                else
                {
                    // 認証失敗。
                    return Redirect(
                        Config.OAuth2AuthorizationServerEndpointsRootURI
                        + "?ret=" + CustomEncode.UrlEncode("認証失敗"));
                }
                // ※ ASP.NET Coreだと、手動でUrlEncodeしないとダメっぽい。
            }
            else
            {
                // IsLockedDownRedirectEndpoint == true;
            }

            // エラー
            return View("Error");
        }

        #endregion

        #endregion

        #region OAuth Endpoint

        #region Authorize（認可エンドポイント）

        #region max_age & auth_time
        /// <summary>CheckAuthTime</summary>
        /// <param name="max_age">string</param>
        /// <returns>bool</returns>
        private bool CheckAuthTime(string max_age)
        {
            if (string.IsNullOrEmpty(max_age))
            {
                // max_ageの指定ナシ
                return true;
            }
            else
            {
                // max_ageの指定アリ
                if (int.TryParse(max_age, out int maxAge))
                {
                    // max_ageが数値
                    IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
                    string auth_time = requestCookies.Get(OAuth2AndOIDCConst.auth_time);
                    if (string.IsNullOrEmpty(auth_time))
                    {
                        // auth_timeナシ
                        return false;
                    }
                    else
                    {
                        // auth_timeアリ
                        DateTime now = DateTime.UtcNow;
                        TimeSpan ts = now - FormatConverter.FromW3cTimestamp(auth_time);

                        if (ts.TotalSeconds <= maxAge)
                        {
                            // max_age内
                            return true;
                        }
                        else
                        {
                            // max_age外
                            return false;
                        }
                    }
                }
                else
                {
                    // max_ageが数値以外
                    return false;
                }
            }
        }

        /// <summary>auth_timeを追加</summary>
        /// <param name="max_age">string</param>
        /// <param name="claims">JObject</param>
        /// <param name="identity">ClaimsIdentity</param>
        private void AddAuthTimeClaim(string max_age, JObject claims, ClaimsIdentity identity)
        {
            // QueryString、Cookieなどに関連するのでController側で追加。
            if (!string.IsNullOrEmpty(max_age) || (claims != null
                && claims.ContainsKey(OAuth2AndOIDCConst.claims_id_token) 
                && ((JObject)claims[OAuth2AndOIDCConst.claims_id_token]).ContainsKey(OAuth2AndOIDCConst.auth_time)))
            {
                IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
                string auth_time = requestCookies.Get(OAuth2AndOIDCConst.auth_time);

                if (string.IsNullOrEmpty(auth_time))
                {
                    auth_time = DateTimeOffset.MinValue.ToString();
                }

                identity.AddClaim(new Claim(
                    OAuth2AndOIDCConst.UrnAuthTimeClaim,
                    FormatConverter.ToW3cTimestamp(DateTime.Parse(auth_time))));
            }
        }
        #endregion

        #region エンドポイント自体
        /// <summary>認可エンドポイント</summary>
        /// <param name="client_id">string（必須）</param>
        /// <param name="redirect_uri">string（任意）</param>
        /// <param name="response_type">string（必須）</param>
        /// <param name="response_mode">string（任意）</param>
        /// <param name="scope">string（任意）</param>
        /// <param name="state">string（推奨）</param>
        /// <param name="nonce">string（OIDC 推奨）</param>
        /// <param name="max_age">string（OIDC 任意）</param>
        /// <param name="prompt">string（OIDC 任意）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpGet]
        public async Task<ActionResult> OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce, string max_age, string prompt) // OpenID Connect
        // Request.QueryStringで直接参照
        // - string code_challenge, string code_challenge_method) // OAuth PKCE
        // - string request_uri // FAPI2 : RequestObject
        {
            string valid_redirect_uri = ""; 
            string err = "";
            string errDescription = "";

            JObject claims = null;
            string request_uri = StringExtractor.GetParameterFromQueryString(
                OAuth2AndOIDCConst.request_uri, Request.GetEncodedUrl());
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                client_id = (string)requestObjectPayload[OAuth2AndOIDCConst.client_id];
                redirect_uri = (string)requestObjectPayload[OAuth2AndOIDCConst.redirect_uri];
                response_type = (string)requestObjectPayload[OAuth2AndOIDCConst.response_type];
                response_mode = (string)requestObjectPayload[OAuth2AndOIDCConst.response_mode];
                scope = (string)requestObjectPayload[OAuth2AndOIDCConst.scope];
                state = (string)requestObjectPayload[OAuth2AndOIDCConst.state];
                nonce = (string)requestObjectPayload[OAuth2AndOIDCConst.nonce];
                max_age = (string)requestObjectPayload[OAuth2AndOIDCConst.max_age];
                prompt = (string)requestObjectPayload[OAuth2AndOIDCConst.prompt];
                claims = (JObject)requestObjectPayload[OAuth2AndOIDCConst.claims];
            }

            if (this.CheckAuthTime(max_age)) {
                if (Token.CmnEndpoints.ValidateAuthZReqParam(
                    client_id, redirect_uri, response_type, scope, nonce,
                    out valid_redirect_uri, out err, out errDescription))
                {
                    // Cookie認証チケットからClaimsPrincipalを取得しておく。
                    AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
                    ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

                    // ClaimsIdentityを生成
                    ClaimsIdentity identity = new ClaimsIdentity(
                        principal.Claims, OAuth2AndOIDCConst.Bearer,
                        ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                    // auth_timeを追加
                    this.AddAuthTimeClaim(max_age, claims, identity);

                    // scopeパラメタ
                    string[] scopes = (scope ?? "").Split(' ');

                    if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                    {
                        // OAuth2/OIDC Authorization Code
                        ViewBag.Name = principal.Identity.Name;
                        ViewBag.Scopes = scopes;

                        // 認証の場合、余計なscopeをfilterする。
                        bool isAuth = scopes.Any(x => x.ToLower() == OAuth2AndOIDCConst.Scope_Auth);

                        if (string.IsNullOrWhiteSpace(prompt)) prompt = "";

                        if (isAuth                           // OAuth2 拡張仕様
                            || prompt.ToLower() == "none")   // OIDC   RFC仕様
                        {
                            // 認可画面をスキップ

                            // ★ 必要に応じてスコープのフィルタ
                            if (isAuth)
                            {
                                scopes = Sts.Helper.FilterClaimAtAuth(scopes).ToArray();
                            }

                            // ★ Codeの生成
                            string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                                client_id, state, scopes, claims, nonce);

                            // RedirectエンドポイントへCodeをRedirect
                            ActionResult actionResult = this.RedirectCode(
                                client_id, response_mode, valid_redirect_uri, code, state);
                            if (actionResult != null) return actionResult;
                        }
                        else
                        {
                            // 認可画面を表示
                            return View();
                        }
                    }
                    else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType)
                    {
                        // OAuth2/OIDC Implicit

                        // ★ Tokenの生成
                        Token.CmnEndpoints.CreateAuthZRes4ImplicitFlow(
                            identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                            response_type, client_id, state, scopes, claims, nonce,
                            out string access_token, out string id_token);

                        // RedirectエンドポイントへTokenをRedirect
                        ActionResult actionResult = this.RedirectToken(
                            client_id, response_mode, response_type, valid_redirect_uri,
                            access_token, id_token, state);
                        if (actionResult != null) return actionResult;
                    }
                    else if (response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                    {
                        // OIDC Hybrid Flow

                        // ★ Tokenの生成
                        string code = Token.CmnEndpoints.CreateAuthNRes4HybridFlow(
                            identity,
                            HttpUtility.ParseQueryString(Request.QueryString.Value),
                            client_id, state, scopes, claims, nonce,
                            out string access_token, out string id_token);

                        // RedirectエンドポイントへRedirect
                        ActionResult actionResult = this.RedirectCodeToken(
                            client_id, response_mode, response_type, valid_redirect_uri,
                            code, access_token, id_token, state);
                        if (actionResult != null) return actionResult;
                    }
                    else
                    {
                        // 不正なresponse_type
                    }
                }
                else
                {
                    // 不正なRequest
                }
            }
            else
            {
                // 不正なRequest
            }

            // ここまで来たらエラー。
            if (!string.IsNullOrEmpty(valid_redirect_uri))
            {
                // valid_redirect_uri
                return new RedirectResult(
                    valid_redirect_uri + string.Format(
                        "?err={0}&errDescription={1}", err, errDescription));
            }
            //else if (!string.IsNullOrEmpty(redirect_uri))
            //{
            //    // redirect_uri//オープンリダイレクター
            //    return new RedirectResult(
            //        redirect_uri + string.Format(
            //            "?err={0}&errDescription={1}", err, errDescription));
            //}
            else
            {
                // エラー画面
                ViewData["Err"] = err;
                ViewData["ErrDescription"] = errDescription;
                return View("Error");
            }
        }

        /// <summary>
        /// 認可エンドポイント
        /// Authorization Codeグラント種別の権限付与画面の結果を受け取り、
        /// 仲介コードを発行してRedirectエンドポイントへRedirect。
        /// ※ パラメタは、認可レスポンスのURL中に残っているものを使用。
        /// </summary>
        /// <param name="client_id">string（必須）</param>
        /// <param name="redirect_uri">string（任意）</param>
        /// <param name="response_type">string（必須）</param>
        /// <param name="response_mode">string（任意）</param>
        /// <param name="scope">string（任意）</param>
        /// <param name="state">string（推奨）</param>
        /// <param name="nonce">string（OIDC 推奨）</param>
        /// <param name="max_age">string（OIDC 任意）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce, string max_age) // OpenID Connect
        // Request.QueryStringで直接参照
        // - string code_challenge, string code_challenge_method) // OAuth PKCE
        // - string request_uri // FAPI2 : RequestObject
        {
            string prompt = ""; // ダミー
            JObject claims = null;
            string request_uri = StringExtractor.GetParameterFromQueryString(
                OAuth2AndOIDCConst.request_uri, Request.GetEncodedUrl());
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                client_id = (string)requestObjectPayload[OAuth2AndOIDCConst.client_id];
                redirect_uri = (string)requestObjectPayload[OAuth2AndOIDCConst.redirect_uri];
                response_type = (string)requestObjectPayload[OAuth2AndOIDCConst.response_type];
                response_mode = (string)requestObjectPayload[OAuth2AndOIDCConst.response_mode];
                scope = (string)requestObjectPayload[OAuth2AndOIDCConst.scope];
                state = (string)requestObjectPayload[OAuth2AndOIDCConst.state];
                nonce = (string)requestObjectPayload[OAuth2AndOIDCConst.nonce];
                max_age = (string)requestObjectPayload[OAuth2AndOIDCConst.max_age];
                prompt = (string)requestObjectPayload[OAuth2AndOIDCConst.prompt];
                claims = (JObject)requestObjectPayload[OAuth2AndOIDCConst.claims];
            }

            if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, response_type, scope, nonce,
                out string valid_redirect_uri, out string err, out string errDescription))
            {
                // Cookie認証チケットからClaimsPrincipalを取得しておく。
                AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
                ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

                // ClaimsIdentityを生成
                ClaimsIdentity identity = new ClaimsIdentity(
                    principal.Claims, OAuth2AndOIDCConst.Bearer,
                    ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // auth_timeを追加
                this.AddAuthTimeClaim(max_age, claims, identity);

                // 次に、アクセス要求を保存して、仲介コードを発行する。

                // scopeパラメタ
                string[] scopes = (scope ?? "").Split(' ');

                if (!string.IsNullOrEmpty(MyHttpContext.Current.Request.Form["submit.Login"]))
                {
                    // 別のアカウントでログイン
                    //（サインアウトしてリダイレクト）
                    await this.HttpContext.SignOutAsync();
                    return new RedirectResult(UriHelper.GetEncodedUrl(Request));
                }
                else if (!string.IsNullOrEmpty(MyHttpContext.Current.Request.Form["submit.Grant"]))
                {
                    // OAuth2/OIDC Authorization Code

                    // ★ Codeの生成
                    string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                        identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                        client_id, state, scopes, claims, nonce);

                    // RedirectエンドポイントへCodeをRedirect
                    ActionResult actionResult = this.RedirectCode(
                        client_id, response_mode, valid_redirect_uri, code, state);
                    if (actionResult != null) return actionResult;
                }
                else
                {
                    // 不正な操作
                }
            }
            else
            {
                // 不正なRequest
            }

            if (string.IsNullOrEmpty(err))
            {
                // 再表示
                return View();
            }
            else if (!string.IsNullOrEmpty(valid_redirect_uri))
            {
                // valid_redirect_uri
                return new RedirectResult(
                    valid_redirect_uri + string.Format(
                        "?err={0}&errDescription={1}", err, errDescription));
            }
            //else if (!string.IsNullOrEmpty(redirect_uri))
            //{
            //    // redirect_uri//オープンリダイレクター
            //    return new RedirectResult(
            //        redirect_uri + string.Format(
            //            "?err={0}&errDescription={1}", err, errDescription));
            //}
            else
            {
                // エラー画面
                ViewData["Err"] = err;
                ViewData["ErrDescription"] = errDescription;
                return View("Error");
            }
        }
        #endregion

        #region Redirect処理 (Response Mode & JARM)
        /// <summary>
        /// RedirectエンドポイントへCodeをRedirect
        /// </summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectCode(
            string client_id, string response_mode,
            string redirect_uri, string code, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            if (string.IsNullOrEmpty(response_mode)
                || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit())
            {
                // query
                return new RedirectResult(redirect_uri + string.Format("?code={0}&state={1}", code, state));
            }
            else if (response_mode.ToLower() 
                == OAuth2AndOIDCEnum.ResponseMode.jwt.ToStringByEmit()
                || response_mode.ToLower().Replace('.', '_')
                == OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit())
            {
                // jwt or query.jwt
                response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                {
                    { "code" , code },
                    { "state",  state }
                }, client_id, expiresUtc);
                return new RedirectResult(redirect_uri + string.Format("?response={0}", response));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
            {
                // fragment
                return new RedirectResult(redirect_uri + string.Format("#code={0}&state={1}", code, state));
            }
            else if (response_mode.ToLower().Replace('.', '_')
                == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
            {
                // fragment.jwt
                response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                {
                    { "code" , code },
                    { "state",  state }
                }, client_id, expiresUtc);
                return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
            {
                // form_post
                ViewData["Action"] = redirect_uri;
                ViewData["Code"] = code;
                ViewData["State"] = state;
                return View("FormPost");
            }
            else if (response_mode.ToLower().Replace('.', '_')
                == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
            {
                // form_post.jwt
                response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                {
                    { "code" , code },
                    { "state",  state }
                }, client_id, expiresUtc);
                ViewData["Action"] = redirect_uri;
                ViewData["Response"] = response;
                return View("FormPost");
            }
            else
            {
                // 不正な操作
                return null;
            }
        }

        /// <summary>
        /// RedirectエンドポイントへTokenをRedirect
        /// </summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="response_type">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="access_token">string</param>
        /// <param name="id_token">string</param>
        /// <param name="state">string</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectToken(
            string client_id, string response_mode, string response_type, string redirect_uri,
            string access_token, string id_token, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            // 補足
            // stateは、クライアントが指定した場合、基本的に必要になる。
            // access_tokenを返す場合、token_type, expires_inが必要になる。
            switch (response_type)
            {
                case OAuth2AndOIDCConst.ImplicitResponseType:
                    if (string.IsNullOrEmpty(access_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri + string.Format(
                                "#access_token={0}&state={1}&token_type={2}&expires_in={3}",
                                access_token, state, "bearer", Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, null, null);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, null, null);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcImplicit1_ResponseType:
                    if (string.IsNullOrEmpty(id_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri
                                + string.Format("#id_token={0}&state={1}", id_token, state));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state }
                            }, null, null);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["IDToken"] = id_token;
                            ViewData["State"] = state;
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state }
                            }, null, null);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcImplicit2_ResponseType:
                    if (string.IsNullOrEmpty(id_token) || string.IsNullOrEmpty(access_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri + string.Format(
                                "#id_token={0}&access_token={1}&state={2}&token_type={3}&expires_in={4}",
                                id_token, access_token, state, "bearer", Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, null, null);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["IDToken"] = id_token;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, null, null);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                default:
                    // queryはNG
                    return null;
            }
        }

        /// <summary>RedirectエンドポイントへCode & TokenをRedirect</summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="response_type">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code">string</param>
        /// <param name="access_token">string</param>
        /// <param name="id_token">string</param>
        /// <param name="state">string</param>
        /// <returns></returns>
        private ActionResult RedirectCodeToken(
            string client_id, string response_mode, string response_type, string redirect_uri,
            string code, string access_token, string id_token, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            // 補足
            // stateは、クライアントが指定した場合、基本的に必要になる。
            // access_tokenを返す場合、token_type, expires_inが必要になる。
            switch (response_type)
            {
                case OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType:
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(access_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri + string.Format(
                                "#code={0}&access_token={1}&state={2}&token_type={3}&expires_in={4}",
                                code, access_token, state, "bearer",
                                Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, client_id, expiresUtc);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, client_id, expiresUtc);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType:
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(id_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri + string.Format(
                                "#code={0}&id_token={1}&state={2}", code, id_token, state));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state }
                            }, client_id, expiresUtc);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["IDToken"] = id_token;
                            ViewData["State"] = state;
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code,  code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state },
                            }, client_id, expiresUtc);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcHybrid3_ResponseType:
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(access_token) || string.IsNullOrEmpty(id_token))
                    {
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(response_mode)
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(redirect_uri + string.Format(
                                "#code={0}&access_token={1}&id_token={2}&state={3}&token_type={4}&expires_in={5}",
                                code, access_token, id_token, state, "bearer",
                                Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, client_id, expiresUtc);
                            return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["IDToken"] = id_token;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.AccessToken , access_token },
                                { OAuth2AndOIDCConst.state,  state },
                                { OAuth2AndOIDCConst.token_type , "bearer" },
                                { OAuth2AndOIDCConst.expires_in , Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString() }
                            }, client_id, expiresUtc);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                default:
                    // queryはNG
                    return null;
            }
        }

        /// <summary>CreateJarmExp</summary>
        /// <returns>DateTimeOffset</returns>
        private DateTimeOffset CreateJarmExp()
        {
            return DateTimeOffset.Now.AddMinutes(10);
        }

        /// <summary>CreateErrorResponseForToken</summary>
        /// <param name="response_mode">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="state">string</param>
        private ActionResult CreateErrorResponseForToken(
            string response_mode, string redirect_uri, string state)
        {
            string response = "";

            if (string.IsNullOrEmpty(response_mode)
                || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
            {
                // fragment
                return new RedirectResult(redirect_uri
                    + string.Format("#error=access_denied&state={0}", state));
            }
            else if(response_mode.ToLower().Replace('.', '_')
                == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
            {
                // fragment.jwt
                response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.error , OAuth2AndOIDCConst.access_denied },
                    { OAuth2AndOIDCConst.state,  state }
                }, null, null);
                return new RedirectResult(redirect_uri + string.Format("#response={0}", response));
            }
            else if(response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
            {
                // form_post
                ViewData["Action"] = redirect_uri;
                ViewData["Error"] = OAuth2AndOIDCConst.access_denied;
                ViewData["State"] = state;
                return View("FormPost");
            }
            else if(response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
            {
                // form_post.jwt
                response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.error , OAuth2AndOIDCConst.access_denied },
                    { OAuth2AndOIDCConst.state,  state }
                }, null, null);
                ViewData["Action"] = redirect_uri;
                ViewData["Response"] = response;
                return View("FormPost");
            }

            // queryはNG
            return null;
        }

        #endregion

        #endregion

        #region Client (Redirectエンドポイント)

        #region Authorization Codeグラント種別

        /// <summary>
        /// Authorization Codeグラント種別のClientエンドポイント
        /// 認可レスポンス（仲介コード）を受け取って処理する。
        /// ・仲介コードを使用してAccess Token・Refresh Tokenを取得
        /// </summary>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <param name="response">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-resp"/>
        /// <seealso cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req"/>
        // [HttpGet] // Response Mode & JARM 対応
        [AllowAnonymous]
        public async Task<ActionResult> OAuth2AuthorizationCodeGrantClient(string code, string state, string response)
        {
            if (!Config.IsLockedDownRedirectEndpoint)
            {
                if (!string.IsNullOrEmpty(code)
                    || !string.IsNullOrEmpty(response))
                {
                    // query(.jwt)、form_post(.jwt)のカバレッジ

                    // JARM
                    if (!string.IsNullOrEmpty(response))
                    {
                        // responseObject検証
                        if (ResponseObject.Verify(response, out JObject responseObject))
                        {
                            // OK
                            code = (string)responseObject[OAuth2AndOIDCConst.code];
                            state = (string)responseObject[OAuth2AndOIDCConst.state];
                        }
                        else
                        {
                            // NG
                        }
                    }

                    // LoadRequestParameters
                    string clientId_InSessionOrCookie = "";
                    string state_InSessionOrCookie = "";
                    string redirect_uri_InSessionOrCookie = "";
                    string nonce_InSessionOrCookie = "";
                    string code_verifier_InSessionOrCookie = "";
                    this.LoadRequestParameters(
                        out clientId_InSessionOrCookie,
                        out state_InSessionOrCookie,
                        out redirect_uri_InSessionOrCookie,
                        out nonce_InSessionOrCookie,
                        out code_verifier_InSessionOrCookie);

                    // Tokenエンドポイントにアクセス
                    Uri tokenEndpointUri = new Uri(
                        Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;
                    OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                    {
                        ClientId = clientId_InSessionOrCookie,
                        State = state,
                        Code = code
                    };

                    #region 仲介コードを使用してAccess, Refresh, Id Tokenを取得

                    string fapi1Prefix = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":";
                    string fapi2Prefix = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":";

                    //stateの検証
                    if (state == state_InSessionOrCookie
                        || state == fapi1Prefix + state_InSessionOrCookie  // specではなくテスト仕様
                        || state == fapi2Prefix + state_InSessionOrCookie) // specではなくテスト仕様
                    {
                        //state正常
                        if (state == null) state = ""; // null対策（テスト）

                        // 仲介コードからAccess Tokenを取得する。

                        // redirect_uriを設定
                        string redirect_uri = "";
                        if (string.IsNullOrEmpty(redirect_uri_InSessionOrCookie))
                        {
                            // 指定なしの場合のテストケース（指定不要
                        }
                        else
                        {
                            // 指定ありの場合のテストケース（指定必要
                            redirect_uri = redirect_uri_InSessionOrCookie;
                        }

                        // Tokenエンドポイントにアクセス
                        if (state.StartsWith(fapi1Prefix))
                        {
                            // FAPI1

                            // Tokenエンドポイントにアクセス
                            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

                            // client_id(iss)
                            string iss = clientId_InSessionOrCookie;

                            // 秘密鍵
                            DigitalSignX509 dsX509 = new DigitalSignX509(
                                CmnClientParams.RsaPfxFilePath,
                                CmnClientParams.RsaPfxPassword,
                                HashAlgorithmName.SHA256);

                            model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code, JwtAssertion.CreateByRsa(
                                    iss, aud, new TimeSpan(0, 0, 30), Const.StandardScopes,
                                    ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true)));
                        }
                        else if (state.StartsWith(fapi2Prefix))
                        {
                            // FAPI2

                            //  client_Idと、クライアント証明書（TB）
                            string client_id = clientId_InSessionOrCookie;

                            model.Response = await Sts.Helper.GetInstance()
                                .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                client_id, "", redirect_uri, code);
                        }
                        else
                        {
                            // OAuth2 / OIDC

                            //  client_Idから、client_secretを取得。
                            string client_id = clientId_InSessionOrCookie;
                            string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                            if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
                            {
                                // 通常
                                model.Response = await Sts.Helper.GetInstance()
                                    .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                    client_id, client_secret, redirect_uri, code);
                            }
                            else
                            {
                                // PKCE
                                model.Response = await Sts.Helper.GetInstance()
                                   .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                   client_id, client_secret, redirect_uri,
                                   code, code_verifier_InSessionOrCookie);
                            }
                        }

                        dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);
                    }
                    else
                    {
                        // state異常
                        dic = new Dictionary<string, string>();
                        dic.Add(OAuth2AndOIDCConst.error, "state error.");
                    }

                    #endregion

                    #region Access, Refresh, Id Tokenの検証と表示

                    if (!dic.ContainsKey(OAuth2AndOIDCConst.error))
                    {
                        string out_sub = "";
                        JObject out_jobj = null;

                        if (dic.ContainsKey(OAuth2AndOIDCConst.AccessToken))
                        {
                            model.AccessToken = dic[OAuth2AndOIDCConst.AccessToken];
                            model.AccessTokenJwtToJson = CustomEncode.ByteToString(
                                   CustomEncode.FromBase64UrlString(model.AccessToken.Split('.')[1]), CustomEncode.UTF_8);


                            if (!string.IsNullOrEmpty(model.AccessToken))
                            {
                                if (!AccessToken.Verify(model.AccessToken,
                                out out_sub, out List<string> out_roles, out List<string> out_scopes, out out_jobj))
                                {
                                    throw new Exception("AccessToken検証エラー");
                                }
                            }
                            else
                            {
                                throw new Exception("AccessToken検証エラー");
                            }
                        }

                        if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                        {
                            model.IdToken = dic[OAuth2AndOIDCConst.IDToken];

                            if (!string.IsNullOrEmpty(model.IdToken))
                            {
                                if (!IdToken.Verify(
                                    model.IdToken, model.AccessToken, code, state,
                                    out out_sub, out string out_nonce, out out_jobj)
                                    && out_nonce == nonce_InSessionOrCookie)
                                {
                                    throw new Exception("IdToken検証エラー");
                                }
                            }
                            else
                            {
                                throw new Exception("IdToken検証エラー");
                            }

                            // 暗号化解除のケースがあるので、jobjを使用。
                            model.IdTokenJwtToJson = out_jobj.ToString();
                        }

                        model.RefreshToken = dic.ContainsKey(OAuth2AndOIDCConst.RefreshToken) ? dic[OAuth2AndOIDCConst.RefreshToken] : "";

                        // 画面の表示。
                        return View(model);
                    }
                    #endregion
                }
                else
                {
                    // fragmentのカバレッジ
                    // そのまま画面を出し、画面側でfragmentを処理
                    return View(new OAuth2AuthorizationCodeGrantClientViewModel());
                }
            }
            else
            {
                // IsLockedDownRedirectEndpoint == true;
            }

            // エラー
            return View("Error");
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
                        model.Response = await Sts.Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Refresh"]))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                        // Tokenエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().
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
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint);

                        // Revokeエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().RevokeTokenAsync(
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
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint);

                        // Introspectエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().IntrospectTokenAsync(
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
        // [HttpGet] // Response Mode & JARM 対応
        [AllowAnonymous]
        public ActionResult OAuth2ImplicitGrantClient(
            string access_token, string id_token, string code, string state,
            string token_type, string expires_in, string response)
        {
            if (!Config.IsLockedDownRedirectEndpoint)
            {
                // OAuth2のREQUIREDは、access_token, token_type, state
                if (!string.IsNullOrEmpty(state)
                   || !string.IsNullOrEmpty(response))
                {
                    // query(.jwt)、form_post(.jwt)のカバレッジ

                    // JARM
                    if (!string.IsNullOrEmpty(response))
                    {
                        // responseObject検証
                        if (ResponseObject.Verify(response, out JObject responseObject))
                        {
                            // OK
                            access_token = (string)responseObject[OAuth2AndOIDCConst.AccessToken];
                            id_token = (string)responseObject[OAuth2AndOIDCConst.IDToken];
                            code = (string)responseObject[OAuth2AndOIDCConst.code];
                            state = (string)responseObject[OAuth2AndOIDCConst.state];
                            token_type = (string)responseObject[OAuth2AndOIDCConst.token_type];
                            expires_in = (string)responseObject[OAuth2AndOIDCConst.expires_in];
                            //scope = (string)responseObject[OAuth2AndOIDCConst.scope];
                        }
                        else
                        {
                            // NG
                        }
                    }

                    // 画面の表示。
                    // form_post(.jwt)
                    ViewData["FormPost"] = JsonConvert.SerializeObject(
                        new
                        {
                            access_token,
                            id_token,
                            code,
                            state,
                            token_type,
                            expires_in
                        });
                    return View();// model);
                }
                else
                {
                    // fragment(.jwt)のカバレッジ

                    // ココでstateの検証を予定していたが、コメントヘッダに有るように、ココでは実装できなかった。
                    // stateは、JWTにnonce Claimとして格納してあるため、必要であれば、UserAgent側で検証できる。

                    // そのまま画面を出し、画面側でfragmentを処理
                    return View();
                }
            }

            return View("Error");
        }

        #endregion

        #endregion

        #endregion

        #region Device AuthZ
        /// <summary>
        /// DeviceAuthZVerify画面（初期表示）
        /// GET: /device_verify
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult DeviceAuthZVerify()
        {
            ViewBag.ReceiveResult = false;
            ViewBag.UserCode = StringExtractor.GetParameterFromQueryString(
                OAuth2AndOIDCConst.user_code, Request.GetEncodedUrl());

            return View("DeviceAuthZVerify");
        }

        /// <summary>
        /// DeviceAuthZVerify画面
        /// POST: /device_verify
        /// </summary>
        /// <param name="formData">IFormCollection</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        public ActionResult DeviceAuthZVerify(IFormCollection formData)
        {
            ViewBag.ReceiveResult = false;

            if (formData != null)
            {
                string userCode = formData[OAuth2AndOIDCConst.user_code];
                ViewBag.ReceiveResult = Sts.DeviceAuthZProvider.ReceiveResult(userCode, User.Identity.Name, formData.ContainsKey("allow"));
            }
            
            return View("DeviceAuthZVerify");
        }
        #endregion

        #region テスト用

        /// <summary>LoadRequestParameters</summary>
        /// <param name="clientId">out string</param>
        /// <param name="state">out string</param>
        /// <param name="redirect_uri">out string</param>
        /// <param name="nonce">out string</param>
        /// <param name="code_verifier">out string</param>
        private void LoadRequestParameters(
            out string clientId,
            out string state, out string redirect_uri,
            out string nonce, out string code_verifier)
        {
            IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            // client_id
            clientId = HttpContext.Session.GetString(Const.TestClientId);
            if (!string.IsNullOrEmpty(clientId))
            {
                HttpContext.Session.SetString(Const.TestClientId, "");
            }
            else
            {
                clientId = requestCookies.Get(Const.TestClientId);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestClientId, "", this._cookieOptions);
                }
            }

            // state
            state = HttpContext.Session.GetString(Const.TestState);
            if (!string.IsNullOrEmpty(state))
            {
                HttpContext.Session.SetString(Const.TestState, "");
            }
            else
            {
                state = requestCookies.Get(Const.TestState);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestState, "", this._cookieOptions);
                }
            }

            // redirect_uri
            redirect_uri = HttpContext.Session.GetString(Const.TestRedirectUri);
            if (!string.IsNullOrEmpty(redirect_uri))
            {
                HttpContext.Session.SetString(Const.TestRedirectUri, "");
            }
            else
            {
                redirect_uri = requestCookies.Get(Const.TestRedirectUri);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestRedirectUri, "", this._cookieOptions);
                }
            }

            // nonce
            nonce = HttpContext.Session.GetString(Const.TestNonce);
            if (!string.IsNullOrEmpty(nonce))
            {
                HttpContext.Session.SetString(Const.TestNonce, "");
            }
            else
            {
                nonce = requestCookies.Get(Const.TestNonce);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestNonce, "", this._cookieOptions);
                }
            }

            // code_verifier
            code_verifier = HttpContext.Session.GetString(Const.TestCodeVerifier);
            if (!string.IsNullOrEmpty(code_verifier))
            {
                HttpContext.Session.SetString(Const.TestCodeVerifier, "");
            }
            else
            {
                code_verifier = requestCookies.Get(Const.TestCodeVerifier);
                if (!string.IsNullOrEmpty(clientId))
                {
                    responseCookies.Set(Const.TestCodeVerifier, "", this._cookieOptions);
                }
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
    }
}