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
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//**********************************************************************************


using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.TokenProviders;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using OAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Configuration;

using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Web.Configuration;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Facebook;

using Fido2NetLib;
using Fido2NetLib.Objects;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

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

        #region property

        /// <summary>SessionCookieName</summary>
        private string SessionCookieName
        {
            get
            {
                return ((SessionStateSection)ConfigurationManager.GetSection("system.web/sessionState")).CookieName;
            }
        }

        #region GetOwinContext

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

            string cmnPattern = "";

            #region ReturnUrl

            cmnPattern = "ReturnUrl=";

            if (string.IsNullOrEmpty(returnUrl)
                && Request.RawUrl.IndexOf(cmnPattern) != -1)
            {
                if (Request.RawUrl.Contains('&'))
                {
                    // 正規表現でreturnUrlを抜き出す。
                    string regexPattern = "(" + cmnPattern + ")(?<returnUrl>.+?)(\\&)";
                    returnUrl = CustomEncode.UrlDecode(Regex.Match(Request.RawUrl, regexPattern).Groups["returnUrl"].Value);
                }
                else
                {
                    // IndexOf & SubstringでreturnUrlを抜き出す。
                    returnUrl = CustomEncode.UrlDecode(Request.RawUrl.Substring(Request.RawUrl.IndexOf(cmnPattern) + cmnPattern.Length));
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
            else if(Config.FIDOServerMode == FIDO.EnumFidoType.MsPass)
            {
                fido2Challenge = GetPassword.Generate(22, 0);
                Session["fido2Challenge"] = fido2Challenge;
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
            SignInStatus signInStatus = SignInStatus.Failure;

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
                            if (await UserManager.IsEmailConfirmedAsync(user.Id))
                            {
                                // EmailConfirmed == true の場合、
                                // パスワード入力失敗回数に基づいてアカウントがロックアウトされるように設定するには、shouldLockout: true に変更する
                                signInStatus = await SignInManager.PasswordSignInAsync(
                                    userName: uid,                                      // アカウント(UID)
                                    password: model.Password,                           // アカウント(PWD)
                                    isPersistent: model.RememberMe,                     // アカウント記憶
                                    shouldLockout: Config.UserLockoutEnabledByDefault); // ロックアウト

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
                    Session["id_federation_signin_state"] = state;

                    // nonce // 記号は入れない。
                    string nonce = GetPassword.Generate(20, 0);
                    Session["id_federation_signin_nonce"] = state;

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
                            Session["fido2.AssertionOptions"] = options.ToJson();
                        }
                        catch (Exception e)
                        {
                            options = new AssertionOptions
                            {
                                Status = "error",
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
                                (string)Session["fido2.AssertionOptions"]);

                            result = await webAuthnHelper.AuthenticatorAssertion(clientResponse, options);

                            if (result.Status.ToLower() == "ok")
                            {
                                ApplicationUser user = await UserManager.FindByNameAsync(
                                    FIDO.DataProvider.GetUserByCredential(clientResponse.RawId).Name);

                                // ロックアウト
                                if (user.LockoutEndDateUtc != null
                                    && DateTime.Now <= user.LockoutEndDateUtc)
                                {
                                    signInStatus = SignInStatus.LockedOut;
                                }
                                // 2FAは不要（デバイス特定されているため）
                                //else if (true) { }
                                else
                                {
                                    await SignInManager.SignInAsync(user, false, false);
                                    signInStatus = SignInStatus.Success;
                                }

                                return VerifySignInStatus(signInStatus, model, user);
                            }
                        }
                        catch (Exception e)
                        {
                            result = new AssertionVerificationResult
                            {
                                Status = "error",
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
                        if (await UserManager.IsEmailConfirmedAsync(user.Id))
                        {
                            // ロックアウト
                            if (user.LockoutEndDateUtc != null
                                && DateTime.Now <= user.LockoutEndDateUtc)
                            {
                                signInStatus = SignInStatus.LockedOut;
                            }
                            // 2FAは不要（デバイス特定されているため）
                            //else if (true) { }
                            else
                            {
                                string fido2Challenge = (string)Session["fido2Challenge"];

                                FIDO.MsPassHelper msPassHelper = new FIDO.MsPassHelper(user.FIDO2PublicKey, fido2Challenge);
                                if (msPassHelper.ValidateSignature(
                                    (string)fido2Data["fido2ClientData"],
                                    (string)fido2Data["fido2AuthenticatorData"],
                                    (string)fido2Data["fido2Signature"]))
                                {
                                    await SignInManager.SignInAsync(user, false, false);
                                    signInStatus = SignInStatus.Success;
                                }
                                else
                                {
                                    signInStatus = SignInStatus.Failure;
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
        /// <param name="signInStatus">SignInStatus</param>
        /// <param name="model">AccountLoginViewModel</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ActionResult</returns>
        private ActionResult VerifySignInStatus(SignInStatus signInStatus, AccountLoginViewModel model, ApplicationUser user)
        {
            // SignInStatus
            switch (signInStatus)
            {
                case SignInStatus.Success:
                    // サインイン成功

                    // テスト機能でSession["state"]のチェックを止めたので不要になった。
                    // また、ManageControllerの方はログイン済みアクセスになるので。

                    // AppScan指摘の反映
                    this.FxSessionAbandon();
                    // SessionIDの切換にはこのコードが必要である模様。
                    // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                    Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

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

                case SignInStatus.LockedOut:
                    // ロックアウト
                    return View("Lockout");

                case SignInStatus.RequiresVerification:
                    // EmailConfirmedとは別の2FAが必要。

                    // 検証を求める（2FAなど）。
                    return this.RedirectToAction(
                        "SendCode", new
                        {
                            ReturnUrl = model.ReturnUrl,  // 戻り先のURL
                            RememberMe = model.RememberMe // アカウント記憶
                        });

                case SignInStatus.Failure:
                // サインイン失敗

                default:
                    // その他
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
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
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
                                await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                                await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);
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
                    IdentityResult result = await UserManager.ConfirmEmailAsync(userId, code);

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
                            IdentityResult result = await UserManager.ConfirmEmailAsync(model.UserId, model.Code);

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
                IdentityResult result = await UserManager.ResetPasswordAsync(model.UserId, model.Code, model.Password);

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
                        Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

                        //// オペレーション・トレース・ログ出力 できない（User.Identity.GetUserId() == null
                        //ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                        //Logging.MyOperationTrace(string.Format("{0}({1}) did 2fa sign in.", user.Id, user.UserName));

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
                            Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

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
                                    Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

                                    // オペレーション・トレース・ログ出力
                                    Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                                    // リダイレクト
                                    return RedirectToLocal(returnUrl);
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
                                user = ApplicationUser.CreateUser(uid, true);

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

                                    // ロールに追加。
                                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);

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
                                        Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

                                        // オペレーション・トレース・ログ出力
                                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed up with a verified external account.", user.Id, user.UserName));

                                        // リダイレクト
                                        return RedirectToLocal(returnUrl);
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
                                    // ユーザの新規作成が失敗した場合

                                    // 結果のエラー情報を追加
                                    this.AddErrors(result);
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
                if (state == (string)Session["id_federation_signin_state"])
                {
                    // state正常
                    Session["id_federation_signin_state"] = ""; // 誤動作防止

                    #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri = Config.IdFederationRedirectEndPoint;

                    // Tokenエンドポイントにアクセス
                    model.Response = await OAuth2.Helper.GetInstance().GetAccessTokenByCodeAsync(
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
                            && jobj[OAuth2AndOIDCConst.nonce].ToString() == (string)Session["id_federation_signin_nonce"])
                        {
                            // id_token検証OK。
                        }
                        else
                        {
                            // id_token検証NG。
                            return View("Error");
                        }

                        Session["id_federation_signin_nonce"] = ""; // 誤動作防止                            
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
                            await this.UserManager.AddToRoleAsync(user.Id, roleName);
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
                        IList<string> currentRoles = await UserManager.GetRolesAsync(user.Id);

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
                                await this.UserManager.AddToRoleAsync(user.Id, roleName);
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
                                await this.UserManager.RemoveFromRoleAsync(user.Id, roleName);
                            }
                        }
                    }

                    #region サインイン

                    if (result.Succeeded == true)
                    {
                        // EmailConfirmed == true の場合、
                        // パスワード入力失敗回数に基づいてアカウントがロックアウトされるように設定するには、shouldLockout: true に変更する
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                        // AppScan指摘の反映
                        this.FxSessionAbandon();
                        // SessionIDの切換にはこのコードが必要である模様。
                        // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
                        Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));

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

        /// <summary>認可エンドポイント</summary>
        /// <param name="client_id">string（必須）</param>
        /// <param name="redirect_uri">string（任意）</param>
        /// <param name="response_type">string（必須）</param>
        /// <param name="response_mode">string（任意）</param>
        /// <param name="scope">string（任意）</param>
        /// <param name="state">string（推奨）</param>
        /// <param name="nonce">string（OIDC）</param>
        /// <param name="prompt">string（OIDC）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpGet]
        public ActionResult OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce, string prompt) // OpenID Connect
            // string code_challenge, string code_challenge_method) // OAuth PKCE // Request.QueryStringで直接参照
        {
            if (CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, response_type, scope, nonce,
                out string valid_redirect_uri, out string err, out string errDescription))
            {
                // Cookie認証チケットからClaimsIdentityを取得しておく。
                AuthenticateResult ticket = this.AuthenticationManager
                    .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
                ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

                // scopeパラメタ
                string[] scopes = (scope ?? "").Split(' ');

                if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    // OAuth2/OIDC Authorization Code
                    ViewBag.Name = identity.Name;
                    ViewBag.Scopes = scopes;

                    // 認証の場合、余計なscopeをfilterする。
                    bool isAuth = scopes.Any(x => x.ToLower() == OAuth2AndOIDCConst.Scope_Auth);

                    if (string.IsNullOrWhiteSpace(prompt)) prompt = "";

                    if (isAuth                           // OAuth2 拡張仕様
                        || prompt.ToLower() == "none")   // OIDC   RFC仕様
                    {
                        // 認可画面をスキップ

                        // ClaimsIdentityを生成
                        identity = new ClaimsIdentity(
                            identity.Claims, OAuth2AndOIDCConst.Bearer, identity.NameClaimType, identity.RoleClaimType);

                        // ★ 必要に応じてスコープのフィルタ
                        if (isAuth)
                        {
                            scopes = OAuth2.Helper.FilterClaimAtAuth(scopes).ToArray();
                        }

                        // ★ Codeの生成
                        string code = CmnEndpoints.CreateCodeInAuthZNRes(
                            identity, Request.QueryString, client_id, state, scopes, nonce);

                        // RedirectエンドポイントへRedirect
                        if (string.IsNullOrEmpty(response_mode) ||
                            response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit())
                        {
                            return new RedirectResult(valid_redirect_uri + string.Format("?code={0}&state={1}", code, state));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            return new RedirectResult(valid_redirect_uri + string.Format("#code={0}&state={1}", code, state));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_postに必要な、HTTP response message body
                            string body =
                                "<html>" +
                                "  <body onload=\"javascript: document.forms[0].submit()\">" +
                                "    <form method=\"post\" action =\"{0}\">" +
                                "      <input type=\"hidden\" name =\"code\" value =\"{1}\"/>" +
                                "      <input type=\"hidden\" name =\"state\"  value =\"{2}\"/>" +
                                "    </form>" +
                                "  </body>" +
                                "</html>";

                            // bodyに組み込んで
                            body = string.Format(body, valid_redirect_uri, code, state);

                            return this.Content(body);
                        }
                        else
                        {
                            // 不正な操作
                        }
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

                    // ClaimsIdentityを生成
                    identity = new ClaimsIdentity(
                        identity.Claims, OAuth2AndOIDCConst.Bearer, identity.NameClaimType, identity.RoleClaimType);

                    // ★ Tokenの生成
                    CmnEndpoints.CreateAuthZRes4ImplicitFlow(
                        identity, Request.QueryString,
                        response_type, client_id, state, scopes, nonce,
                        out string access_token, out string id_token);

                    // RedirectエンドポイントへRedirect
                    switch (response_type)
                    {
                        case OAuth2AndOIDCConst.ImplicitResponseType:
                            if (string.IsNullOrEmpty(access_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri + string.Format(
                                    "#access_token={0}&state={1}&token_type={2}&expires_in={3}",
                                    access_token, state, "bearer", Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                            }
                            
                        case OAuth2AndOIDCConst.OidcImplicit1_ResponseType:
                            if (string.IsNullOrEmpty(id_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#id_token={0}&state={1}", id_token, state));
                            }
                            
                        case OAuth2AndOIDCConst.OidcImplicit2_ResponseType:
                            if (string.IsNullOrEmpty(id_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri + string.Format(
                                    "#id_token={0}&access_token={1}&state={2}&token_type={3}&expires_in={4}",
                                    id_token, access_token, state, "bearer", Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                            }
                            
                        default:
                            break;
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    // Hybrid Flow

                    // アクセス要求を保存して、仲介コードを発行する。
                    identity = new ClaimsIdentity(
                        identity.Claims, OAuth2AndOIDCConst.Bearer, identity.NameClaimType, identity.RoleClaimType);

                    // ★ Tokenの生成
                    string code = CmnEndpoints.CreateAuthNRes4HybridFlow(
                        identity, Request.QueryString,
                        client_id, state, scopes, nonce,
                        out string access_token, out string id_token);

                    // RedirectエンドポイントへRedirect
                    switch (response_type)
                    {
                        case OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType:
                            if (string.IsNullOrEmpty(access_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri + string.Format(
                                    "#code={0}&access_token={1}&state={2}&token_type={3}&expires_in={4}",
                                    code, access_token, state, "bearer",
                                    Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                            }
                            
                        case OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType:
                            if (string.IsNullOrEmpty(id_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri + string.Format(
                                    "#code={0}&id_token={1}", code, id_token));
                            }
                            
                        case OAuth2AndOIDCConst.OidcHybrid3_ResponseType:
                            if (string.IsNullOrEmpty(id_token))
                            {
                                return new RedirectResult(valid_redirect_uri
                                    + string.Format("#error=access_denied&state={0}", state));
                            }
                            else
                            {
                                return new RedirectResult(valid_redirect_uri + string.Format(
                                    "#code={0}&access_token={1}&id_token={2}&state={3}&token_type={4}&expires_in={5}",
                                    code, access_token, id_token, state, "bearer",
                                    Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds));
                            }
                            
                        default:
                            break;
                    }
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

            // 再表示
            return View();
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
        /// <param name="nonce">string（OIDC）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce) // OpenID Connect
        {
            if (CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, response_type, scope, nonce,
                out string valid_redirect_uri, out string err, out string errDescription))
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
                    identity = new ClaimsIdentity(
                        identity.Claims, OAuth2AndOIDCConst.Bearer, identity.NameClaimType, identity.RoleClaimType);
                    
                    // ★ Codeの生成
                    string code = CmnEndpoints.CreateCodeInAuthZNRes(
                        identity, Request.QueryString, client_id, state, scopes, nonce);

                    // RedirectエンドポイントへRedirect
                    if (string.IsNullOrEmpty(response_mode) ||
                        response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit())
                    {
                        return new RedirectResult(valid_redirect_uri + string.Format("?code={0}&state={1}", code, state));
                    }
                    else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                    {
                        return new RedirectResult(valid_redirect_uri + string.Format("#code={0}&state={1}", code, state));
                    }
                    else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                    {
                        // form_postに必要な、HTTP response message body
                        string body =
                            "<html>" +
                            "  <body onload=\"javascript: document.forms[0].submit()\">" +
                            "    <form method=\"post\" action =\"{0}\">" +
                            "      <input type=\"hidden\" name =\"code\" value =\"{1}\"/>" +
                            "      <input type=\"hidden\" name =\"state\"  value =\"{2}\"/>" +
                            "    </form>" +
                            "  </body>" +
                            "</html>";

                        // bodyに組み込んで
                        body = string.Format(body, valid_redirect_uri, code, state);

                        return this.Content(body);
                    }
                    else
                    {
                        // 不正な操作
                    }
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

            // client_id
            string clientId_InSessionOrCookie = (string)Session["test_client_id"];
            if (string.IsNullOrEmpty(clientId_InSessionOrCookie))
            {
                clientId_InSessionOrCookie = Request.Cookies["test_client_id"].Value;
            }

            // state
            string state_InSessionOrCookie = (string)Session["test_state"];
            if (string.IsNullOrEmpty(state_InSessionOrCookie))
            {
                state_InSessionOrCookie = Request.Cookies["test_state"].Value;
            }

            // nonce
            string nonce_InSessionOrCookie = (string)Session["test_nonce"];
            if (string.IsNullOrEmpty(nonce_InSessionOrCookie))
            {
                nonce_InSessionOrCookie = Request.Cookies["test_nonce"].Value;
            }

            // code_verifier
            string code_verifier_InSessionOrCookie = (string)Session["test_code_verifier"];
            if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
            {
                code_verifier_InSessionOrCookie = Request.Cookies["test_code_verifier"].Value;
            }

            // クリア
            Session["test_client_id"] = null;
            Response.Cookies["test_client_id"].Value = "";
            Session["test_state"] = null;
            Response.Cookies["test_state"].Value = "";
            Session["test_code_verifier"] = null;
            Response.Cookies["test_code_verifier"].Value = "";

            #endregion

            if (!Config.IsLockedDownRedirectEndpoint)
            {
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

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri
                    = Config.OAuth2ClientEndpointsRootURI
                    + Config.OAuth2AuthorizationCodeGrantClient_Account;

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
                            OAuth2AndOIDCParams.RS256Pfx,
                            OAuth2AndOIDCParams.RS256Pwd, HashAlgorithmName.SHA256);

                        model.Response = await OAuth2.Helper.GetInstance().GetAccessTokenByCodeAsync(
                            tokenEndpointUri, redirect_uri, code, JwtAssertion.CreateJwtBearerTokenFlowAssertion(
                                iss, aud, new TimeSpan(0, 0, 30), Const.StandardScopes,
                                ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true)));
                    }
                    else if (state.StartsWith(fapi2Prefix))
                    {
                        // FAPI2

                        //  client_Idと、クライアント証明書（TB）
                        string client_id = clientId_InSessionOrCookie;

                        model.Response = await OAuth2.Helper.GetInstance()
                            .GetAccessTokenByCodeAsync(tokenEndpointUri,
                            client_id, "", redirect_uri, code);
                    }
                    else
                    {
                        // OAuth2 / OIDC

                        //  client_Idから、client_secretを取得。
                        string client_id = clientId_InSessionOrCookie;
                        string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                        if (string.IsNullOrEmpty(code_verifier_InSessionOrCookie))
                        {
                            // 通常
                            model.Response = await OAuth2.Helper.GetInstance()
                                .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                client_id, client_secret, redirect_uri, code);
                        }
                        else
                        {
                            // PKCE
                            model.Response = await OAuth2.Helper.GetInstance()
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
                }

                #endregion

                #region Access, Refresh, Id Tokenの検証と表示

                if (!dic.ContainsKey("error"))
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

                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.GetUserClaims")))
                    {
                        // UserInfoエンドポイントにアクセス
                        model.Response = await OAuth2.Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Refresh")))
                    {
                        #region Tokenエンドポイントで、Refresh Tokenを使用してAccess Tokenを更新

                        Uri tokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

                        // Tokenエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await OAuth2.Helper.GetInstance().
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
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.RevokeAccess"))
                        || !string.IsNullOrEmpty(Request.Form.Get("submit.RevokeRefresh")))
                    {
                        #region Revokeエンドポイントで、Tokenを無効化

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.RevokeAccess")))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.RevokeRefresh")))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri revokeTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint);

                        // Revokeエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await OAuth2.Helper.GetInstance().RevokeTokenAsync(
                            revokeTokenEndpointUri, client_id, client_secret, token, token_type_hint);

                        #endregion
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.IntrospectAccess"))
                        || !string.IsNullOrEmpty(Request.Form.Get("submit.IntrospectRefresh")))
                    {
                        #region Introspectエンドポイントで、Token情報を取得

                        // token_type_hint設定
                        string token = "";
                        string token_type_hint = "";

                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.IntrospectAccess")))
                        {
                            token = model.AccessToken;
                            token_type_hint = OAuth2AndOIDCConst.AccessToken;
                        }

                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.IntrospectRefresh")))
                        {
                            token = model.RefreshToken;
                            token_type_hint = OAuth2AndOIDCConst.RefreshToken;
                        }

                        Uri introspectTokenEndpointUri = new Uri(
                            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint);

                        // Introspectエンドポイントにアクセス

                        //  client_Idから、client_secretを取得。
                        string client_id = model.ClientId;
                        string client_secret = OAuth2.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await OAuth2.Helper.GetInstance().IntrospectTokenAsync(
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
                return RedirectToAction("Index", "Home");
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
            code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Account",
                    new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);

            // E-mailの送信
            string subject = GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm);
            string body = GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg);
            await UserManager.SendEmailAsync(user.Id, subject, string.Format(body, callbackUrl, user.UserName));
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
            code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);

            // URLの生成
            callbackUrl = Url.Action(
                    "ResetPassword", "Account",
                    new { userId = user.Id, code = code }, protocol: Request.Url.Scheme
                );

            // E-mailの送信
            await UserManager.SendEmailAsync(
                    user.Id, GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
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
            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = GetContentOfLetter.Get("RegistationWasCompletedEmailTitle", CustomEncode.UTF_8, "");
            idmsg.Destination = user.Email;
            idmsg.Body = string.Format(GetContentOfLetter.Get("RegistationWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName);

            await ems.SendAsync(idmsg);
        }

        /// <summary>
        /// パスワード リセットの完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendPasswordResetCompletedEmail(ApplicationUser user)
        {
            // パスワード リセット用のメールを送信
            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = GetContentOfLetter.Get("PasswordResetWasCompletedEmailTitle", CustomEncode.UTF_8, "");
            idmsg.Destination = user.Email;
            idmsg.Body = string.Format(GetContentOfLetter.Get("PasswordResetWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName);

            await ems.SendAsync(idmsg);
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
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_SystemAdmin);
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);
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
                            (await this.UserManager.FindByNameAsync("super_tanaka@gmail.com")).Id, Const.Role_User);
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("super_tanaka@gmail.com")).Id, Const.Role_Admin);
                    }

                    // 一般ユーザを作成
                    user = ApplicationUser.CreateUser("tanaka@gmail.com", true);
                    result = await this.UserManager.CreateAsync(user, password);
                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            (await this.UserManager.FindByNameAsync("tanaka@gmail.com")).Id, Const.Role_User);
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