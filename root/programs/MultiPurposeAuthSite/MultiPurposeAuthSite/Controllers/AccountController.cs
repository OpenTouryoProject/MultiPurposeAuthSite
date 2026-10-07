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
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/02/28  西野 大介         エラーメッセージ通知の改善
//*  2020/03/04  西野 大介         CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2020/12/21  西野 大介         Device AuthZ対応実施
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/07  玄人 幸道         expires_inが常に0になる不具合を修正（#182）
//*  2026/09/08  玄人 幸道         エラー応答とRedirect URLをRFC 6749に合わせる（#187）
//*  2026/09/16  玄人 幸道         2FAのコード送信の失敗を、画面に戻して伝える（#214）
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認の待ち受け（TwoFactorPushStatus）を追加（#216）
//*  2026/09/17  玄人 幸道         IsLockedDownRedirectEndpoint を IsLockedDownTestEndpoints に改名（#219）
//*  2026/09/18  玄人 幸道         認可リクエストの code_challenge を検証に渡す（#220）
//*  2026/09/25  玄人 幸道         設定キーの改名（IdFederation*Endpoint）に追随（#236）
//*  2026/09/27  玄人 幸道         RP-Initiated Logout（/end_session）を追加（#232）
//*  2026/09/28  玄人 幸道         FAPI2 の自己テストのトークン交換を private_key_jwt にした（#246）
//*  2026/09/28  玄人 幸道         アサーションの組み立てを SelfTestClient へ寄せた（#246）
//*  2026/09/28  玄人 幸道         SAML2 の応答（アサーション）を画面に出す（#246 の項目 3）
//*  2026/09/28  玄人 幸道         認可画面に、確かめる内容（prompt / max_age など）を出す（#246 の項目 3）
//*  2026/09/28  玄人 幸道         max_age の超過で再認証し、prompt=none なら login_required を返す（#247）
//*  2026/09/30  玄人 幸道         ID 連携の Error に理由のトレースを足す（#253）
//*  2026/09/30  玄人 幸道         未サインイン＋prompt=none で login_required を返す（#254）
//*  2026/09/30  玄人 幸道         自身が書く Cookie の名前に接頭辞を付けられるようにした（#255）
//*  2026/09/30  玄人 幸道         既存アカウントへメアドで結ぶとき email_verified を確かめるようにした（#140 の段階 1）
//*  2026/09/30  玄人 幸道         Facebook / Twitter 固有のメアド取得を削除（#249）
//*  2026/09/30  玄人 幸道         ID 連携の鍵を (iss, sub) にし、iss の検証と PKCE(S256) を追加（#140 の段階 3）
//*  2026/10/01  玄人 幸道         利用者名とメアドの両方でサインインできるようにし、サインアップを見直した（#151 の段階 3）
//*  2026/10/01  玄人 幸道         ID 連携の新規作成で preferred_username を優先（#151 の段階 4）
//*  2026/10/03  玄人 幸道         テスト利用者の名前に接尾辞を付けられるようにした（#260）
//*  2026/10/03  玄人 幸道         E2E専用のクライアント登録を種データにした（#264）
//*  2026/10/03  玄人 幸道         2人目のテスト利用者に標準クレームのサンプルを仕込む（#261）
//*  2026/10/04  玄人 幸道         response_typeを正規化して受ける（#267）
//*  2026/10/06  玄人 幸道         種データのクライアント登録を専用列で作る（#270）
//*  2026/10/06  玄人 幸道         promptの照合を集合に寄せた（#272 の段階 1）
//*  2026/10/06  玄人 幸道         同意を記録し、promptの各値を処理（#272 の段階 2）
//*  2026/10/07  玄人 幸道         WebAuthn / MsPass のサインインを削除（#137）
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
using Token = MultiPurposeAuthSite.TokenProviders;
using Saml = MultiPurposeAuthSite.SamlProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Configuration;

using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Web.Configuration;
//using System.Net;
//using System.Net.Http;
using System.Net.Http.Formatting;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Facebook;


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

        #region IdP (Identity Provider)

        /// <summary>InitSessionAfterlogin</summary>
        private void InitSessionAfterlogin()
        {
            // AppScan指摘の反映
            this.FxSessionAbandon();
            // SessionIDの切換にはこのコードが必要である模様。
            // https://support.microsoft.com/ja-jp/help/899918/how-and-why-session-ids-are-reused-in-asp-net
            Response.Cookies.Add(new HttpCookie(this.SessionCookieName, ""));
            Response.Cookies[Config.AuthTimeCookieName].Value = FormatConverter.ToW3cTimestamp(DateTime.UtcNow);
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

            string loginHint = "";

            if (!string.IsNullOrEmpty(returnUrl))
            {
                // RawUrlから、UrlデコードしたReturnUrlを取得
                returnUrl = CustomEncode.UrlDecode(
                    StringExtractor.GetParameterFromQueryString("ReturnUrl", Request.RawUrl));
                //ViewBag.ReturnUrl = returnUrl;

                // ReturnUrlからLoginHintを取得
                loginHint = CustomEncode.UrlDecode(
                    StringExtractor.GetParameterFromQueryString("login_hint", returnUrl));
                //ViewBag.LoginHint = loginHint;
            }

            // サインイン画面（初期表示）
            // **WebAuthn は net48 版では扱わない**（#137）。
            //   **現行版の WebAuthn ライブラリが netstandard2.0 を支えていない。**
            //   **ビューの欄は残す**（ViewModel を両系統で共有しているため）。
            string fido2Challenge = "";
            string sequenceNo = "";

            // **Email 欄が「利用者名またはメアド」の入力である**（#151 の段階 3）。
            //   **欄の名前は変えていない。** ビュー・リソース・E2E・ID 連携の login_hint に
            //   波及するため、名前の整理は後の段階に回す。
            return View(new AccountLoginViewModel
            {
                ReturnUrl = returnUrl,
                Email = loginHint,
                Fido2Data = fido2Challenge,
                SequenceNo = sequenceNo
            });
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
                        // **利用者名とメアドの、どちらでも受ける**（#151 の段階 3）。
                        //   **`@` を含むならメアド**として引く（利用者名に `@` は禁じている）。
                        string uid = model.Email;

                        ApplicationUser user = Const.LooksLikeEmail(uid)
                            ? await UserManager.FindByEmailAsync(uid)
                            : await UserManager.FindByNameAsync(uid);

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
                                // **入力した値ではなく、引いた利用者の利用者名で署名する**（#151 の段階 3）。
                                //   **メアドで引いた場合、入力値は利用者名ではない。**
                                signInStatus = await SignInManager.PasswordSignInAsync(
                                    userName: user.UserName,                                      // アカウント(UID)
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

                    // **入力された値を、そのまま login_hint として上流へ渡す**（#151 の段階 3）。
                    //   利用者名でもメアドでもよい（上流がどう解釈するかは上流しだい）。
                    string uid = model.Email;

                    // 認可エンドポイント
                    string oAuthAuthorizeEndpoint =
                        Config.OAuth2AuthorizationServerEndpointsRootURI
                        + Config.OAuth2AuthorizeEndpoint;

                    // client_id
                    string client_id = OAuth2AndOIDCParams.ClientID;
                    //OAuth2Helper.GetInstance().GetClientIdByName("IdFederation");

                    // state // 記号は入れない。
                    //   **32 文字にした**（#140 の段階 3）。10 文字では短い。
                    //   PKCE があるので CSRF は守られるが、**推測しにくい方がよい。**
                    string state = GetPassword.Generate(32, 0);
                    Session["id_federation_signin_state"] = state;

                    // redirect_uri
                    string redirect_uri = Config.IdFederationRedirectEndpoint;

                    // nonce // 記号は入れない。
                    string nonce = GetPassword.Generate(20, 0);
                    Session["id_federation_signin_nonce"] = nonce;

                    // ID連携に必要なscope
                    string scope = Const.IdFederationScopes;

                    // **PKCE を付ける**（#140 の段階 3）。
                    //   これまで client_secret だけだった。**OAuth 2.1 は、秘密を持つ
                    //   クライアントでも PKCE を付けることを求める**（コードの横取りに備える）。
                    //   相手が PKCE を見ない OP でも、**余分なパラメタとして無視されるだけ**なので壊れない。
                    string codeVerifier = GetPassword.Base64UrlSecret(50);
                    Session["id_federation_signin_verifier"] = codeVerifier;

                    return Redirect(
                        Config.IdFederationAuthorizeEndpoint +
                        "?client_id=" + client_id +
                        "&response_type=code" +
                        "&scope=" + scope +
                        "&state=" + state +
                        "&nonce=" + nonce +
                        "&redirect_uri=" + CustomEncode.UrlEncode(redirect_uri) +
                        "&response_mode=form_post" +
                        "&code_challenge="
                            + OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(codeVerifier) +
                        "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256 +
                        "&login_hint=" + uid + "&prompt=none");
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

        #region RP-Initiated Logout（#232）

        /// <summary>
        /// RP からのログアウト要求（初期表示・GET）
        /// GET: /end_session
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <remarks>**GET と POST の両方を受けることが MUST**（RP-Initiated Logout 1.0 §2）。</remarks>
        [HttpGet]
        [AllowAnonymous] // 空振りできるように（§4 : サインインしていなくてもエラーではない）。
        public async Task<ActionResult> EndSession()
        {
            return await this.EndSessionCore(
                Request.QueryString[OAuth2AndOIDCConst.id_token_hint],
                Request.QueryString[OAuth2AndOIDCConst.client_id],
                Request.QueryString[Token.CmnEndpoints.PostLogoutRedirectUri],
                Request.QueryString[OAuth2AndOIDCConst.state],
                false);
        }

        /// <summary>
        /// RP からのログアウト要求（POST）
        /// POST: /end_session
        /// </summary>
        /// <param name="dummy">FormDataCollectionは、WebAPI専用らしい（DeviceAuthZVerify と同じ）。</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> EndSession(string dummy)
        {
            return await this.EndSessionCore(
                Request.Form[OAuth2AndOIDCConst.id_token_hint],
                Request.Form[OAuth2AndOIDCConst.client_id],
                Request.Form[Token.CmnEndpoints.PostLogoutRedirectUri],
                Request.Form[OAuth2AndOIDCConst.state],
                false);
        }

        /// <summary>
        /// 確認画面（EndSession）からの応答
        /// POST: /Account/EndSessionConfirm
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **こちらは画面からの応答なので、CSRF のトークンを検証する。**
        /// RP からの /end_session はトークンを持てないので、そちらでは検証しない
        /// （**確認を求めること自体が、勝手なログアウトへの対策**。§6）。
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EndSessionConfirm()
        {
            if (string.IsNullOrEmpty(Request.Form["allow"]))
            {
                // 「いいえ」。ログアウトしない（RP へも戻さない）。
                return RedirectToAction("Index", "Home");
            }

            return await this.EndSessionCore(
                Request.Form[OAuth2AndOIDCConst.id_token_hint],
                Request.Form[OAuth2AndOIDCConst.client_id],
                Request.Form[Token.CmnEndpoints.PostLogoutRedirectUri],
                Request.Form[OAuth2AndOIDCConst.state],
                true);
        }

        /// <summary>ログアウト要求の本体（GET / POST / 確認の応答で共通）</summary>
        /// <param name="idTokenHint">id_token_hint</param>
        /// <param name="clientId">client_id</param>
        /// <param name="postLogoutRedirectUri">post_logout_redirect_uri</param>
        /// <param name="state">state</param>
        /// <param name="confirmed">利用者が確認画面で「はい」を押したか</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **判定は CmnEndpoints.ReceiveEndSessionRequest（両アプリ共通）。**
        /// ここは「確認画面を出すか」「サインアウト」「リダイレクト」だけを行う。
        /// </remarks>
        private async Task<ActionResult> EndSessionCore(
            string idTokenHint, string clientId,
            string postLogoutRedirectUri, string state, bool confirmed)
        {
            bool signedIn = User.Identity.IsAuthenticated;

            Token.CmnEndpoints.ReceiveEndSessionRequest(
                idTokenHint, clientId, postLogoutRedirectUri, state,
                signedIn ? User.Identity.Name : "",
                out bool verified, out string redirectUri,
                out string err, out string errDescription);

            // **利用者に確認しなければならない場合**（§2 の MUST / §6）。
            //   - id_token_hint が無い、または現在のセッションの利用者と一致しない
            //   - 要求に誤りがある（RP へは戻さないので、画面で知らせる。§4）
            //   **サインインしていなければ、消すものが無いので確認しない**（§4 : エラーではない）。
            if (!confirmed && signedIn && (!verified || !string.IsNullOrEmpty(err)))
            {
                ViewBag.IdTokenHint = idTokenHint;
                ViewBag.ClientId = clientId;
                ViewBag.PostLogoutRedirectUri = postLogoutRedirectUri;
                ViewBag.State = state;
                ViewBag.Error = errDescription;

                return View("EndSession");
            }

            if (signedIn)
            {
                // サインアウト（Cookieの削除）
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) has signed out by RP-Initiated Logout.", user.Id, user.UserName));
            }

            if (!string.IsNullOrEmpty(redirectUri))
            {
                // **戻してよいと判定できた場合だけ**（§3）。
                return Redirect(redirectUri);
            }

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

                    // **利用者名とメアドの両方を受け取る**（#151 の段階 3）。
                    //   以前はどちらか一方を `uid` に潰していた（画面には両方在ったのに）。
                    string userName = model.Name;
                    string email = model.Email;

                    // **利用者名に `@` を禁じる**（サインインの入力がどちらなのか決まらなくなるため）。
                    if (!Const.IsValidUserName(userName))
                    {
                        ModelState.AddModelError("", Resources.AccountController.Register_InvalidUserName);
                    }
                    else if (!string.IsNullOrWhiteSpace(email))
                    {
                        // 利用者名もメアドも在る場合。

                        #region サインアップ

                        // ユーザを作成
                        ApplicationUser user = ApplicationUser.CreateUser(userName, email, false);

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

                            // **メアドは常に在るので、必ず検証する**（#151 の段階 3）。
                            //   以前は「メアド無し」の配備があり、そのときは
                            //   約款画面またはサインイン画面へ直行していた。
                            //   **約款は、メアド検証のリンクを踏んだ後に出る**（下の Agreement）。

                            // サインインの前にメアド検証用のメールを送信して、
                            this.SendConfirmEmail(user);

                            // VerifyEmailAddress画面へ遷移
                            return View("VerifyEmailAddress");

                            #endregion
                        }
                        else
                        {
                            #region サインアップ失敗

                            // サインアップ済みの可能性を探る
                            //   **メアドで引く**（#151 の段階 3。鍵はメアド）。
                            ApplicationUser oldUser = await UserManager.FindByEmailAsync(email);

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
                                            // **メアドは常に在るので、必ず検証の再送をする**（#151 の段階 3）。
                                            //   以前は「メアド無し」の配備があり、そのときは約款画面へ直行していた。

                                            // メアド検証用のメールを送信して、
                                            this.SendConfirmEmail(user);

                                            // VerifyEmailAddress
                                            return View("VerifyEmailAddress");
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

                    // **メアドのアクティベーションを必ず伴う**（#151 の段階 3）。
                    //   以前は「メアド無し」の配備があり、そのときは EmailConfirmed を
                    //   直に true にしてサインイン画面へ送っていた。
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

        #region 2 要素認証 (2FA :2 factor authentication)

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

                // 2FA画面のコード送信画面に遷移
                return View(await this.CreateSendCodeViewModelAsync(userId, returnUrl, rememberMe));
            }
        }

        /// <summary>
        /// 2FA画面のコード送信画面のモデルを作る（#214）
        /// </summary>
        /// <param name="userId">検証されたアカウントのUID</param>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <returns>AccountSendCodeViewModelを非同期に返す</returns>
        /// <remarks>
        /// 初期表示（GET）と、送信に失敗したときの再表示（POST）で共用する。
        /// **2 箇所で一覧の作り方が食い違わないように、1 箇所にまとめる。**
        /// </remarks>
        private async Task<AccountSendCodeViewModel> CreateSendCodeViewModelAsync(
            string userId, string returnUrl, bool rememberMe)
        {
            // UIDから、2FAのプロバイダを取得する。
            IList<string> userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);

            // 2FAのプロバイダの一覧を取得する
            List<SelectListItem> factorOptions = userFactors.Select(
                purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();

            return new AccountSendCodeViewModel
            {
                Providers = factorOptions,  // 2FAのプロバイダの一覧
                ReturnUrl = returnUrl,      // 戻り先のURL
                RememberMe = rememberMe     // アカウント記憶
            };
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
                // **送信の失敗を、処理されない例外にしない**（#214）。
                //   SendTwoFactorCodeAsync の中でメール / SMS を送るため、
                //   ネットワーク障害や資格情報の誤りで例外になりうる。
                bool sent = false;

                try
                {
                    sent = await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider);
                }
                catch (Exception ex)
                {
                    // **原因は、記録に残す。** 例外を受け止めると、
                    //   これまで OnException が ACCESS ログに書いていた内容が失われるため。
                    Logging.MyDebugLogForEx(ex);
                }

                if (sent)
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
                    // 失敗（送信できなかったことを画面で伝え、別の送信先を選び直せるようにする）
                    ModelState.AddModelError("", Resources.AccountController.SendCodeError);
                }
            }
            else
            {
                // AccountSendCodeViewModelの検証に失敗
            }

            // 再表示
            // **モデルを渡さないとビューが落ちる**（Model.ReturnUrl などを読むため）（#214）。
            string currentUserId = await SignInManager.GetVerifiedUserIdAsync();

            if (currentUserId == null)
            {
                // 2FA の途中ではない
                return View("Error");
            }

            return View(await this.CreateSendCodeViewModelAsync(
                currentUserId, model.ReturnUrl, model.RememberMe));
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

                        // セッションの初期化
                        this.InitSessionAfterlogin();

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

        /// <summary>
        /// 2FAのプッシュ承認の状態を返す（#216）
        /// GET: /Account/TwoFactorPushStatus
        /// </summary>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberBrowser">ブラウザ記憶(2FA)</param>
        /// <returns>
        /// 承認済みなら { "approved": true, "redirectUrl": "..." }、まだなら { "approved": false }
        /// </returns>
        /// <remarks>
        /// **待っているのはブラウザである。**
        /// 認証デバイスは /2fa_result に承認を送るだけで、サインインは完了できない
        /// （2FA のセッションはブラウザの Cookie にあり、端末からは触れない）。
        /// そこで、コードの入力画面（VerifyCode）からこの口をポーリングし、
        /// 承認されていれば、そのコードでサインインを完了させる。
        ///
        /// 承認は 1 回取り出すと消える（TwoFactorPushProvider.Receive）。
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> TwoFactorPushStatus(string returnUrl, bool rememberBrowser)
        {
            // 2FA のセッション（Cookie）から利用者を取る
            string userId = await SignInManager.GetVerifiedUserIdAsync();

            if (userId == null)
            {
                // 2FA の途中ではない
                return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
            }

            // 認証デバイスからの承認（無ければ null）
            string code = Sts.TwoFactorPushProvider.Receive(userId);

            if (string.IsNullOrEmpty(code))
            {
                // まだ承認されていない
                return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
            }

            // 承認されたコードでサインインを完了させる。
            // **検証は、画面から入力された場合と同じ経路を通る**（プロバイダも同じ）。
            SignInStatus result = await SignInManager.TwoFactorSignInAsync(
                provider: MobileAppTokenProvider.ProviderName,   // 2FAプロバイダ
                code: code,                                     // 2FAコ－ド
                isPersistent: rememberBrowser,                  // アカウント記憶
                rememberBrowser: rememberBrowser                // ブラウザ記憶(2FA)
                );

            if (result == SignInStatus.Success)
            {
                // セッションの初期化
                this.InitSessionAfterlogin();

                return Json(new
                {
                    approved = true,
                    // **戻り先は、ローカルかを確かめてから返す**（RedirectToLocal と同じ判定）。
                    //   外部のサイトへ誘導されないようにする。
                    redirectUrl = this.Url.IsLocalUrl(returnUrl)
                        ? returnUrl : this.Url.Action("Index", "Home")
                }, JsonRequestBehavior.AllowGet);
            }

            // 承認はあったが、サインインは成立しなかった（コードの期限切れ、ロックアウトなど）。
            // 画面は、そのまま手入力での完了を続けられる。
            return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
        }

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

                    // **Facebook / Twitter は取り下げた**（#249。`StartupAuth` で登録していない）。
                    //   **この 2 つだけ、メアドを取るための専用コードを抱えていた。**
                    //   Facebook は Graph の /me、Twitter は api.twitter.com/1.1 を直接叩いており、
                    //   **外部 API が変わるたびに追随の判断が要る**のが維持コストの中身だった。
                    //   **削除せずコメントアウトにしてある**（戻せるように）。
                    //
                    //   **emailClaim が無ければ email は空のまま**になり、
                    //   この後の「クレーム情報を取得できた」の判定で外れる（サインインは成立しない）。
                    //if (emailClaim == null)
                    //{
                    //    // emailClaimが取得できなかった場合、
                    //    if (externalLoginInfo.Login.LoginProvider == "Facebook")
                    //    {
                    //        ClaimsIdentity excIdentity = AuthenticationManager.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);
                    //        string access_token = excIdentity.FindFirstValue("FacebookAccessToken");
                    //        FacebookClient facebookClient = new FacebookClient(access_token);

                    //        // e.g. :
                    //        // "/me?fields=id,email,gender,link,locale,name,timezone,updated_time,verified,last_name,first_name,middle_name"
                    //        dynamic myInfo = facebookClient.Get("/me?fields=email,name,last_name,first_name,middle_name,gender");

                    //        email = myInfo.email; // Microsoft.Owin.Security.Facebookでは、emailClaimとして取得できない。
                    //        emailClaim = new Claim(ClaimTypes.Email, email); // emailClaimとして生成
                    //    }
                    //    else if (externalLoginInfo.Login.LoginProvider == "Twitter")
                    //    {
                    //        string access_token = externalLoginInfo.ExternalIdentity.Claims.Where(
                    //            x => x.Type == "urn:twitter:access_token").Select(x => x.Value).FirstOrDefault();
                    //        string access_secret = externalLoginInfo.ExternalIdentity.Claims.Where(
                    //            x => x.Type == "urn:twitter:access_secret").Select(x => x.Value).FirstOrDefault();

                    //        JObject myInfo = await WebAPIHelper.GetInstance().GetTwitterAccountInfo(
                    //            "include_email=true",
                    //            access_token, access_secret,
                    //            Config.TwitterAuthenticationClientId,
                    //            Config.TwitterAuthenticationClientSecret);

                    //        email = (string)myInfo[OAuth2AndOIDCConst.Scope_Email]; // Microsoft.Owin.Security.Twitterでは、emailClaimとして取得できない。
                    //        emailClaim = new Claim(ClaimTypes.Email, email); // emailClaimとして生成
                    //    }
                    //}
                    //else
                    if (emailClaim != null)
                    {
                        // emailClaimが取得できた場合、
                        email = emailClaim.Value;
                    }
                    #endregion

                    // **上流が「検証済み」と言っているか**（#140 の段階 1）。
                    //   **既定のプロバイダ構成では、このクレームは来ない。**
                    //   その場合は「言っていない」として扱う（無い ＝ false）。
                    string emailVerified =
                        identity.FindFirst(OAuth2AndOIDCConst.email_verified)?.Value;

                    // **鍵はメアド**（#151 の段階 3）。
                    //   以前は RequireUniqueEmail で「メアド」か「上流の識別子」かを選んでいた。
                    //   **メアドは常に在って一意**なので、鍵はメアドで決まる。
                    string uid = email;

                    // **新規に作るときの利用者名**（#151 の段階 3）。
                    //   上流の識別子がそのまま使えるならそれを、
                    //   **`@` を含んで使えないならメアドから作る**（利用者名に `@` は禁じている）。
                    string newUserName = Const.IsValidUserName(name)
                        ? name : Const.UserNameFromEmail(email);

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
                            // **メアドで引く**（#151 の段階 3。鍵がメアドになった）。
                            user = await UserManager.FindByEmailAsync(uid);

                            if (user != null)
                            {
                                // サインアップ済み → 外部ログイン追加だけで済む

                                // **メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない**（#140 の段階 1）。
                                if (Sts.AccountLink.CheckLinkToExistingUser(emailVerified)
                                        == Sts.AccountLinkCheck.NeedsVerifiedEmail)
                                {
                                    // **結び付けない。** 画面に理由を出し、明示的な追加へ誘導する。
                                    Logging.MyOperationTrace(string.Format(
                                        "Rejected linking an external login to {0}({1}) "
                                        + "because the upstream did not assert email_verified.",
                                        user.Id, user.UserName));

                                    ViewBag.Reason = Resources.AccountViews.ExternalLoginNeedsVerifiedEmail;

                                    return View("ExternalLoginFailure");
                                }

                                // 外部ログイン（ = UserLoginInfo ）の追加
                                // **メアドで引いているので、メアドの一致は自明**（#151 の段階 3）。
                                //   以前は「鍵が上流の識別子」の場合に備えて、ここで突き合わせていた。
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
                                    // SignInAsync、ExternalSignInAsync
                                    // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                    await SignInManager.SignInAsync(
                                        user,
                                        isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                        rememberBrowser: true); // rememberBrowser は true 固定

                                    //// この外部ログイン・プロバイダでサインイン
                                    //signInStatus = await SignInManager.ExternalSignInAsync(

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
                                // **利用者名とメアドを別に渡す**（#151 の段階 3）。
                                //   以前は uid を利用者名にしてから、メアドを後で入れ直していた。
                                user = ApplicationUser.CreateUser(newUserName, email, true);

                                // **上流が検証していないメアドを「確認済み」として定着させない**（#140 の段階 1）。
                                user.EmailConfirmed = Sts.AccountLink.EmailConfirmedForNewUser(emailVerified);

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

                                        // セッションの初期化
                                        this.InitSessionAfterlogin();

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
        public async Task<ActionResult> IDFederationRedirectEndPoint(string code, string state, string iss)
        {
            if (!Config.IsLockedDownTestEndpoints)
            {
                // **認可応答の `iss` を検証する**（RFC 9207。#140 の段階 3）。
                //   **Mix-Up 攻撃への対策**で、OAuth 2.1 が挙げているのはこの応答パラメタである。
                //   `id_token` の `iss` も照合しているが（IdToken.Verify → SpRp_Isser）、
                //   **応答そのものを見ていなかった。**
                //
                //   **来なければ通す。** RFC 9207 を実装していない OP があるため
                //   （この IdP 自身は #231 で出すようになった）。
                if (!string.IsNullOrEmpty(iss)
                    && !string.Equals(iss, CmnClientParams.Isser, StringComparison.Ordinal))
                {
                    Logging.MyOperationTrace(
                        "The iss of the authorization response did not match the expected issuer.");

                    return View("Error");
                }

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

                // **合わないときに理由を残す**（#253）。
                //   **この分岐には else が無く、末尾の View("Error") に落ちるだけだった**ので、
                //   **「なぜ Error になったか」がログから分からなかった。**
                //   **値そのものは出さない**（有無と長さだけ）。
                if (state != (string)Session["id_federation_signin_state"])
                {
                    Logging.MyOperationTrace(string.Format(
                        "The state of the authorization response did not match the session. (response: {0}, session: {1})",
                        AccountController.DescribeForTrace(state),
                        AccountController.DescribeForTrace((string)Session["id_federation_signin_state"])));
                }

                // stateの検証
                if (state == (string)Session["id_federation_signin_state"])
                {
                    // state正常
                    Session["id_federation_signin_state"] = ""; // 誤動作防止

                    #region 仲介コードを使用してAccess Token・Refresh Tokenを取得

                    // 仲介コードからAccess Tokenを取得する。
                    string redirect_uri = Config.IdFederationRedirectEndpoint;

                    // Tokenエンドポイントにアクセス
                    // **ここも Helper を通さない**（#140 の段階 3）。
                    //   **Helper は宛先のホストをコンテナの認可サーバへ書き換える**
                    //   （GetContainerizatedAuthZServerUri）。**ID フェデレーションの相手は他の IdP** なので、
                    //   通すと宛先が変わって壊れる。/userinfo は #246 で外していたが、
                    //   **こちらは残っていた。**
                    //
                    // **code_verifier を渡す**（#140 の段階 3）。
                    //   以前は "" を渡しており、**PKCE を使っていないのに PKCE の
                    //   オーバーロード（client_secret_post）を選んでいた。**
                    string codeVerifier = (string)Session["id_federation_signin_verifier"];
                    Session["id_federation_signin_verifier"] = ""; // 誤動作防止

                    model.Response = await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                            new Uri(Config.IdFederationTokenEndpoint),
                            client_id, client_secret, redirect_uri, code, codeVerifier);

                    #endregion

                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    #region id_tokenの検証コード

                    string sub = "";
                    string nonce = "";
                    JObject jobj = null;

                    // **id_token の payload を取っておく**（#140 の段階 3）。
                    //   jobj は、この後 /userinfo の応答で上書きされる。
                    //   **連携キー（iss / sub）は、署名を検証した id_token 側から取る。**
                    JObject idTokenPayload = null;

                    if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                    {
                        // id_tokenがある。
                        string id_token = dic[OAuth2AndOIDCConst.IDToken];
                        string access_token = dic[OAuth2AndOIDCConst.AccessToken];

                        // **結果を控えておく**（#253）。**失敗したときに、どちらで落ちたかを残すため。**
                        bool idTokenVerified =
                            IdToken.Verify(id_token, access_token, code, state, out sub, out nonce, out jobj);
                        bool nonceMatched =
                            (nonce == (string)Session["id_federation_signin_nonce"]);

                        if (idTokenVerified && nonceMatched)
                        {
                            // id_token検証OK。
                            idTokenPayload = jobj;
                        }
                        else
                        {
                            // id_token検証NG。
                            // **理由を残す**（#253）。署名・クレームの検証と nonce の照合を分けて出す。
                            Logging.MyOperationTrace(string.Format(
                                "The id_token of the ID federation was not accepted. (verified: {0}, nonce matched: {1})",
                                idTokenVerified, nonceMatched));

                            return View("Error");
                        }

                        Session["id_federation_signin_nonce"] = ""; // 誤動作防止
                    }
                    else
                    {
                        // id_tokenがない。
                        // **理由を残す**（#253）
                        Logging.MyOperationTrace(
                            "The token response of the ID federation had no id_token.");

                        return View("Error");
                    }

                    #endregion

                    #region /userinfoエンドポイント
                    // /userinfoエンドポイントにアクセスする場合

                    // **ここは Helper を通さない**（#246 で確かめた）。
                    //   Helper の WebAPI 呼び出しは、すべて GetContainerizatedAuthZServerUri を通し、
                    //   **宛先のホストをコンテナの認可サーバへ書き換える。**
                    //   ID フェデレーションの相手は**他の IdP** なので、通すと宛先が変わって壊れる。
                    //   （Helper.GetUserInfoAsync は URI を引数に取らず、常に自分の /userinfo を向く）
                    string response = await OAuth2AndOIDCClient.GetUserInfoAsync(
                        new Uri(Config.IdFederationUserInfoEndpoint), dic[OAuth2AndOIDCConst.AccessToken]);
                    #endregion

                    #region ユーザの登録・更新

                    IdentityResult result = null;
                    SignInStatus signInStatus = SignInStatus.Failure;

                    // クレーム情報（ID情報とe-mail, name情報）を抽出
                    jobj = (JObject)JsonConvert.DeserializeObject(response);

                    // **連携キーは (issuer, sub)**（#140 の段階 3）。
                    //   **以前は独自の `userid` クレームを鍵にしていた**ため、
                    //   **相手が汎用認証サイトに限られていた**（`userid` は独自スコープ）。
                    //   `sub` は OIDC の標準なので、**どの OP とも連携できる形になる。**
                    //
                    //   **`iss` と `sub` は、署名を検証した id_token から取る**
                    //   （/userinfo の値は、この後で一致を確かめるだけに使う）。
                    string idpIssuer = (string)idTokenPayload[OAuth2AndOIDCConst.iss];
                    string federationKey = sub;

                    // **旧い鍵**（下位互換。移行のために読む）。
                    string legacyKey = (string)jobj[OAuth2AndOIDCConst.Scope_UserID];

                    string name = (string)jobj[OAuth2AndOIDCConst.sub];
                    string email = (string)jobj[OAuth2AndOIDCConst.Scope_Email];

                    // **上流が「検証済み」と言っているか**（#140 の段階 1）。
                    //   相手が汎用認証サイトなら、/userinfo が email_verified を返す
                    //   （user.EmailConfirmed。#184 で真偽値に直してある）。
                    string emailVerified = (string)jobj[OAuth2AndOIDCConst.email_verified];

                    Claim nameClaim = new Claim(OAuth2AndOIDCConst.UrnSubjectClaim, name);
                    Claim emailClaim = new Claim(OAuth2AndOIDCConst.UrnEmailClaim, email);

                    // **鍵はメアド**（#151 の段階 3）。
                    //   以前は RequireUniqueEmail で「メアド」か「上流の識別子」かを選んでいた。
                    //   **メアドは常に在って一意**なので、鍵はメアドで決まる。
                    string uid = email;

                    // **新規に作るときの利用者名**（#151 の段階 3・段階 4）。
                    //   **上流の sub は利用者名ではない**（既定が public ＝ 利用者 ID）。
                    //   **利用者名は preferred_username で受け取る**
                    //   （上流が UserClaimsMapping で出す。#151 の段階 1）。
                    //   **無ければメアドの「@」より前**（利用者名に `@` は禁じている）。
                    //
                    //   **sub は見ない**（利用者を指す識別子であって、名前ではない）。
                    //
                    //   **鍵はメアド**なので、**名前がどちらになっても同じ利用者に結び付く**（上の uid）。
                    //   ここで決まるのは、**新規に作るときの名前だけ**である。
                    string preferredUserName = (string)jobj[Const.PreferredUserNameClaim];

                    string newUserName = Const.IsValidUserName(preferredUserName)
                        ? preferredUserName : Const.UserNameFromEmail(email);

                    // **/userinfo の sub は、id_token の sub と一致しなければならない**
                    //   （OIDC Core §5.3.2。一致しなければトークンの取り違えを疑う）。
                    if (!string.Equals(name, sub, StringComparison.Ordinal))
                    {
                        Logging.MyOperationTrace(
                            "The sub of /userinfo did not match the sub of the id_token.");

                        return View("Error");
                    }

                    if (string.IsNullOrEmpty(idpIssuer))
                    {
                        // **iss が無い id_token は受けない**（連携キーが決まらない）。
                        Logging.MyOperationTrace("The id_token had no iss claim.");

                        return View("Error");
                    }

                    // **連携キーは (issuer, sub)**（#140 の段階 3）。
                    UserLoginInfo login = new UserLoginInfo(idpIssuer, federationKey);
                    ExternalLoginInfo externalLoginInfo = new ExternalLoginInfo();
                    externalLoginInfo.Login = login;
                    externalLoginInfo.Email = email;

                    if (!string.IsNullOrWhiteSpace(email)
                        && !string.IsNullOrWhiteSpace(name))
                    {
                        // クレーム情報（e-mail, name情報）を取得できた。

                        // 既存の外部ログインを確認する。
                        ApplicationUser user = await UserManager.FindAsync(login);

                        if (user == null && !string.IsNullOrEmpty(legacyKey))
                        {
                            // **旧い鍵（"MultiPurposeAuthSite", userid）で引き直す**（下位互換）。
                            //   見つかったら**新しい鍵を足して移行する**（旧い鍵は消さない。
                            //   切り戻しできるようにするため）。
                            user = await UserManager.FindAsync(
                                new UserLoginInfo("MultiPurposeAuthSite", legacyKey));

                            if (user != null)
                            {
                                result = await UserManager.AddLoginAsync(user.Id, login);

                                Logging.MyOperationTrace(string.Format(
                                    "Migrated the ID federation key of {0}({1}) to (iss, sub).",
                                    user.Id, user.UserName));
                            }
                        }

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
                            // **メアドで引く**（#151 の段階 3。鍵がメアドになった）。
                            user = await UserManager.FindByEmailAsync(uid);

                            if (user != null)
                            {
                                // サインアップ済み → 外部ログイン追加だけで済む

                                // **メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない**（#140 の段階 1）。
                                if (Sts.AccountLink.CheckLinkToExistingUser(emailVerified)
                                        == Sts.AccountLinkCheck.NeedsVerifiedEmail)
                                {
                                    // **結び付けない。** 画面に理由を出し、明示的な追加へ誘導する。
                                    Logging.MyOperationTrace(string.Format(
                                        "Rejected linking an ID federation login to {0}({1}) "
                                        + "because the upstream did not assert email_verified.",
                                        user.Id, user.UserName));

                                    ViewBag.Reason = Resources.AccountViews.ExternalLoginNeedsVerifiedEmail;

                                    return View("ExternalLoginFailure");
                                }

                                // 外部ログイン（ = UserLoginInfo ）の追加
                                // **メアドで引いているので、メアドの一致は自明**（#151 の段階 3）。
                                //   以前は「鍵が上流の識別子」の場合に備えて、ここで突き合わせていた。
                                result = await UserManager.AddLoginAsync(user.Id, login);

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
                                    this.AddErrors(result);
                                }
                            }
                            else
                            {
                                // サインアップ済みでない → サインアップから行なう。
                                // If the user does not have an account, then prompt the user to create an account
                                // ユーザがアカウントを持っていない場合、アカウントを作成するようにユーザに促します。
                                ViewBag.ReturnUrl = Config.OAuth2AuthorizationServerEndpointsRootURI;
                                ViewBag.LoginProvider = login.LoginProvider;

                                //// メアドを返さないので、ExternalLoginConfirmationで
                                //// メアドを手入力して外部ログインと関連付けを行なう。
                                ////return View("ExternalLoginConfirmation");
                                //return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });

                                // 外部ログイン プロバイダのユーザー情報でユーザを作成
                                // **利用者名とメアドを別に渡す**（#151 の段階 3）。
                                //   以前は uid を利用者名にしてから、メアドを後で入れ直していた。
                                user = ApplicationUser.CreateUser(newUserName, email, true);

                                // **上流が検証していないメアドを「確認済み」として定着させない**（#140 の段階 1）。
                                user.EmailConfirmed = Sts.AccountLink.EmailConfirmedForNewUser(emailVerified);

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
                                    result = await UserManager.AddLoginAsync(user.Id, login);

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

                                        // セッションの初期化
                                        this.InitSessionAfterlogin();

                                        // オペレーション・トレース・ログ出力
                                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed up with a verified external account.", user.Id, user.UserName));

                                        // リダイレクト
                                        return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
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

                    #endregion
                }
            }
            else
            {
                // **塞いである**（#253）。**理由が残らないと、設定ミスと区別が付かない。**
                Logging.MyOperationTrace(
                    "The ID federation redirect endpoint is locked down. (IsLockedDownTestEndpoints)");
            }

            // **ここに来た理由を残す**（#253）。
            //   **上で個別のトレースを出していれば、その次の行として出る**（経路の終わりを示す）。
            //   **出ていなければ、利用者の作成や外部ログインの追加に失敗している。**
            Logging.MyOperationTrace("The ID federation did not complete. (the error view was returned)");

            return View("Error");
        }

        /// <summary>値そのものを出さずに、有無と長さだけを表す（#253）</summary>
        /// <param name="value">値</param>
        /// <returns>"(empty)" または "len=&lt;長さ&gt;"</returns>
        /// <remarks>
        /// **state や nonce をログに出さないため。**
        /// **切り分けに要るのは「空か／長さが違うか」までで、値そのものではない。**
        /// </remarks>
        private static string DescribeForTrace(string value)
        {
            return string.IsNullOrEmpty(value) ? "(empty)" : ("len=" + value.Length);
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
        public ActionResult Saml2Request(string samlRequest, string relayState, string sigAlg)
        {
            bool verified = false;

            string queryString = "";
            string decodeSaml = "";

            XmlDocument samlRequest2 = null;
            XmlNamespaceManager samlNsMgr = null;

            string iss = "";
            string id = "";
            string rtnUrl = "";

            // Cookie認証チケットからClaimsIdentityを取得しておく。
            AuthenticateResult ticket = this.AuthenticationManager
                .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
            ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

            string samlResponse = "";
            SAML2Enum.StatusCode statusCode = SAML2Enum.StatusCode.Success;

            try
            {
                //// ここでエラーになった場合、返る？
                //throw new Exception("test");

                if (Request.HttpMethod.ToLower() == "get")
                {
                    // DecodeRedirect
                    string rawUrl = Request.RawUrl;
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
                else if (Request.HttpMethod.ToLower() == "post")
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
        /// <returns>ActionResult（Saml2Response 画面）</returns>
        /// <remarks>
        /// **検証の本体は `Sts.SelfTestClient.VerifySaml2Response`**（#246 で両アプリから寄せた）。
        ///
        /// **アサーションを画面に出す**（#246 の項目 3）。
        /// 以前は `?ret=認証完了（nameId=…）` / `?ret=認証失敗` という URL に移るだけで、
        /// **どこで落ちたのかが分からず、読み取った属性も XML も捨てていた。**
        /// </remarks>
        [AllowAnonymous]
        public ActionResult AssertionConsumerService(string samlResponse, string relayState, string sigAlg)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                // テスト用のエンドポイントを閉じている。
                return View("Error");
            }

            bool isGet = (Request.HttpMethod.ToLower() == "get");
            string queryString = "";

            if (isGet)
            {
                // **Redirect Binding は、クエリ文字列そのものが署名の対象**である。
                string rawUrl = Request.RawUrl;
                queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);
            }

            // LoadRequestParameters（state と RelayState を照合するため）
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

            Sts.SelfTestClient.Saml2Result result = Sts.SelfTestClient.VerifySaml2Response(
                samlResponse, queryString, sigAlg,
                relayState, state_InSessionOrCookie, isGet);

            ViewBag.Verdict = result.Verdict;
            ViewBag.Reason = result.Reason;
            ViewBag.Binding = result.Binding;
            ViewBag.SigAlg = result.SigAlg;
            ViewBag.RelayState = result.RelayState;
            ViewBag.RelayStateMatched = result.RelayStateMatched;
            ViewBag.SignatureVerified = result.SignatureVerified;
            ViewBag.IssuerMatched = result.IssuerMatched;
            ViewBag.NameId = result.NameId;
            ViewBag.Issuer = result.Issuer;
            ViewBag.Audience = result.Audience;
            ViewBag.InResponseTo = result.InResponseTo;
            ViewBag.Recipient = result.Recipient;
            ViewBag.NotOnOrAfter = result.NotOnOrAfter;
            ViewBag.StatusCode = result.StatusCode;
            ViewBag.NameIdFormat = result.NameIdFormat;
            ViewBag.AuthnContextClassRef = result.AuthnContextClassRef;
            ViewBag.ResponseXml = result.ResponseXml;

            return View("Saml2Response");
        }

        #endregion

        #endregion

        #region OAuth Endpoint

        #region Authorize（認可エンドポイント）

        #region max_age & auth_time
        // **max_age の判定は CommonLibrary へ移した**（#247。`CmnEndpoints.CheckAuthTime`）。
        //   bool では「再認証」「login_required」「invalid_request」を区別できなかった。

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
                string auth_time = Request.Cookies[Config.AuthTimeCookieName].Value;

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
        /// <remarks>
        /// **[AllowAnonymous] にしてある**（#254）。
        /// **`prompt=none` のときは UI を出さず、`login_required` を RP へ返す**必要があり
        /// （OIDC Core 3.1.2.1 / 3.1.2.6）、**[Authorize] のままでは、
        /// Cookie 認証がこのコードに入る前にサインイン画面へ飛ばしてしまう。**
        ///
        /// **未認証のときの扱いは、このメソッドの中で決める。**
        /// `prompt=none` でなければ HttpUnauthorizedResult を返す（[Authorize] と同じ動き）。
        ///
        /// **判定は `redirect_uri` の照合（ValidateAuthZReqParam）より後で行う。**
        /// **照合前に RP へ返すと、オープン リダイレクトになる。**
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult OAuth2Authorize(
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
            // PKCE : Request Objectが在ればその値を使う（無ければクエリ文字列。#220）
            string code_challenge = Request.QueryString[OAuth2AndOIDCConst.code_challenge];
            string request_uri = Request.QueryString[OAuth2AndOIDCConst.request_uri];
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
                // 存在しないrequest_uriではnullになる（#185）。
                // その場合は上書きせず、後続のValidateAuthZReqParamでエラーにする。
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                if (requestObjectPayload != null)
                {
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
                    code_challenge = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge];
                }
            }

            // **要求の検証を先に行う**（#247）。
            //   `redirect_uri` を照合できていないと、エラーを RP へ返せない。
            //   以前は `max_age` の判定が先で、超過すると
            //   **valid_redirect_uri も err も空のまま、文面の無いエラー画面**になっていた
            //   （`ANALYSIS-IdP.md` の A-12）。
            if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription, code_challenge, prompt))
            {
                // **max_age と auth_time の照合**（#247。判定は CommonLibrary）。
                Token.CmnEndpoints.AuthTimeCheck authTimeCheck = Token.CmnEndpoints.CheckAuthTime(
                    max_age,
                    Request.Cookies[Config.AuthTimeCookieName]?.Value,
                    Request.Cookies[Config.ReAuthenticatedAtCookieName]?.Value);

                if (authTimeCheck == Token.CmnEndpoints.AuthTimeCheck.InvalidMaxAge)
                {
                    // **0 以上の整数でない**（RFC 6749 4.1.2.1 : invalid_request）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "max_age must be a non-negative integer.";
                }
                else if (!this.User.Identity.IsAuthenticated
                    && Token.CmnEndpoints.HasPrompt(prompt, Token.CmnEndpoints.PromptNone))
                {
                    // **そもそもサインインしていない**（OIDC Core 3.1.2.6 : login_required）。
                    //   **#247 で足したのは「セッションは在るが古い」場合だけ**だった。
                    //   **「セッションが無い」場合は、[Authorize] が
                    //   このコードに入る前にサインイン画面へ飛ばしていた**（#254）。
                    err = OAuth2AndOIDCConst.login_required;
                    errDescription = "The end-user is not authenticated, but prompt=none was specified.";
                }
                else if (!this.User.Identity.IsAuthenticated)
                {
                    // **サインイン画面へ送る**（#254）。
                    //   **[Authorize] を外した**ので、未認証のときの扱いを自分で決める。
                    //   401 を返すと、Owin の Cookie 認証が LoginPath へのリダイレクトに変える。
                    //   **[Authorize] が行っていたことと同じ**（ReturnUrl も付く）。
                    return new HttpUnauthorizedResult();
                }
                else if (authTimeCheck == Token.CmnEndpoints.AuthTimeCheck.NeedsReAuthentication
                    && Token.CmnEndpoints.HasPrompt(prompt, Token.CmnEndpoints.PromptNone))
                {
                    // **prompt=none では UI を出せない**（OIDC Core 3.1.2.6 : login_required）。
                    err = OAuth2AndOIDCConst.login_required;
                    errDescription = "Re-authentication is required, but prompt=none was specified.";
                }
                else if (Token.CmnEndpoints.HasPrompt(prompt, Token.CmnEndpoints.PromptLogin)
                    && string.IsNullOrEmpty(Request.Cookies[Config.ReAuthenticatedAtCookieName] == null ? "" : Request.Cookies[Config.ReAuthenticatedAtCookieName].Value))
                {
                    // **prompt=login は、再認証を求める**（OIDC Core §3.1.2.1。#272 の段階 2）。
                    //   **max_age の再認証と同じ経路**を使う（印を残してサインアウトし、同じ URL に戻す）。
                    //   **印（re_auth_at）が在るときはここを通らない。**
                    //   **戻ってきた要求にも prompt=login が付いている**ので、
                    //   印が無いと永久に送り返すことになる。
                    Response.Cookies.Add(new HttpCookie(Config.ReAuthenticatedAtCookieName,
                        FormatConverter.ToW3cTimestamp(DateTime.UtcNow)));
                    this.AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                    return new RedirectResult(Request.RawUrl);
                }
                else if (authTimeCheck == Token.CmnEndpoints.AuthTimeCheck.NeedsReAuthentication)
                {
                    // **再認証する**（OIDC Core 3.1.2.1）。
                    //   印を残してサインアウトし、同じ URL に戻す（この後は認証が要るのでサインイン画面になる）。
                    //   **印は繰り返しを防ぐため**（max_age=0 でも、再認証の直後なら続ける）。
                    Response.Cookies.Add(new HttpCookie(Config.ReAuthenticatedAtCookieName,
                        FormatConverter.ToW3cTimestamp(DateTime.UtcNow)));
                    this.AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                    return new RedirectResult(Request.RawUrl);
                }
                else
                {
                    // Cookie認証チケットからClaimsIdentityを取得しておく。
                    AuthenticateResult ticket = this.AuthenticationManager
                        .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
                    ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

                    // ClaimsIdentityを生成
                    identity = new ClaimsIdentity(
                        identity.Claims, OAuth2AndOIDCConst.Bearer,
                        identity.NameClaimType, identity.RoleClaimType);

                    // **再認証の印を消す**（#247）。
                    //   一度きりの印なので、ここまで来たら落とす。
                    Response.Cookies.Add(new HttpCookie(Config.ReAuthenticatedAtCookieName, "")
                    {
                        Expires = DateTime.UtcNow.AddDays(-1)
                    });

                    // auth_timeを追加
                    this.AddAuthTimeClaim(max_age, claims, identity);

                    // scopeパラメタ
                    string[] scopes = (scope ?? "").Split(' ');

                    if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                    {
                        // OAuth2/OIDC Authorization Code
                        ViewBag.Name = identity.Name;
                        ViewBag.Scopes = scopes;

                        // **認可画面で「何を確かめるのか」を出すための値**（#246 の項目 3）。
                        //   画面側は、自己テストを閉じている配置では出さない（項目 4 の線引き）。
                        ViewBag.ClientId = client_id;
                        ViewBag.ResponseType = response_type;
                        ViewBag.ResponseMode = response_mode;
                        ViewBag.ValidRedirectUri = valid_redirect_uri;
                        ViewBag.Prompt = prompt;
                        ViewBag.MaxAge = max_age;
                        ViewBag.RequestUri = request_uri;
                        ViewBag.HasState = !string.IsNullOrEmpty(state);
                        ViewBag.HasNonce = !string.IsNullOrEmpty(nonce);
                        ViewBag.HasClaims = (claims != null);

                        // 認証の場合、余計なscopeをfilterする。
                        bool isAuth = scopes.Any(x => x.ToLower() == OAuth2AndOIDCConst.Scope_Auth);

                        if (string.IsNullOrWhiteSpace(prompt)) prompt = "";

                        #region 同意の判定（#272 の段階 2 / D-6）

                        // **以前は「`prompt=none` なら無条件に飛ばす」だった**（C-3）。
                        //   **記録を持ったので、「以前に同意済みか」で判定できる。**
                        //
                        //   | 状況 | ここでの扱い |
                        //   |---|---|
                        //   | scope に `auth`（独自の認証用） | **従来どおり飛ばす** |
                        //   | 要求 scope が記録の部分集合 | **飛ばす** |
                        //   | `prompt=consent` | **記録が在っても出す**（§3.1.2.1） |
                        //   | `prompt=select_account` | **出す**（画面に「別のアカウントでログイン」が在る） |
                        //   | 記録が無い ＋ `prompt=none` | **`consent_required`**（§3.1.2.6） |
                        //   | 記録が無い | 同意画面を出す |
                        string userId = User.Identity.GetUserId();

                        bool hasConsent = Sts.ConsentProvider.HasConsent(userId, client_id, scopes);
                        bool asksConsent = Token.CmnEndpoints.HasPrompt(
                                               prompt, Token.CmnEndpoints.PromptConsent)
                                           || Token.CmnEndpoints.HasPrompt(
                                               prompt, Token.CmnEndpoints.PromptSelectAccount);

                        #endregion

                        if (isAuth                              // OAuth2 拡張仕様
                            || (hasConsent && !asksConsent))    // 同意済み（#272 の段階 2）
                        {
                            // 認可画面をスキップ

                            // ★ 必要に応じてスコープのフィルタ
                            if (isAuth)
                            {
                                scopes = Sts.Helper.FilterClaimAtAuth(scopes).ToArray();
                            }

                            // ★ Codeの生成
                            string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                identity, Request.QueryString, client_id, state, scopes, claims, nonce);

                            // RedirectエンドポイントへCodeをRedirect
                            ActionResult actionResult = this.RedirectCode(
                                client_id, response_mode, valid_redirect_uri, code, state);
                            if (actionResult != null) return actionResult;
                        }
                        else if (Token.CmnEndpoints.HasPrompt(
                            prompt, Token.CmnEndpoints.PromptNone))
                        {
                            // **UI を出せないので、エラーを RP へ返す**
                            //   （OIDC Core §3.1.2.6 : consent_required。#272 の段階 2）。
                            //   **ここが C-3 そのものである** — 以前は同意を飛ばして
                            //   code を発行していたので、**セッションが生きていれば
                            //   どのクライアントも無音で認可を取れた。**
                            err = OAuth2AndOIDCConst.consent_required;
                            errDescription = "Consent is required, but prompt=none was specified.";
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
                            identity, Request.QueryString,
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
                            identity, Request.QueryString,
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
            }
            else
            {
                // 不正なRequest
            }

            // ここまで来たらエラー。
            if (!string.IsNullOrEmpty(valid_redirect_uri))
            {
                // valid_redirect_uri
                // RFC 6749 4.1.2.1 : error / error_description、stateは要求にあれば返す（#187）
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(valid_redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, err },
                        { OAuth2AndOIDCConst.error_description, errDescription },
                        { OAuth2AndOIDCConst.state, state }
                    }));
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
                ViewBag.Err = err;
                ViewBag.ErrDescription = errDescription;
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
        public ActionResult OAuth2Authorize(
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
            // PKCE : Request Objectが在ればその値を使う（無ければクエリ文字列。#220）
            string code_challenge = Request.QueryString[OAuth2AndOIDCConst.code_challenge];
            string request_uri = Request.QueryString[OAuth2AndOIDCConst.request_uri];
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
                // 存在しないrequest_uriではnullになる（#185）。
                // その場合は上書きせず、後続のValidateAuthZReqParamでエラーにする。
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                if (requestObjectPayload != null)
                {
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
                    code_challenge = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge];
                }
            }

            if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out string valid_redirect_uri, out string err, out string errDescription,
                code_challenge, prompt))
            {
                // Cookie認証チケットからClaimsIdentityを取得しておく。
                AuthenticateResult ticket = this.AuthenticationManager
                .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
                ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

                // auth_timeを追加
                this.AddAuthTimeClaim(max_age, claims, identity);

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
                else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Deny")))
                {
                    // **拒否した**（E-6 / #272 の段階 2）。
                    //   **RFC 6749 §4.1.2.1 : access_denied を redirect_uri へ返す。**
                    //   **以前は拒否できず、access_denied を返す経路も無かった。**
                    //   **記録は残さない**（「拒否した」を覚えて、
                    //   次回以降自動で断ることはしない。利用者が気を変えられなくなる）。
                    err = OAuth2AndOIDCConst.access_denied;
                    errDescription = "The resource owner denied the request.";
                }
                else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
                {
                    // アクセス要求を保存して、仲介コードを発行する。
                    identity = new ClaimsIdentity(
                        identity.Claims, OAuth2AndOIDCConst.Bearer, identity.NameClaimType, identity.RoleClaimType);

                    // ★ Codeの生成
                    // **同意を記録する**（#272 の段階 2 / D-6）。
                    //   **これが次回以降の `prompt=none` の判定の土台になる。**
                    //   **scope は足し込む**（増えた scope で同意し直しても、以前の分を失わない）。
                    Sts.ConsentProvider.Grant(
                        User.Identity.GetUserId(), client_id, scopes);

                    string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                        identity, Request.QueryString, client_id, state, scopes, claims, nonce);

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
                // valid_redirect_uriに返す。
                // RFC 6749 4.1.2.1 : error / error_description、stateは要求にあれば返す（#187）
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(valid_redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, err },
                        { OAuth2AndOIDCConst.error_description, errDescription },
                        { OAuth2AndOIDCConst.state, state }
                    }));
            }
            //else if (!string.IsNullOrEmpty(redirect_uri))
            //{
            //    // redirect_uriに返す。//オープンリダイレクター
            //    return new RedirectResult(
            //        redirect_uri + string.Format(
            //            "?err={0}&errDescription={1}", err, errDescription));
            //}
            else
            {
                // エラー画面
                ViewBag.Err = err;
                ViewBag.ErrDescription = errDescription;
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
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { OAuth2AndOIDCConst.code, code }, { OAuth2AndOIDCConst.state, state } }));
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
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
            {
                // fragment
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { OAuth2AndOIDCConst.code, code }, { OAuth2AndOIDCConst.state, state } }, true));
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
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, "bearer" },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true));
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                            }, null, null);
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state }
                                }, true));
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, "bearer" },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true));
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                            }, null, null);
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["IDToken"] = id_token;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, "bearer" },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true));
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                            }, client_id, expiresUtc);
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = "bearer";
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state }
                                }, true));
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
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
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, "bearer" },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true));
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                            }, client_id, expiresUtc);
                            return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
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
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
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
                                { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
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
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied },
                        { OAuth2AndOIDCConst.state, state }
                    }, true));
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
                return new RedirectResult(Token.CmnEndpoints.BuildRedirectUrl(redirect_uri,
                    new Dictionary<string, string>() { { "response", response } }, true));
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
            if (!Config.IsLockedDownTestEndpoints)
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

                            // **アサーションの組み立ては SelfTestClient**（#246）。
                            model.AuthMethod = "private_key_jwt（client_assertion。FAPI1 は非対称の認証）";

                            model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                Sts.SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.StandardScopes));
                        }
                        else if (state.StartsWith(fapi2Prefix))
                        {
                            // FAPI2

                            // **private_key_jwt で交換する**（#246）。
                            //   FAPI 2.0 が認めるのは MTLS と private_key_jwt の 2 つ。
                            //   以前は client_secret を空で送り、**クライアント証明書（TB）が付くことを前提**に
                            //   していたが、自己テストのクライアントは
                            //   ClientCertPfxFilePath が設定されていなければ証明書を添えない。
                            //   **設定が無い配置では /token が 401（invalid_client）になり、
                            //   自己テストが結果画面まで通らなかった**（/ros でも /par でも同じ）。
                            //   **証明書の配置を前提にしない private_key_jwt に寄せる。**
                            //   mTLS の経路は E2E（FA-6）が測る。

                            // **アサーションの組み立ては SelfTestClient**（#246）。
                            model.AuthMethod = "private_key_jwt（client_assertion。FAPI 2.0 は MTLS か これ）";

                            model.Response = await Sts.Helper.GetInstance().GetAccessTokenByCodeAsync(
                                tokenEndpointUri, redirect_uri, code,
                                Sts.SelfTestClient.CreateClientAssertion(
                                    clientId_InSessionOrCookie, new TimeSpan(0, 0, 30), Const.OidcScopes));
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
                                //   **Open棟梁 のクライアントは、この経路を Basic で送る**
                                //   （既定が client_secret_basic。#246 の項目 3）。
                                model.AuthMethod = "client_secret_basic（Authorization ヘッダ）";

                                model.Response = await Sts.Helper.GetInstance()
                                    .GetAccessTokenByCodeAsync(tokenEndpointUri,
                                    client_id, client_secret, redirect_uri, code);
                            }
                            else
                            {
                                // PKCE
                                //   **PKCE の経路は既定が client_secret_post**（Basic ではない。#246 の項目 3）。
                                //   PKCE 自体はクライアント認証ではないので、code_verifier は別に送る。
                                model.AuthMethod = "client_secret_post（フォーム）＋ PKCE の code_verifier";

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
                // IsLockedDownTestEndpoints == true;
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
            if (!Config.IsLockedDownTestEndpoints)
            {
                // AccountVerifyCodeViewModelの検証
                if (ModelState.IsValid)
                {
                    // 結果を格納する変数。
                    Dictionary<string, string> dic = null;

                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.GetUserClaims")))
                    {
                        // UserInfoエンドポイントにアクセス
                        model.Response = await Sts.Helper.GetInstance().GetUserInfoAsync(model.AccessToken);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Refresh")))
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
                        string client_secret = Sts.Helper.GetInstance().GetClientSecret(client_id);

                        model.Response = await Sts.Helper.GetInstance().RevokeTokenAsync(
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
            if (!Config.IsLockedDownTestEndpoints)
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
                OAuth2AndOIDCConst.user_code, Request.RawUrl);

            return View("DeviceAuthZVerify");
        }

        /// <summary>
        /// DeviceAuthZVerify画面
        /// POST: /device_verify
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        public ActionResult DeviceAuthZVerify(string dummy)
        {
            // FormDataCollectionは、WebAPI専用らしい。
            ViewBag.ReceiveResult = false;

            if (2 <= Request.Form.Count)
            {
                string userCode = Request.Form[OAuth2AndOIDCConst.user_code];
                ViewBag.ReceiveResult = Sts.DeviceAuthZProvider.ReceiveResult(
                    userCode, User.Identity.Name, !string.IsNullOrEmpty(Request.Form["allow"]));
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
            // client_id
            clientId = (string)Session[Const.TestClientId];
            if (!string.IsNullOrEmpty(clientId))
            {
                Session.Remove(Const.TestClientId);
            }
            else
            {
                clientId = Request.Cookies[Const.TestClientId]?.Value;
                if (!string.IsNullOrEmpty(clientId))
                {
                    Response.Cookies[Const.TestClientId].Value = "";
                }
            }

            // state
            state = (string)Session[Const.TestState];
            if (!string.IsNullOrEmpty(state))
            {
                Session.Remove(Const.TestState);
            }
            else
            {
                state = Request.Cookies[Const.TestState]?.Value;
                if (!string.IsNullOrEmpty(state))
                {
                    Response.Cookies[Const.TestState].Value = "";
                }
            }

            // redirect_uri
            redirect_uri = (string)Session[Const.TestRedirectUri];
            if (!string.IsNullOrEmpty(redirect_uri))
            {
                Session.Remove(Const.TestRedirectUri);
            }
            else
            {
                redirect_uri = Request.Cookies[Const.TestRedirectUri]?.Value;
                if (!string.IsNullOrEmpty(redirect_uri))
                {
                    Response.Cookies[Const.TestRedirectUri].Value = "";
                }
            }

            // nonce
            nonce = (string)Session[Const.TestNonce];
            if (!string.IsNullOrEmpty(nonce))
            {
                Session.Remove(Const.TestNonce);
            }
            else
            {
                nonce = Request.Cookies[Const.TestNonce]?.Value;
                if (!string.IsNullOrEmpty(nonce))
                {
                    Response.Cookies[Const.TestNonce].Value = "";
                }
            }

            // code_verifier
            code_verifier = (string)Session[Const.TestCodeVerifier];
            if (!string.IsNullOrEmpty(code_verifier))
            {
                Session.Remove(Const.TestCodeVerifier);
            }
            else
            {
                code_verifier = Request.Cookies[Const.TestCodeVerifier]?.Value;
                if (!string.IsNullOrEmpty(code_verifier))
                {
                    Response.Cookies[Const.TestCodeVerifier].Value = "";
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
        /// <summary>
        /// 2 人目のテスト利用者に仕込む、標準クレームのサンプル（#261）。
        /// </summary>
        /// <remarks>
        /// **OIDC Core 5.1 の標準クレームを、`UnstructuredData`（JSON）に入れた例**である。
        /// **`UserClaimsMapping` で対応付けると、`/userinfo` と id_token に出る**（#230）。
        /// 雛形の対応付けは `_appsettings.json` / `_app.config` にコメントで置いてある。
        ///
        /// **`name` と `address.locality` は、わざと入れていない。**
        /// 雛形の対応付けは、その 2 つを **`usd1` / `usd2`（管理画面で入れられる 2 欄）**に
        /// 向けてある（**画面から入れた値が返ることを E2E で測り続けるため**。`RT-230.*`）。
        ///
        /// **`preferred_username` / `email` / `phone_number` も入れていない。**
        /// **`user:` で `ApplicationUser` から直に取れる**ので、二重に持たない（#151 の段階 1）。
        ///
        /// > **この JSON は、管理画面で保存すると消える。**
        /// > 画面（`ManageAddUnstructuredDataViewModel`）は `usd1` / `usd2` しか持たないので、
        /// > **読み込みで他のキーが捨てられ、保存で JSON ごと置き換わる。**
        /// > **仕込み先を 2 人目にしてあるのは、そのため**である
        /// > （`RT-230.*` は 1 人目の画面を叩く）。
        /// </remarks>
        private const string SampleUnstructuredData =
            "{"
            + "\"given_name\":\"Taro\","
            + "\"family_name\":\"Tanaka\","
            + "\"nickname\":\"taro\","
            + "\"profile\":\"https://example.com/taro\","
            + "\"picture\":\"https://example.com/taro.png\","
            + "\"website\":\"https://example.com/\","
            + "\"gender\":\"male\","
            + "\"birthdate\":\"1990-01-23\","
            + "\"zoneinfo\":\"Asia/Tokyo\","
            + "\"locale\":\"ja-JP\","
            + "\"updated_at\":1759449600,"
            + "\"address\":{"
            + "\"formatted\":\"100-0001 1-1 Chiyoda, Chiyoda-ku, Tokyo, JP\","
            + "\"street_address\":\"1-1 Chiyoda, Chiyoda-ku\","
            + "\"region\":\"Tokyo\","
            + "\"postal_code\":\"100-0001\","
            + "\"country\":\"JP\""
            + "}"
            + "}";

        /// <summary>
        /// テスト利用者を作る（IsDebug ＋ TestUserPWD が在るときだけ）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **名前に接尾辞を付けられる**（`TestUserSuffix`。#260）。**空なら従来どおり。**
        ///
        /// **E2E は net48 版と net10.0 版を同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ため、分けないと
        /// **同じ利用者の属性（`DeviceToken` / `UnstructuredData`）を書き換え合う。**
        ///
        /// **居なければ作る**（**初期化済みの DB でも呼ばれる**）。
        /// **接尾辞を変えても、DB を作り直さなくてよい**ようにするため。
        /// </remarks>
        private async Task CreateTestUsers()
        {
            string password = Config.TestUserPWD;

            if (!Config.IsDebug
                || string.IsNullOrWhiteSpace(password))
            {
                return;
            }

            string suffix = Config.TestUserSuffix;
            string superName = "super_tanaka" + suffix;
            string normalName = "tanaka" + suffix;

            // 管理者ユーザを作成
            if (await this.UserManager.FindByNameAsync(superName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    superName, superName + "@gmail.com", true);

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(superName)).Id, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(superName)).Id, Const.Role_Admin);
                }
            }

            // 一般ユーザを作成
            if (await this.UserManager.FindByNameAsync(normalName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    normalName, normalName + "@gmail.com", true);

                // **標準クレームのサンプルを持たせる**（#261）。
                user.UnstructuredData = SampleUnstructuredData;

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(normalName)).Id, Const.Role_User);
                }
            }
            else
            {
                // **既に居る利用者にも、空なら入れる**（#261）。
                //   **#260 より前に作られた DB を、作り直させないため。**
                //   **空のときだけ**なので、利用者が自分で入れた値は上書きしない。
                ApplicationUser user = await this.UserManager.FindByNameAsync(normalName);

                if (user != null
                    && string.IsNullOrEmpty(user.UnstructuredData))
                {
                    user.UnstructuredData = SampleUnstructuredData;
                    await this.UserManager.UpdateAsync(user);
                }
            }

            // **E2E 専用のクライアント登録**（#264）。
            //   **以前は test.ps1 -Launch が環境変数で差し込んでいた**が、
            //   **net48 版は一覧ごと 1 本の環境変数**で渡すため、**件数に上限があった**
            //   （#262 で踏んだ。IIS Express が起動するのに全要求が 500 になる）。
            //   **利用者の登録（saml2OAuth2Data）に寄せた**ので、**上限が無い。**
            //
            //   **接尾辞は付けない。** client_name は E2E が名前で引くため
            //   （Sts.TestClients の表と、E2E の KnownClients を同じ値で揃える）。
            //   **サイトごとに分ける必要も無い**（作った後は読むだけで、書き換え合わない。#260）。
            foreach (Sts.TestClients.Entry entry in Sts.TestClients.Entries)
            {
                ViewModels.ManageAddSaml2OAuth2DataViewModel saml2OAuth2Data
                    = Sts.TestClients.CreateSaml2OAuth2Data(entry);

                if (saml2OAuth2Data == null)
                {
                    // **写す元が構成ファイルに無い。** その分は E2E が Skip する。
                    continue;
                }

                if (await this.UserManager.FindByNameAsync(entry.ClientName) == null)
                {
                    ApplicationUser user = ApplicationUser.CreateUser(
                        entry.ClientName, entry.ClientName + "@gmail.com", true);

                    // **client_id は固定値**（既定の Guid.NewGuid を上書きする）。
                    user.ClientID = entry.ClientId;

                    // **ロールは要らない**（このクライアントはサインインしない）。
                    await this.UserManager.CreateAsync(user, password);
                }

                // **登録が無ければ入れる**（在れば触らない）。
                //   **DB ストアでは 2 つのサイトが同じ user store を共有する**（#260）ので、
                //   **書き込みを 1 回に閉じる。**
                if (Sts.DataProvider.Get(entry.ClientId) == null)
                {
                    Sts.DataProvider.Create(entry.ClientId, saml2OAuth2Data);
                }
            }
        }

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
                        // **初期化済みでも、テスト利用者だけは作り足す**（#260）。
                        //   **接尾辞（TestUserSuffix）を変えたら、その利用者は未作成**である。
                        //   **DB を作り直させないため**に、足りなければここで作る。
                        await this.CreateTestUsers();

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

                user = ApplicationUser.CreateUser(
                        Const.UserNameFromEmail(Config.AdministratorUID),
                        Config.AdministratorUID, true);
                result = await this.UserManager.CreateAsync(user, Config.AdministratorPWD);
                if (result.Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_SystemAdmin);
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);
                }

                #endregion

                #region テスト・ユーザ

                await this.CreateTestUsers();

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