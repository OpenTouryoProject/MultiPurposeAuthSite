//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の サインイン・サインアウト
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
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
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の サインイン・サインアウト**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
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

            // **OP のセッションの識別子を作る**（#310 の段階 1）。
            //   **ここがセッションの始まり**である（`sid` はこの値から引く）。
            this.SetOpSessionCookie(Guid.NewGuid().ToString("N"));
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
                    UriOperator.GetParameterFromQueryString("ReturnUrl", Request.RawUrl));
                //ViewBag.ReturnUrl = returnUrl;

                // ReturnUrlからLoginHintを取得
                loginHint = CustomEncode.UrlDecode(
                    UriOperator.GetParameterFromQueryString("login_hint", returnUrl));
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

                        ApplicationUser user = UserIdentifier.LooksLikeEmail(uid)
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
                    //  **OIDC の ID 連携**（#286 の段階 2 でメソッドに分けた）。
                    //    **入力された値を、そのまま `login_hint` として上流へ渡す**（#151 の段階 3）。
                    //
                    //  **どの上流へ委譲するかは `IdpKey`**（#292 の段階 1）。
                    //    **空なら既定（先頭の 1 件）** — **従来の押し方と同じ結果になる。**
                    return this.StartIdFederationByOidc(
                        model.Email,
                        IdFederationUpstreams.GetOrDefault(
                            model.IdpKey, IdFederationUpstream.Oidc));
                }
                else if (submitButtonName == "id_federation_saml2_signin")
                {
                    //  **SAML2 の ID 連携**（#286 の段階 2）。
                    //    **押しても成立しない上流は、画面に出ていない**（`IsUsable`）。
                    return await this.StartIdFederationBySaml2(
                        IdFederationUpstreams.GetOrDefault(
                            model.IdpKey, IdFederationUpstream.Saml2));
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
            List<string> iframeUrls = new List<string>();

            if (User.Identity.IsAuthenticated) // 空振りできるように。
            {
                // **OP のセッションを終わらせる**（#310 の段階 1・2・3）
                iframeUrls = this.ClearOpSession();

                // サインアウト（Cookieの削除）
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                Logging.MyOperationTrace(string.Format("{0}({1}) has signed out.", user.Id, user.UserName));
            }

            // **ブラウザ経由で伝える**（#310 の段階 3。**伝える先が無ければ、従来どおり戻る**）
            ActionResult frontChannel = this.FrontChannelLogoutView(
                iframeUrls, Url.Action("Index", "Home"));
            if (frontChannel != null) return frontChannel;

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

            List<string> iframeUrls = new List<string>();

            if (signedIn)
            {
                // **OP のセッションを終わらせる**（#310 の段階 1・2・3）
                iframeUrls = this.ClearOpSession();

                // サインアウト（Cookieの削除）
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                // オペレーション・トレース・ログ出力
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) has signed out by RP-Initiated Logout.", user.Id, user.UserName));
            }

            // **ブラウザ経由で伝える**（#310 の段階 3）。
            //   **画面を挟んでから、戻り先へ進む**（**進む先は、ここで決める**）。
            //   **伝える先が無ければ、従来どおり直に戻る。**
            ActionResult frontChannel = this.FrontChannelLogoutView(
                iframeUrls,
                string.IsNullOrEmpty(redirectUri) ? Url.Action("Index", "Home") : redirectUri);
            if (frontChannel != null) return frontChannel;

            if (!string.IsNullOrEmpty(redirectUri))
            {
                // **戻してよいと判定できた場合だけ**（§3）。
                return Redirect(redirectUri);
            }

            return RedirectToAction("Index", "Home");
        }

        #endregion

        #endregion

        #endregion
    }
}
