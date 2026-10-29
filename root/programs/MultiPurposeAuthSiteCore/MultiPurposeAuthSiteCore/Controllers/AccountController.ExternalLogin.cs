//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の 外部ログイン
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//*  2026/10/26  玄人 幸道         name / email のクレームが無いとき、例外で落ちないようにした（#294）
//*  2026/10/26  玄人 幸道         外部ログインの失敗の出口ごとに、理由を OPERATION に記録する（#294）
//*  2026/10/29  玄人 幸道         外部ログインの結果を見る、クレームの入れ替え、name を必須にしない、知らない provider を断る（#294）
//**********************************************************************************

/*
外部ログインを用いた外部認証の開始処理とコールバック処理（連携・新規登録・ログイン）を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AspNetId = Microsoft.AspNetCore.Identity;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 外部ログイン**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region 送信と受信

        /// <summary>
        /// 外部Login（Redirect）の開始
        /// POST: /Account/ExternalLogin
        /// </summary>
        /// <param name="provider">string</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **登録されていない provider は、サインイン画面へ戻す**（#294）。
        /// 以前は `Challenge` が例外を出し、500 になっていた。
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLogin(string provider, string returnUrl)
        {
            if (!(await SignInManager.GetExternalAuthenticationSchemesAsync()).Any(x => x.Name == provider))
            {
                Logging.MyOperationTrace(string.Format(
                    "An unknown external login provider was requested. ({0})", LogSanitizer.Sanitize(provider)));

                return RedirectToAction(nameof(Login));
            }

            // Request a redirect to the external login provider
            string redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return this.Challenge(properties, provider);
        }

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
                // **失敗の出口ごとに、理由を記録する**（#294）。
                //   **以前は、どの出口も画面を返すだけで、何が起きたのか残らなかった。**
                Logging.MyOperationTrace(string.Format(
                    Resources.Diagnostics.LogExternalLoginRemoteError,
                    LogSanitizer.Sanitize(remoteError, Const.LogDetailMaxLength)));

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
                // **外部ログインの Cookie（Identity.External）が届いていたか**も残す。
                //   届いていなければ、プロバイダからの戻りで Cookie が送られなかった（SameSite など）。
                //   届いていて読めなければ、Cookie の中身（DataProtection の鍵など）を疑う。
                bool hasExternalCookie = Request.Cookies.Keys.Any(
                    x => x.EndsWith(IdentityConstants.ExternalScheme));

                Logging.MyOperationTrace(string.Format(
                    Resources.Diagnostics.LogExternalLoginInfoMissing,
                    hasExternalCookie ? "present" : "absent"));

                return RedirectToAction(nameof(Login));
            }

            IdentityResult idResult = null;
            AspNetId.SignInResult siResult = null;

            // ログイン情報を受け取れた場合、クレーム情報を分析
            ClaimsIdentity identity = externalLoginInfo.Principal.Identities.First();

            // ID情報とe-mail, name情報は必須
            Claim idClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
            Claim emailClaim = identity.FindFirst(ClaimTypes.Email);
            Claim nameClaim = identity.FindFirst(ClaimTypes.Name);

            // **プロバイダ固有のクレームは、ここではなく Startup で標準の型にそろえる**（#140 / #249）。
            //   net10.0 : ClaimActions、net48 : Provider の OnAuthenticated。
            //   ここに足すと、両アプリに同じ処理を二重に持つことになる。

            if (idClaim != null)
            {
                // クレーム情報（ID情報とe-mail, name情報）を抽出
                //   **name / email は返さないプロバイダがある**ので、null のまま進める。
                //   **email は鍵なので必須、name は無くてよい**（#294。利用者名はメアドから作れる）。
                string id = idClaim.Value;
                string name = nameClaim?.Value;
                string email = emailClaim?.Value;

                // **上流が「検証済み」と言っているか**（#140）。
                //   **既定のプロバイダ構成では、このクレームは来ない。**
                //   その場合は「言っていない」として扱う（無い ＝ false）。
                //   Google なら ClaimActions.MapJsonKey で拾えるようにできる（Startup）。
                string emailVerified = identity.FindFirst(OAuth2AndOIDCConst.email_verified)?.Value;

                // **鍵はメアド**（#151）。
                //   **メアドは常に在って一意**なので、鍵はメアドで決まる。
                string uid = email;

                // **新規に作るときの利用者名**（#151）。
                //   上流の識別子がそのまま使えるならそれを、
                //   **`@` を含んで使えないならメアドから作る**（利用者名に `@` は禁じている）。
                string newUserName = UserIdentifier.IsValidUserName(name)
                    ? name : UserIdentifier.UserNameFromEmail(email);

                if (!string.IsNullOrWhiteSpace(email))
                {
                    // クレーム情報（e-mail情報）を取得できた（name は無くてよい。#294）。
                    
                    // 既存の外部ログインを確認する。
                    ApplicationUser user = await UserManager.FindByLoginAsync(
                        externalLoginInfo.LoginProvider,
                        externalLoginInfo.ProviderKey);

                    if (user != null)
                    {
                        // 既存の外部ログインがある場合。

                        // ユーザーが既に外部ログインしている場合は、クレームをRemove, Addで更新し、
                        // **同じ種類の古いクレームを消してから足す**（#294）。
                        idResult = await this.ReplaceClaimAsync(user, emailClaim);
                        idResult = await this.ReplaceClaimAsync(user, nameClaim);

                        // SignInAsyncより、ExternalSignInAsyncが適切。
                        // 既存の外部ログイン・プロバイダでサインイン
                        siResult = await SignInManager.ExternalLoginSignInAsync(
                            externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey,
                            isPersistent: false, bypassTwoFactor: true); // 外部ログインの Cookie 永続化は常に false.

                        //  **サインインできていなければ、先へ進めない**（#294。NotAllowed / LockedOut など）。
                        if (!siResult.Succeeded)
                        {
                            return this.ExternalSignInFailed(externalLoginInfo.LoginProvider, user, siResult);
                        }

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
                        // **メアドで引く**（#151。鍵がメアドになった）。
                        user = await UserManager.FindByEmailAsync(uid);

                        if (user != null)
                        {
                            // サインアップ済み → 外部ログイン追加だけで済む

                            // **メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない**（#140）。
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
                            // **メアドで引いているので、メアドの一致は自明**（#151）。
                            idResult = await UserManager.AddLoginAsync(user, externalLoginInfo);

                            // クレーム（emailClaim, nameClaim, etc.）の追加
                            if (idResult.Succeeded)
                            {
                                idResult = await UserManager.AddClaimAsync(user, emailClaim);
                                idResult = await this.ReplaceClaimAsync(user, nameClaim); // name は無いことがある
                                // 保存するクレームを足すなら、ここ
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
                                    isPersistent: false); // rememberMe は false 固定（外部ログインの場合）

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
                                this.LogExternalLoginUserFailed(externalLoginInfo, "link to existing user", idResult);

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
                            // **利用者名とメアドを別に渡す**（#151）。
                            user = ApplicationUser.CreateUser(newUserName, email, true);

                            // **上流が検証していないメアドを「確認済み」として定着させない**（#140）。
                            user.EmailConfirmed = Sts.AccountLink.EmailConfirmedForNewUser(emailVerified);

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
                                    idResult = await this.ReplaceClaimAsync(user, nameClaim); // name は無いことがある
                                    // 保存するクレームを足すなら、ここ
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
                                       isPersistent: false); // rememberMe は false 固定（外部ログインの場合）

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
                                    this.LogExternalLoginUserFailed(externalLoginInfo, "link to new user", idResult);

                                    // 結果のエラー情報を追加
                                    this.AddErrors(idResult);
                                }
                            }
                            else
                            {
                                // ユーザの新規作成が失敗した場合
                                this.LogExternalLoginUserFailed(externalLoginInfo, "create user", idResult);

                                // 結果のエラー情報を追加
                                this.AddErrors(idResult);
                            } // else処理済
                        } // else処理済
                    } // else処理済
                    
                }
                else
                {
                    // クレーム情報（e-mail情報）を取得できなかった。
                    this.LogExternalLoginClaimsMissing(externalLoginInfo, true, false);
                }
            }
            else
            {
                // クレーム情報（ID情報）を取得できなかった。
                this.LogExternalLoginClaimsMissing(externalLoginInfo, false, false);
            }

            // ログイン情報を受け取れなかった場合や、その他の問題が在った場合。
            return View("ExternalLoginFailure");
        }

        #endregion

        #region 問題の記録

        /// <summary>必要なクレームが揃わなかったことを記録する（#294）</summary>
        /// <param name="externalLoginInfo">ExternalLoginInfo</param>
        /// <param name="noEmail">email が無い</param>
        /// <param name="noName">name が無い</param>
        /// <remarks>
        /// **無かったクレームの種類だけを書く。** 値は個人情報なので書かない。
        /// noEmail と noName が両方 false なら、ID情報（NameIdentifier）が無かったことを表す。
        /// </remarks>
        private void LogExternalLoginClaimsMissing(
            ExternalLoginInfo externalLoginInfo, bool noEmail, bool noName)
        {
            List<string> missing = new List<string>();

            if (!noEmail && !noName) missing.Add(nameof(ClaimTypes.NameIdentifier));
            if (noEmail) missing.Add(nameof(ClaimTypes.Email));
            if (noName) missing.Add(nameof(ClaimTypes.Name));

            Logging.MyOperationTrace(string.Format(
                Resources.Diagnostics.LogExternalLoginClaimsMissing,
                externalLoginInfo.LoginProvider, string.Join(",", missing)));
        }

        /// <summary>利用者を作れなかった・結べなかったことを記録する（#294）</summary>
        /// <param name="externalLoginInfo">ExternalLoginInfo</param>
        /// <param name="step">どの段階で失敗したか</param>
        /// <param name="idResult">IdentityResult</param>
        /// <remarks>
        /// **エラーの Code だけを書く**（InvalidUserName / DuplicateEmail など）。
        /// Description には利用者名やメアドが入るので書かない。
        /// </remarks>
        private void LogExternalLoginUserFailed(
            ExternalLoginInfo externalLoginInfo, string step, IdentityResult idResult)
        {
            Logging.MyOperationTrace(string.Format(
                Resources.Diagnostics.LogExternalLoginUserFailed,
                externalLoginInfo.LoginProvider, step,
                string.Join(",", idResult.Errors.Select(x => x.Code))));
        }

        #endregion

        #region 外部ログイン・ID 連携で共用する補助（#294）

        /// <summary>同じ種類のクレームを、新しい値に入れ替える</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">新しいクレーム（null なら何もしない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **以前は「新しい値を消して、新しい値を足す」だった**（`RemoveClaimAsync(user, 新しいクレーム)`）。
        /// **値が変わると古いクレームが消えずに残り、たまっていった。**
        /// **同じ種類の古いクレームを全部消してから足す。**
        /// </remarks>
        private async Task<IdentityResult> ReplaceClaimAsync(ApplicationUser user, Claim claim)
        {
            if (claim == null)
            {
                return IdentityResult.Success;
            }

            foreach (Claim old in (await UserManager.GetClaimsAsync(user)).Where(c => c.Type == claim.Type).ToList())
            {
                await UserManager.RemoveClaimAsync(user, old);
            }

            return await UserManager.AddClaimAsync(user, claim);
        }

        /// <summary>既存の結び付けで、サインインできなかったときの応答</summary>
        /// <param name="loginProvider">外部ログイン・上流の名前</param>
        /// <param name="user">ApplicationUser</param>
        /// <param name="siResult">SignInResult</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **以前は結果を見ずに、セッションを初期化し「has signed in」を記録して先へ進んでいた**
        /// （実際にはサインインしていないので、権限は渡らない）。
        /// **ロックアウトならロックアウトの画面、それ以外は失敗の画面を返す。**
        /// </remarks>
        private ActionResult ExternalSignInFailed(string loginProvider, ApplicationUser user, AspNetId.SignInResult siResult)
        {
            Logging.MyOperationTrace(string.Format(
                Resources.Diagnostics.LogExternalLoginSignInFailed,
                loginProvider, user.Id, siResult.ToString()));

            return siResult.IsLockedOut ? View("Lockout") : View("ExternalLoginFailure");
        }

        #endregion
    }
}
