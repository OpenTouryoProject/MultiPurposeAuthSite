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
//**********************************************************************************

/*
外部ログインを用いた外部認証の開始処理とコールバック処理（連携・新規登録・ログイン）を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AspNetId = Microsoft.AspNetCore.Identity;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 外部ログイン**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
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

                // **上流が「検証済み」と言っているか**（#140 の段階 1）。
                //   **既定のプロバイダ構成では、このクレームは来ない。**
                //   その場合は「言っていない」として扱う（無い ＝ false）。
                //   Google なら ClaimActions.MapJsonKey で拾えるようにできる（Startup）。
                string emailVerified = identity.FindFirst(OAuth2AndOIDCConst.email_verified)?.Value;

                // **鍵はメアド**（#151 の段階 3）。
                //   以前は RequireUniqueEmail で「メアド」か「上流の識別子」かを選んでいた。
                //   **メアドは常に在って一意**なので、鍵はメアドで決まる。
                string uid = email;

                // **新規に作るときの利用者名**（#151 の段階 3）。
                //   上流の識別子がそのまま使えるならそれを、
                //   **`@` を含んで使えないならメアドから作る**（利用者名に `@` は禁じている）。
                string newUserName = UserIdentifier.IsValidUserName(name)
                    ? name : UserIdentifier.UserNameFromEmail(email);

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
                            // **利用者名とメアドを別に渡す**（#151 の段階 3）。
                            //   以前は uid を利用者名にしてから、メアドを後で入れ直していた。
                            user = ApplicationUser.CreateUser(newUserName, email, true);

                            // **上流が検証していないメアドを「確認済み」として定着させない**（#140 の段階 1）。
                            //   以前は言い値に関わらず true を入れていた。
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
    }
}
