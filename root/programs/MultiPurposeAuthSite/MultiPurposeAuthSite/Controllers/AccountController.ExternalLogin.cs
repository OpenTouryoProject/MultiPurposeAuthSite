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
//*  2026/10/25  玄人 幸道         段階ごとの経緯を DesignNotes へ移した（#294）
//**********************************************************************************

/*
外部ログインを用いた外部認証の開始処理とコールバック処理（連携・新規登録・ログイン）を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Threading.Tasks;
using System.Security.Claims;

using System.Web.Mvc;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

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
            // 外部ログイン プロバイダーへのリダイレクトを要求します
            return new ExternalLoginStarter(
                provider,
                Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
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

                    // **上流が「検証済み」と言っているか**（#140）。
                    //   **既定のプロバイダ構成では、このクレームは来ない。**
                    //   その場合は「言っていない」として扱う（無い ＝ false）。
                    string emailVerified =
                        identity.FindFirst(OAuth2AndOIDCConst.email_verified)?.Value;

                    // **鍵はメアド**（#151）。
                    //   **メアドは常に在って一意**なので、鍵はメアドで決まる。
                    string uid = email;

                    // **新規に作るときの利用者名**（#151）。
                    //   上流の識別子がそのまま使えるならそれを、
                    //   **`@` を含んで使えないならメアドから作る**（利用者名に `@` は禁じている）。
                    string newUserName = UserIdentifier.IsValidUserName(name)
                        ? name : UserIdentifier.UserNameFromEmail(email);

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
                                // **利用者名とメアドを別に渡す**（#151）。
                                user = ApplicationUser.CreateUser(newUserName, email, true);

                                // **上流が検証していないメアドを「確認済み」として定着させない**（#140）。
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
    }
}
