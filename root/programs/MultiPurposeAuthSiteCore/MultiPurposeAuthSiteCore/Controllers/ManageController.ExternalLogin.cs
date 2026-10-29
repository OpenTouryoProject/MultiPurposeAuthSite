//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController の外部ログイン・同意
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         外部ログインの結び付けを AccountController に揃えた（name / email が無い・
//*                                メアドで照合・クレームの入れ替え・他人の結び付け・未登録の provider）、
//*                                最後のサインインの手段を消させない（#294）
//**********************************************************************************

/*
外部ログインの関連付け・解除、
同意の一覧・取り消しを担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController の外部ログイン・同意**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region (External) Logins

        /// <summary>
        /// 同意（consent grant）の一覧（#272 の段階 2 / D-6）
        /// GET: /Manage/ConsentGrants
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **利用者が「どのアプリケーションに何を許したか」を見る画面である。
        /// **記録するなら、取り消せなければならない**（そうでないと記録が増えるだけになる）。
        /// </remarks>
        [HttpGet]
        public async Task<ActionResult> ConsentGrants(EnumManageMessageId? message)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            ViewBag.StatusMessage = (message == EnumManageMessageId.RevokeConsentSuccess)
                ? Resources.ManageController.RevokeConsentSuccess : "";

            List<ConsentGrantViewModel> grants = new List<ConsentGrantViewModel>();

            foreach (KeyValuePair<string, string> kv
                in Sts.ConsentProvider.GetByUser(user.Id))
            {
                // **client_name を引けなければ client_id を出す**
                //   （登録を消した後でも、同意の記録は残る）。
                string clientName = Sts.Helper.GetInstance().GetClientName(kv.Key);

                grants.Add(new ConsentGrantViewModel()
                {
                    ClientId = kv.Key,
                    ClientName = string.IsNullOrEmpty(clientName) ? kv.Key : clientName,
                    Scopes = kv.Value
                });
            }

            return View(new ManageConsentGrantsViewModel() { Grants = grants });
        }

        /// <summary>
        /// 同意を取り消す（#272 の段階 2 / D-6）
        /// POST: /Manage/RevokeConsent
        /// </summary>
        /// <param name="clientId">client_id</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **次の認可で同意画面が出る**（`prompt=none` なら `consent_required`）。
        /// **発行済みのトークンは失効しない。** そちらは `/revoke`（RFC 7009）の役目である。
        /// </remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RevokeConsent(string clientId)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            Sts.ConsentProvider.Revoke(user.Id, clientId);

            return RedirectToAction("ConsentGrants",
                new { Message = EnumManageMessageId.RevokeConsentSuccess });
        }

        /// <summary>
        /// 外部ログイン管理画面（初期表示）
        /// GET: /Manage/ManageLogins
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ManageLogins(EnumManageMessageId? message)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
                    message == EnumManageMessageId.Error ? Resources.ManageController.Error
                    : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                    : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                    : "";

                // 全ての外部ログイン情報
                IEnumerable<AuthenticationScheme> loginProviders = await SignInManager.GetExternalAuthenticationSchemesAsync();

                // 現在の認証ユーザが外部ログイン済みの外部ログイン情報を取得
                IList<UserLoginInfo> userLogins = await UserManager.GetLoginsAsync(user);

                // 現在の認証ユーザが未ログインの外部ログイン情報を取得
                IList<AuthenticationScheme> otherLogins = new List<AuthenticationScheme>();

                foreach (AuthenticationScheme auth in loginProviders)
                {
                    bool flg = true;
                    foreach (UserLoginInfo ul in userLogins)
                    {
                        // **スキーム名で突き合わせる**（#294。以前は表示名で比べていた）。
                        if (auth.Name == ul.LoginProvider)
                        {
                            flg = false;
                        }
                    }

                    // userLoginsに存在しないものだけ追加
                    if (flg) otherLogins.Add(auth);
                }

                // 削除ボタンを表示するかしないか。
                // 通常ログインがあるか、外部ログイン・カウントが１以上ある場合に表示する。
                ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;

                // 表示
                return View(new ManageLoginsViewModel
                {
                    CurrentLogins = userLogins,
                    OtherLogins = otherLogins
                });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部ログイン削除
        /// POST: /Manage/RemoveLogin
        /// </summary>
        /// <param name="loginProvider">loginProvider</param>
        /// <param name="providerKey">providerKey</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin && Config.EnableEditingOfUserAttribute)
            {
                // メッセージ列挙型
                EnumManageMessageId? message;

                IdentityResult result = null;

                // **最後のサインインの手段は消させない**（#294）。
                //   **パスワードが無く、外部ログインが 1 つだけなら断る。**
                //   **以前は画面で削除ボタンを隠すだけ**（`ShowRemoveButton`）で、要求を送れば消せた。
                if (!await UserManager.HasPasswordAsync(user)
                    && (await UserManager.GetLoginsAsync(user)).Count <= 1)
                {
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) tried to remove the last way to sign in.", user.Id, user.UserName));

                    return RedirectToAction("ManageLogins", new { Message = EnumManageMessageId.Error });
                }

                // ログインを削除
                result = await UserManager.RemoveLoginAsync(user, loginProvider, providerKey);

                // 結果の確認
                if (result.Succeeded)
                {
                    // ログイン削除の成功

                    // クレームを削除（**ログインを消せてから**。#294）
                    // Memory Provider使用の時
                    // 「コレクションが変更されました。列挙操作は実行されない可能性があります。」
                    // 問題で若干冗長なコードに。
                    List<Claim> lc = new List<Claim>();
                    foreach (Claim c in user.Claims)
                    {
                        if (c.Issuer == loginProvider)
                        {
                            lc.Add(c);
                        }
                    }
                    foreach (Claim c in lc)
                    {
                        await UserManager.RemoveClaimAsync(user, c);
                    }

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        message = EnumManageMessageId.RemoveExternalLoginSuccess;
                    }
                    else
                    {
                        // 再ログインに失敗
                        message = EnumManageMessageId.Error;
                    }
                }
                else
                {
                    // ログイン削除の失敗
                    message = EnumManageMessageId.Error;
                }

                // ログイン管理画面（ログイン削除結果
                return RedirectToAction("ManageLogins", new { Message = message });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部ログイン（リダイレクト）の開始
        /// POST: /Manage/ExternalLogin
        /// </summary>
        /// <param name="provider">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLogin(string provider)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // **登録されていない provider は、外部ログインの管理画面へ戻す**（#294）。
                //   以前は `Challenge` が例外を出し、500 になっていた（AccountController と同じ）。
                if (!(await SignInManager.GetExternalAuthenticationSchemesAsync()).Any(x => x.Name == provider))
                {
                    Logging.MyOperationTrace(string.Format(
                        "An unknown external login provider was requested. ({0})", LogSanitizer.Sanitize(provider)));

                    return RedirectToAction("ManageLogins", new { Message = EnumManageMessageId.Error });
                }

                // Request a redirect to the external login provider
                string redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Manage");
                AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
                return this.Challenge(properties, provider);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 外部LoginのCallback（ExternalLoginCallback）
        /// Redirect後、外部Login providerに着信し、そこで、
        /// URL fragmentを切捨てCookieに認証Claim情報を設定、
        /// その後、ココにRedirectされ、認証Claim情報を使用してSign-Inする。
        /// （外部Login providerからRedirectで戻る先のURLのAction method）
        /// GET: /Manage/ExternalLoginCallback
        /// </summary>
        /// <param name="returnUrl">string</param>
        /// <param name="remoteError">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl, string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                return RedirectToAction(nameof(Index));
            }

            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // AccountControllerはサインアップかどうかを判定して処理する必要がある。
                // ManageControllerは判定不要だが、サインイン後なので、uidが一致する必要がある。

                // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
                // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

                //// ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
                //AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
                // 外部ログイン・プロバイダからユーザに関する情報を取得する。
                ExternalLoginInfo externalLoginInfo = await SignInManager.GetExternalLoginInfoAsync();
                if (externalLoginInfo == null)
                {
                    return RedirectToAction(nameof(Index));
                }

                ApplicationUser user = null;
                IdentityResult idResult = null;

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
                    //   **name / email は返さないプロバイダがある**ので、null のまま進める。
                    //   **email は鍵なので必須、name は無くてよい**（#294。AccountController と同じ）。
                    string id = idClaim.Value;
                    string name = nameClaim?.Value;
                    string email = emailClaim?.Value;

                    // **鍵はメアド**（#151 の段階 3）。
                    string uid = email;

                    if (!string.IsNullOrWhiteSpace(email))
                    {
                        // クレーム情報（e-mail情報）を取得できた（name は無くてよい。#294）。

                        // サインイン中のユーザ
                        ApplicationUser currentUser = await UserManager.GetUserAsync(User);

                        // 既存の外部ログインを確認する。
                        user = await UserManager.FindByLoginAsync(
                            externalLoginInfo.LoginProvider,
                            externalLoginInfo.ProviderKey);

                        if (user != null)
                        {
                            // 既存の外部ログインがある場合。

                            if (user.Id != currentUser.Id)
                            {
                                // **ほかの利用者に結び付いている**（#294）。
                                //   **以前は、その利用者のクレームを書き換え、成功したように戻っていた。**
                                return RedirectToAction("ManageLogins",
                                    new { Message = EnumManageMessageId.AccountConflictInSocialLogin });
                            }

                            // ユーザーが既に外部ログインしている場合は、クレームを更新する。
                            //   **同じ種類の古いクレームを消してから足す**（#294）。
                            idResult = await this.ReplaceClaimAsync(user, emailClaim);
                            idResult = await this.ReplaceClaimAsync(user, nameClaim);

                            //// SignInAsyncより、ExternalSignInAsyncが適切。

                            // ManageControllerではサインイン済みなので、何もしない。
                            return RedirectToAction("ManageLogins");
                        }
                        else
                        {
                            // 既存の外部ログインがない。

                            // ManageControllerではサインアップ・サインイン
                            // 済みなので、外部ログインの追加のみ行なう。
                            user = currentUser;

                            // uid（e-mail情報）が一致している必要がある。
                            //   **利用者名ではなく、メアドと比べる**（#294）。
                            //   **利用者名とメアドを分けた**（#151）**後も利用者名と比べていた**ので、
                            //   **利用者名がメアドと違う利用者は、外部ログインを結び付けられなかった。**
                            if (string.Equals(user.Email, uid, StringComparison.OrdinalIgnoreCase))
                            {
                                // uid（e-mail情報）が一致している。

                                // 外部ログイン（ = UserLoginInfo ）の追加
                                idResult = await UserManager.AddLoginAsync(user, externalLoginInfo);

                                // クレーム（emailClaim, nameClaim, etc.）の追加
                                if (idResult.Succeeded)
                                {
                                    idResult = await UserManager.AddClaimAsync(user, emailClaim);
                                    idResult = await this.ReplaceClaimAsync(user, nameClaim); // name は無いことがある
                                    // ・・・
                                    // ・・・
                                    // ・・・
                                }

                                // 上記の結果の確認
                                if (idResult.Succeeded)
                                {
                                    // 外部ログインの追加に成功した場合 → サインイン

                                    // SignInAsync、ExternalSignInAsync
                                    // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                    await SignInManager.SignInAsync(
                                        user,
                                        isPersistent: false);//,  // rememberMe は false 固定（外部ログインの場合）
                                        //rememberBrowser: true); // rememberBrowser は true 固定

                                    IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                                    responseCookies.Set(Config.AuthTimeCookieName,
                                        Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow), this._cookieOptions);
                            
                                    // リダイレクト
                                    return RedirectToAction("ManageLogins");
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
                                // uid（e-mail情報）が一致していない。
                                // 外部ログインのアカウントを間違えている。
                                return RedirectToAction("ManageLogins",
                                    new { Message = EnumManageMessageId.AccountConflictInSocialLogin });

                            } // else処理済
                        } // else処理済
                    } // クレーム情報（e-mail情報）を取得できなかった。
                } // クレーム情報（ID情報）を取得できなかった。

                // ログイン情報を受け取れなかった場合や、その他の問題が在った場合。
                return RedirectToAction("ManageLogins", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion
    }
}
