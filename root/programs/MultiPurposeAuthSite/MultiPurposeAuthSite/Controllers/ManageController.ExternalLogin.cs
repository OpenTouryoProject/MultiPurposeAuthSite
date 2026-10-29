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
//**********************************************************************************

/*
外部ログインの関連付け・解除、
同意の一覧・取り消しを担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web.Mvc;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

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
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

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
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
                    message == EnumManageMessageId.Error ? Resources.ManageController.Error
                    : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                    : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                    : "";

                // 認証されたユーザを取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // 現在の認証ユーザが外部ログイン済みの外部ログイン情報を取得
                IList<UserLoginInfo> userLogins = await UserManager.GetLoginsAsync(User.Identity.GetUserId());

                // 現在の認証ユーザが未ログインの外部ログイン情報を取得
                List<AuthenticationDescription> otherLogins = new List<AuthenticationDescription>();

                #region Collect otherLogins
                //// auth : AuthenticationDescription
                //// ul   : UserLoginInfo
                //otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().
                //    Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();

                // 以下と等価（どっちが楽？）

                IEnumerable<AuthenticationDescription> allExternalLogins = AuthenticationManager.GetExternalAuthenticationTypes();
                foreach (AuthenticationDescription auth in allExternalLogins)
                {
                    bool flg = true;
                    foreach (UserLoginInfo ul in userLogins)
                    {
                        if (auth.AuthenticationType == ul.LoginProvider)
                        {
                            flg = false;
                        }
                    }

                    // userLoginsに存在しないものだけ追加
                    if (flg) otherLogins.Add(auth);
                }
                #endregion

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
            if (Config.CanEditExtLogin && Config.EnableEditingOfUserAttribute)
            {
                // メッセージ列挙型
                EnumManageMessageId? message;

                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                IdentityResult result = null;

                // クレームを削除
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
                    result = await UserManager.RemoveClaimAsync(user.Id, c);
                }

                // ログインを削除
                result = await UserManager.RemoveLoginAsync(
                    User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));

                // 結果の確認
                if (result.Succeeded)
                {
                    // ログイン削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
        public ActionResult ExternalLogin(string provider)
        {
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // Request a redirect to the external login provider
                //  to link a login for the current user.
                // 現在のユーザーのログインをリンクするために
                // 外部ログイン プロバイダーへのリダイレクトを要求します。
                return new ExternalLoginStarter(
                provider,
                Url.Action("ExternalLoginCallback", "Manage"), User.Identity.GetUserId());
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
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            if (Config.CanEditExtLogin
                && Config.EnableEditingOfUserAttribute)
            {
                // AccountControllerはサインアップかどうかを判定して処理する必要がある。
                // ManageControllerは判定不要だが、サインイン後なので、uidが一致する必要がある。

                // asp.net mvc - MVC 5 Owin Facebook Auth results in Null Reference Exception - Stack Overflow
                // http://stackoverflow.com/questions/19564479/mvc-5-owin-facebook-auth-results-in-null-reference-exception

                // ログイン プロバイダーが公開している認証済みユーザーに関する情報を受け取る。
                AuthenticateResult authenticateResult = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie);
                // 外部ログイン・プロバイダからユーザに関する情報を取得する。
                ExternalLoginInfo externalLoginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();

                IdentityResult result = null;
                //SignInStatus signInStatus = SignInStatus.Failure;

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
                        //   **削除せずコメントアウトにしてある**（戻せるように）。
                        //   同じ処理が `AccountController.ExternalLoginCallback` にもある。
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

                        // **鍵はメアド**（#151 の段階 3）。
                        string uid = email;

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

                                // ManageControllerではサインイン済みなので、何もしない。
                                return RedirectToAction("ManageLogins");
                            }
                            else
                            {
                                // 既存の外部ログインがない。

                                // ManageControllerではサインアップ・サインイン
                                // 済みなので、外部ログインの追加のみ行なう。

                                // サインアップ済みの可能性を探る
                                user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                                // uid（e-mail or name情報）が一致している必要がある。
                                //   Manage（サインイン済み）なので、
                                //   RequireUniqueEmail == false時のname and e-mailまでの一致は不要。
                                if (user.UserName == uid)
                                {
                                    // uid（e-mail, name情報）が一致している。

                                    // 外部ログイン（ = UserLoginInfo ）の追加
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
                                        // 外部ログインの追加に成功した場合 → サインイン

                                        // SignInAsync、ExternalSignInAsync
                                        // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                        await SignInManager.SignInAsync(
                                            user,
                                            isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                            rememberBrowser: true); // rememberBrowser は true 固定

                                        Response.Cookies[Config.AuthTimeCookieName].Value = Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow);

                                        // リダイレクト
                                        return RedirectToAction("ManageLogins");
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
                                    // uid（e-mail, name情報）が一致していない。
                                    // 外部ログインのアカウントを間違えている。
                                    return RedirectToAction("ManageLogins", 
                                        new { Message = EnumManageMessageId.AccountConflictInSocialLogin });

                                } // else処理済
                            } // else処理済
                        } // クレーム情報（e-mail, name情報）を取得できなかった。
                    } // クレーム情報（ID情報）を取得できなかった。
                } // ログイン情報を取得できなかった。

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
