//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController の補助
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         メールを要求から切り離して送る・パスワードの確認・クレームの入れ替え・
//*                                TOTP の鍵をコードの確認まで保存しない（#294）
//**********************************************************************************

/*
再サインイン、パスワードの確認、エラーの表示、メールの送信、
クレームの入れ替え、TOTP の鍵と QR コードを担う
ManageControllerの補助
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AspNetId = Microsoft.AspNetCore.Identity;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController の補助**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region 再度サインイン

        /// <summary>
        /// 再度サインインする。
        /// Cookie再設定 or SecurityStamp対応
        /// </summary>
        /// <returns>Task</returns>
        private async Task<bool> ReSignInAsync(string userId)
        {
            // 認証されたユーザを取得
            ApplicationUser user = await UserManager.FindByIdAsync(userId);

            // ユーザの確認
            if (user != null)
            {
                // 認証されたユーザが無い
                // 再度サインイン
                await SignInManager.SignInAsync(
                        user,
                        isPersistent: false);//,      // アカウント記憶    // 既定値
                        //rememberBrowser: true);     // ブラウザ記憶(2FA) // 既定値

                IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
                responseCookies.Set(Config.AuthTimeCookieName,
                    Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow), this._cookieOptions);

                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion

        #region パスワードの確認

        /// <summary>
        /// 利用者名・メアドの変更の前に、パスワードを確かめる（#294）。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="password">入力されたパスワード</param>
        /// <returns>確かめられたら null、そうでなければ画面に出す文言</returns>
        /// <remarks>
        /// **以前は `PasswordSignInAsync`（サインインそのもの）で確かめていた。**
        /// - **2FA を有効にした利用者は、必ず失敗していた**（`RequiresTwoFactor` が返る）
        /// - **パスワードを持たない利用者**（外部ログインだけ）**は、通しようが無かった**
        /// - **間違えても、何も言わずに画面を出し直していた**
        ///
        /// **`CheckPasswordSignInAsync` はサインインしない**（2FA に関わらない）。**ロックアウトは数える。**
        /// </remarks>
        private async Task<string> CheckPasswordForEditingAsync(ApplicationUser user, string password)
        {
            if (!await UserManager.HasPasswordAsync(user))
            {
                // パスワードを持たない（先に設定してもらう）
                return Resources.ManageController.PasswordNotSet;
            }

            AspNetId.SignInResult result = await SignInManager.CheckPasswordSignInAsync(
                user, password ?? "", lockoutOnFailure: Config.UserLockoutEnabledByDefault);

            if (!result.Succeeded)
            {
                // Passwordが一致しない（ロックアウト中も同じ文言）
                return Resources.ManageController.PasswordIncorrect;
            }

            // Passwordが一致した。
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;
            responseCookies.Set(Config.AuthTimeCookieName,
                Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow), this._cookieOptions);

            return null;
        }

        #endregion

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

        #endregion

        #region メール送信処理

        /// <summary>
        /// メールを、要求から切り離して送る（#294）。
        /// </summary>
        /// <param name="purpose">用途（ログと MailThrottle の用途。間隔で絞らないメールは null）</param>
        /// <param name="userId">宛先の利用者の id（ログに書く。メアドは書かない）</param>
        /// <param name="destination">宛先</param>
        /// <param name="subject">件名</param>
        /// <param name="body">本文</param>
        /// <remarks>
        /// **`AccountController.SendMailInBackground` と同じ**（理由もそちらに書いた）。
        /// **以前は `async void` で送っていて、SMTP の失敗でプロセスが落ちることがあった。**
        /// </remarks>
        private void SendMailInBackground(
            string purpose, string userId, string destination, string subject, string body)
        {
            IEmailSender sender = this.EmailSender;

            Task.Run(async () =>
            {
                try
                {
                    await sender.SendAsync(destination, subject, body);
                }
                catch (Exception ex)
                {
                    Logging.MyOperationTrace(string.Format(
                        "The {0} mail to {1} could not be sent. ({2})",
                        purpose ?? "notification", userId, ex.GetType().Name));
                    Logging.MyDebugLogForEx(ex);

                    // **送れなかった分は、間隔に数えない**（すぐに送り直せるように）。
                    if (purpose != null)
                    {
                        Sts.MailThrottle.Release(purpose, userId);
                    }
                }
            });
        }

        /// <summary>
        /// メアドの変更で使用する確認メールの送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="newEmail">更新後のメアド</param>
        /// <remarks>
        /// **同じ利用者に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）。
        /// **そのときは確認の符号も作り直さない** —
        /// 作り直すと、先に送ったリンクが使えなくなり、新しいリンクも届かない。
        /// </remarks>
        private void SendConfirmEmail(ApplicationUser user, string newEmail)
        {
            if (!Sts.MailThrottle.TryAcquire(Sts.MailThrottle.PurposeEmailChange, user.Id))
            {
                return;
            }

            // DB ストアに保存
            CustomizedConfirmationJson customizedConfirmationJson = new CustomizedConfirmationJson
            {
                Code = GetPassword.Base64UrlSecret(128),
                Email = newEmail // 更新後のメアド
            };
            CustomizedConfirmationProvider.GetInstance()
                .CreateCustomizedConfirmationData(user.Id, customizedConfirmationJson);

            // URLの生成
            string callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Manage",
                    new { userId = user.Id, code = customizedConfirmationJson.Code }, protocol: HttpContext.Request.Scheme
                );

            this.SendMailInBackground(Sts.MailThrottle.PurposeEmailChange, user.Id,
                newEmail, Resources.AccountController.SendEmail_emailconfirm,
                string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl));
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理（文面が無ければ送らない。#294）。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// **完了メールの文面には、既定値（リソース）が無い。**
        /// **以前は、文面のファイルが無いと、件名も本文も空のメールを送っていた。**
        /// </remarks>
        private void SendChangeCompletedEmail(ApplicationUser user)
        {
            string subject = GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, "");
            string body = GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, "");

            if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(body))
            {
                Logging.MyOperationTrace(string.Format(
                    "The AccountChangeWasCompletedEmailTitle mail to {0} was not sent. (no letter)", user.Id));
                return;
            }

            this.SendMailInBackground(null, user.Id, user.Email, subject, string.Format(body, user.UserName));
        }

        #endregion

        #region 外部ログイン

        /// <summary>同じ種類のクレームを、新しい値に入れ替える（#294）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">新しいクレーム（null なら何もしない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **`AccountController.ReplaceClaimAsync` と同じ。**
        /// **以前は「新しい値を消して、新しい値を足す」だった**ので、**値が変わると古いクレームがたまっていった。**
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

        #endregion

        #region 2FA(TOTP)

        /// <summary>LoadSharedKeyAndQrCodeUriAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="model">EnableAuthenticatorViewModel</param>
        /// <returns>－</returns>
        /// <remarks>
        /// **鍵が無ければ作るが、保存はしない**（#294）。**コードを確かめてから保存する**（`EnableTwoFactorAuthenticator` の POST）。
        /// **以前は画面を開いただけで鍵を保存していた**ので、**登録を終えていなくても**、
        /// 管理画面は TOTP を「有効」と出し、サインインの手段にも認証アプリが出ていた。
        /// **作った鍵は TempData に置く**（Cookie。Data Protection で守られる）。**やり直しでも同じ鍵を出す。**
        /// </remarks>
        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            string totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(totpAuthenticatorKey))
            {
                totpAuthenticatorKey = TempData.Peek(PendingAuthenticatorKey) as string;

                if (string.IsNullOrEmpty(totpAuthenticatorKey))
                {
                    totpAuthenticatorKey = UserManager.GenerateNewAuthenticatorKey();
                    TempData[PendingAuthenticatorKey] = totpAuthenticatorKey;
                }
            }

            model.SharedKey = this.FormatKey(totpAuthenticatorKey);
            model.AuthenticatorUri = this.GenerateQrCodeUri(user.Email, totpAuthenticatorKey);
        }

        /// <summary>保存する前の鍵で、コードを確かめる（#294）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="pendingKey">保存する前の鍵</param>
        /// <param name="code">コード</param>
        /// <returns>正しければ true</returns>
        /// <remarks>
        /// **利用者そのものには鍵を入れない** — **mem ストアでは、引いた利用者がそのまま保存の実体である**
        /// （入れた時点で保存したことになり、コードが間違っていても鍵が残る）。
        /// **鍵だけを持つ写しで確かめる**（認証アプリのコードの検証は、鍵しか見ない）。
        /// </remarks>
        private async Task<bool> VerifyPendingAuthenticatorCodeAsync(ApplicationUser user, string pendingKey, string code)
        {
            ApplicationUser probe = new ApplicationUser()
            {
                Id = user.Id,
                UserName = user.UserName,
                TotpAuthenticatorKey = pendingKey
            };

            return await UserManager.VerifyTwoFactorTokenAsync(
                probe, UserManager.Options.Tokens.AuthenticatorTokenProvider, code);
        }

        /// <summary>FormatKey</summary>
        /// <param name="unformattedKey">string</param>
        /// <returns>FormatKey</returns>
        private string FormatKey(string unformattedKey)
        {
            StringBuilder result = new StringBuilder();
            int currentPosition = 0;

            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }

            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        /// <summary>GenerateQrCodeUri</summary>
        /// <param name="email">string</param>
        /// <param name="unformattedKey">string</param>
        /// <returns>QrCodeUri</returns>
        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                UrlEncoder.Encode("MultiPurposeAuthSite"),
                UrlEncoder.Encode(email),
                unformattedKey);
        }

        #endregion
    }
}
