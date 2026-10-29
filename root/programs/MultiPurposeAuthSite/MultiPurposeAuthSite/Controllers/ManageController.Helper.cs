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
//*  2026/10/29  玄人 幸道         メールを要求から切り離して送る・パスワードの確認・クレームの入れ替え（#294）
//*  2026/10/30  玄人 幸道         再サインインで auth_time を書かない・アカウント記憶を引き継ぐ・パスワードの確認を
//*                                ほかの操作でも使う・メールの間隔を宛先ごとに数える・メアドの変更を変更前のメアドにも
//*                                知らせる・クレームの入れ替えを発行元ごとに（#294）
//**********************************************************************************

/*
再サインイン、パスワードの確認、エラーの表示、
メールの送信、クレームの入れ替えを担う
ManageControllerの補助
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;

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
        /// <remarks>
        /// **auth_time は書かない**（#294）。**資格情報を確かめていない**ので、認証したことにはならない。
        /// **以前は書いていた**ので、**2FA の有効化などの操作だけで `max_age` の再認証が要らなくなっていた。**
        /// 書くのは、資格情報を確かめた所だけ（`WriteAuthTime`）。
        /// </remarks>
        private async Task<bool> ReSignInAsync()
        {
            // 認証されたユーザを取得
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            // ユーザの確認
            if (user != null)
            {
                // **いまのサインインの「アカウント記憶」を引き継ぐ**（#294）。
                //   以前は false 固定で、管理画面で何か操作すると、ブラウザを閉じれば切れるサインインに変わっていた。
                AuthenticateResult current = await AuthenticationManager.AuthenticateAsync(
                    DefaultAuthenticationTypes.ApplicationCookie);
                bool isPersistent = current?.Properties?.IsPersistent ?? false;

                // 認証されたユーザが無い
                // 再度サインイン
                // **ここでブラウザ記憶(2FA)を付けない。**
                //   付けると、2FAを有効にする操作それ自体が、そのブラウザを「記憶済み」にしてしまい、
                //   以後そのブラウザでは2FAが要求されなくなる（利用者は有効にしたつもりでいる）。
                //   サインイン時の判定が「2FAが有効」かつ「ブラウザを記憶していない」であるため。
                //   記憶するのは、利用者が2FAを通して「ブラウザ記憶」を選んだときだけ（Account/VerifyCode）。
                //   net10.0版は、同じ引数を渡していない。
                //
                //   再サインインそのものは必要（SecurityStampが変わるため）。
                await SignInManager.SignInAsync(
                        user,
                        isPersistent: isPersistent, // アカウント記憶
                        rememberBrowser: false);    // ブラウザ記憶(2FA)

                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>auth_time を、いまの時刻にする（資格情報を確かめた所だけで呼ぶ。#294）</summary>
        private void WriteAuthTime()
        {
            Response.Cookies[Config.AuthTimeCookieName].Value = Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow);
        }

        #endregion

        #region パスワードの確認

        /// <summary>
        /// 利用者名・メアドの変更の前に、パスワードを確かめる（#294）。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="password">入力されたパスワード</param>
        /// <returns>確かめられたら null、そうでなければ画面に出す文言</returns>
        private async Task<string> CheckPasswordForEditingAsync(ApplicationUser user, string password)
        {
            EnumManageMessageId? error = await this.VerifyPasswordAsync(user, password);

            return error == null ? null
                : error == EnumManageMessageId.PasswordNotSet ? Resources.ManageController.PasswordNotSet
                : Resources.ManageController.PasswordIncorrect;
        }

        /// <summary>
        /// 操作の前に、パスワードを確かめる（#294）。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="password">入力されたパスワード</param>
        /// <returns>確かめられたら null、そうでなければ断る理由</returns>
        /// <remarks>
        /// **以前は `PasswordSignInAsync`（サインインそのもの）で確かめていた。**
        /// - **2FA を有効にした利用者は、必ず失敗していた**（`RequiresVerification` が返る）
        /// - **パスワードを持たない利用者**（外部ログインだけ）**は、通しようが無かった**
        /// - **間違えても、何も言わずに画面を出し直していた**
        ///
        /// **サインインはしない**（2FA に関わらない）。**ロックアウトは数える**（`PasswordSignInAsync` と同じ手順）。
        /// **パスワードを持たない利用者は断る**（先に設定してもらう）。
        /// **確かめられたら auth_time を書く**（資格情報を確かめたため）。
        /// </remarks>
        private async Task<EnumManageMessageId?> VerifyPasswordAsync(ApplicationUser user, string password)
        {
            if (!await UserManager.HasPasswordAsync(user.Id))
            {
                // パスワードを持たない（先に設定してもらう）
                return EnumManageMessageId.PasswordNotSet;
            }

            if (await UserManager.IsLockedOutAsync(user.Id))
            {
                // ロックアウト中（パスワードが合っていても通さない。文言は同じ）
                return EnumManageMessageId.PasswordIncorrect;
            }

            if (!await UserManager.CheckPasswordAsync(user, password ?? ""))
            {
                // Passwordが一致しない。
                if (Config.UserLockoutEnabledByDefault)
                {
                    await UserManager.AccessFailedAsync(user.Id);
                }

                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) failed to confirm the password.", user.Id, user.UserName));

                return EnumManageMessageId.PasswordIncorrect;
            }

            // Passwordが一致した。
            await UserManager.ResetAccessFailedCountAsync(user.Id);
            this.WriteAuthTime();

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
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError("", error);
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
        /// **以前は `async void` で送っていて、SMTP の失敗が要求の完了と競合した。**
        /// **管理画面の間隔は、宛先ごとに数える**（`MailThrottle.TryAcquireForDestination`）。
        /// </remarks>
        private void SendMailInBackground(
            string purpose, string userId, string destination, string subject, string body)
        {
            Task.Run(async () =>
            {
                try
                {
                    await new EmailService().SendAsync(new IdentityMessage()
                    {
                        Destination = destination,
                        Subject = subject,
                        Body = body
                    });
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
                        Sts.MailThrottle.ReleaseForDestination(purpose, destination);
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
        /// **同じ宛先に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）。
        /// **宛先ごとに数える** — 打ち間違いを直した宛先へは、すぐに送れる。
        /// **断ったときは確認の符号も作り直さない** —
        /// 作り直すと、先に送ったリンクが使えなくなり、新しいリンクも届かない。
        /// </remarks>
        private void SendConfirmEmail(ApplicationUser user, string newEmail)
        {
            if (!Sts.MailThrottle.TryAcquireForDestination(Sts.MailThrottle.PurposeEmailChange, newEmail, user.Id))
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
                    new { userId = user.Id, code = customizedConfirmationJson.Code }, protocol: Request.Url.Scheme
                );

            this.SendMailInBackground(Sts.MailThrottle.PurposeEmailChange, user.Id,
                newEmail, Resources.AccountController.SendEmail_emailconfirm,
                string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl));
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理（文面が無ければ送らない。#294）。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="oldEmail">変更前のメアド（メアドの変更のとき。それ以外は null）</param>
        /// <remarks>
        /// **完了メールの文面には、既定値（リソース）が無い。**
        /// **以前は、文面のファイルが無いと、件名も本文も空のメールを送っていた。**
        ///
        /// **メアドを変えたときは、変更前のメアドにも送る**（#294）。
        /// **変えたのが本人でなければ、本人が気付けるのは、変更前のメアドだけである。**
        /// </remarks>
        private void SendChangeCompletedEmail(ApplicationUser user, string oldEmail = null)
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

            if (!string.IsNullOrWhiteSpace(oldEmail)
                && !string.Equals(oldEmail, user.Email, StringComparison.OrdinalIgnoreCase))
            {
                this.SendMailInBackground(null, user.Id, oldEmail, subject, string.Format(body, user.UserName));
            }
        }

        #endregion

        #region 外部ログイン

        /// <summary>同じ発行元・同じ種類のクレームを、新しい値に入れ替える（#294）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">新しいクレーム（null なら何もしない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **`AccountController.ReplaceClaimAsync` と同じ。**
        /// **以前は「新しい値を消して、新しい値を足す」だった**ので、**値が変わると古いクレームがたまっていった。**
        /// **消すのは同じ発行元（外部ログインのプロバイダ）の分だけ** —
        /// 種類だけで消すと、**ほかのプロバイダのクレームまで消えていた。**
        /// </remarks>
        private async Task<IdentityResult> ReplaceClaimAsync(ApplicationUser user, Claim claim)
        {
            if (claim == null)
            {
                return IdentityResult.Success;
            }

            foreach (Claim old in (await UserManager.GetClaimsAsync(user.Id))
                .Where(c => c.Type == claim.Type && c.Issuer == claim.Issuer).ToList())
            {
                await UserManager.RemoveClaimAsync(user.Id, old);
            }

            return await UserManager.AddClaimAsync(user.Id, claim);
        }

        #endregion
    }
}
