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
//**********************************************************************************

/*
再サインイン、エラーの表示、メールの送信を担う
ManageControllerの補助
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;

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
        private async Task<bool> ReSignInAsync()
        {
            // 認証されたユーザを取得
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            // ユーザの確認
            if (user != null)
            {
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
                        isPersistent: false,        // アカウント記憶    // 既定値
                        rememberBrowser: false);    // ブラウザ記憶(2FA)

                Response.Cookies[Config.AuthTimeCookieName].Value = Sts.AuthTimeCookie.ProtectAuthTime(DateTime.UtcNow);

                return true;
            }
            else
            {
                return false;
            }
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
        /// メアド検証で使用するメール送信処理。
        /// </summary>
        /// <param name="uid">string</param>
        /// <param name="email">string</param>
        /// <param name="code">string</param>
        private async void SendConfirmEmail(string uid, string email, string code)
        {
            string callbackUrl;

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Manage",
                    new { userId = uid, code = code }, protocol: Request.Url.Scheme
                );

            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = Resources.AccountController.SendEmail_emailconfirm;
            idmsg.Destination = email;
            idmsg.Body = string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl);

            await ems.SendAsync(idmsg);
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendChangeCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            EmailService ems = new EmailService();
            IdentityMessage idmsg = new IdentityMessage();

            idmsg.Subject = GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, "");
            idmsg.Destination = user.Email;
            idmsg.Body = string.Format(GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName);

            await ems.SendAsync(idmsg);
        }

        #endregion
    }
}
