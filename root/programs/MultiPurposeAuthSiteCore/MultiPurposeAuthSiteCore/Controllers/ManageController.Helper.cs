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
再サインイン、エラーの表示、メールの送信、TOTP の鍵と QR コードを担う
ManageControllerの補助
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Framework.StdMigration;
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
                    new { userId = uid, code = code }, protocol: HttpContext.Request.Scheme
                );

            await EmailSender.SendAsync(email, Resources.AccountController.SendEmail_emailconfirm,
                string.Format(Resources.AccountController.SendEmail_emailconfirm_msg, callbackUrl));
        }

        /// <summary>
        /// アカウント変更の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendChangeCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            await EmailSender.SendAsync(user.Email, GetContentOfLetter.Get("AccountChangeWasCompletedEmailTitle", CustomEncode.UTF_8, ""),
                string.Format(GetContentOfLetter.Get("AccountChangeWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        #endregion

        #region 2FA(TOTP)

        /// <summary>LoadSharedKeyAndQrCodeUriAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="model">EnableAuthenticatorViewModel</param>
        /// <returns>－</returns>
        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            string totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(totpAuthenticatorKey))
            {
                await UserManager.ResetAuthenticatorKeyAsync(user);
                totpAuthenticatorKey = await UserManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = this.FormatKey(totpAuthenticatorKey);
            model.AuthenticatorUri = this.GenerateQrCodeUri(user.Email, totpAuthenticatorKey);
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
