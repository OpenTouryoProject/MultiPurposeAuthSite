//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController の 2 要素認証
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         TOTP の鍵をコードの確認後に保存・TOTP の画面を CanEdit2FA で閉じる・
//*                                鍵のリセットで SecurityStamp を更新・SMS を続けて送らない（#294）
//**********************************************************************************

/*
電話番号の登録・検証・削除、2 要素認証の有効化・無効化、
TOTP の認証アプリ・回復コードを担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController の 2 要素認証**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region Phone Number

        #region Createプロセス

        #region Create

        /// <summary>
        /// 電話番号の追加画面（初期表示）
        /// GET: /Manage/AddPhoneNumber
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AddPhoneNumber()
        {
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 電話番号の追加画面（電話番号の追加）
        /// POST: /Manage/AddPhoneNumber
        /// </summary>
        /// <param name="model">ManageAddPhoneNumberViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(ManageAddPhoneNumberViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPhoneNumberViewModelの検証に成功

                    // **同じ利用者に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）。
                    if (Sts.MailThrottle.TryAcquire(Sts.MailThrottle.PurposePhoneNumber, user.Id))
                    {
                        // 検証コード生成
                        string code = await UserManager.GenerateChangePhoneNumberTokenAsync(user, model.Number);

                        // メッセージをSMSで送信する。
                        await SmsSender.SendAsync(model.Number,
                            GetContentOfLetter.Get("AddPhoneNumber",
                            CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code);
                    }

                    // 電話番号の検証画面に進む
                    return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.Number });
                }
                else
                {
                    // ManageAddPhoneNumberViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Verify

        /// <summary>
        /// 追加電話番号の検証画面（初期表示）
        /// GET: /Manage/VerifyPhoneNumber
        /// </summary>
        /// <param name="phoneNumber">追加電話番号</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public ActionResult VerifyPhoneNumber(string phoneNumber)
        {
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                return phoneNumber == null ?
                View("Error") :
                View("VerifyPhoneNumber", new ManageVerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 追加電話番号の検証画面（検証コードの検証）
        /// POST: /Manage/VerifyPhoneNumber
        /// </summary>
        /// <param name="model">ManageVerifyPhoneNumberViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(ManageVerifyPhoneNumberViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageVerifyPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageVerifyPhoneNumberViewModelの検証に成功

                    // 電話番号の検証（電話番号の登録の際に、SMSで送信した検証コードを検証）
                    IdentityResult result = await UserManager.ChangePhoneNumberAsync(
                    	user, model.PhoneNumber, model.Code);

                    // 電話番号の検証結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync(user.Id);

                        // Index - AddPhoneSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.AddPhoneSuccess });
                    }
                    else
                    {
                        // 失敗
                        ModelState.AddModelError("", Resources.ManageController.FailedVerifyPhoneNumber);
                    }
                }
                else
                {
                    // ManageVerifyPhoneNumberViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region Delete

        /// <summary>
        /// 電話番号の削除
        /// POST: /Manage/RemovePhoneNumber
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone && Config.EnableEditingOfUserAttribute)
            {
                // null クリア
                IdentityResult result = await UserManager.SetPhoneNumberAsync(user, "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // 電話番号削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemovePhoneSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 電話番号削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region 2FA

        #region 2FAの有効化・無効化

        /// <summary>
        /// 2FAの有効化
        /// POST: /Manage/EnableTwoFactorAuthentication
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの有効化
                await UserManager.SetTwoFactorEnabledAsync(user, true);

                // 再ログイン
                await this.ReSignInAsync(user.Id);

                return RedirectToAction("Index", "Manage");
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 2FAの無効化
        /// POST: /Manage/DisableTwoFactorAuthentication
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの無効化
                await UserManager.SetTwoFactorEnabledAsync(user, false);

                // 再ログイン
                await this.ReSignInAsync(user.Id);

                return RedirectToAction("Index", "Manage");
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region 2FA(TOTP)の有効化・無効化

        #region EnableTwoFactorAuthenticator

        /// <summary>EnableTwoFactorAuthenticator（初期表示）</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>**鍵は、ここでは保存しない**（#294。`LoadSharedKeyAndQrCodeUriAsync`）。</remarks>
        [HttpGet]
        public async Task<ActionResult> EnableTwoFactorAuthenticator()
        {
            // **TOTP の画面も、2FA の変更と同じ設定で閉じる**（#294。以前は閉じていなかった）。
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            // QRコード生成
            ManageEnableTwoFactorAuthenticatorViewModel model
                = new ManageEnableTwoFactorAuthenticatorViewModel();

            await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return View(model);
        }

        /// <summary>EnableTwoFactorAuthenticator</summary>
        /// <param name="model">ManageEnableTwoFactorAuthenticatorViewModel</param>
        /// <returns>IActionResult</returns>
        /// <remarks>
        /// **コードを確かめてから、鍵を保存する**（#294）。
        /// **2FA も有効にする**（認証アプリを登録したのに、2FA が無効のままにならないように）。
        /// </remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthenticator(ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (ModelState.IsValid)
            {
                string code = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

                // トークン検証
                //   **鍵が保存済みなら、その鍵で。まだなら、画面に出した鍵（TempData）で。**
                bool hasStoredKey = !string.IsNullOrEmpty(await UserManager.GetAuthenticatorKeyAsync(user));
                string pendingKey = TempData.Peek(PendingAuthenticatorKey) as string;

                bool is2faTokenValid = false;

                if (hasStoredKey)
                {
                    is2faTokenValid = await UserManager.VerifyTwoFactorTokenAsync(
                        user, UserManager.Options.Tokens.AuthenticatorTokenProvider, code);
                }
                else if (!string.IsNullOrEmpty(pendingKey))
                {
                    is2faTokenValid = await this.VerifyPendingAuthenticatorCodeAsync(user, pendingKey, code);
                }

                if (is2faTokenValid)
                {
                    // valid
                    if (!hasStoredKey)
                    {
                        // **ここで初めて鍵を保存する**（SecurityStamp も更新する。ResetAuthenticatorKeyAsync と同じ）。
                        user.TotpAuthenticatorKey = pendingKey;
                        await UserManager.UpdateSecurityStampAsync(user);
                        TempData.Remove(PendingAuthenticatorKey);
                    }

                    await UserManager.SetTwoFactorEnabledAsync(user, true);

                    // 再ログイン（SecurityStamp が変わったため）
                    await this.ReSignInAsync(user.Id);

                    Logging.MyOperationTrace(string.Format(
                        "User with ID {0} has enabled 2FA with an authenticator app.", user.Id));

                    IEnumerable<string> recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

                    return RedirectToAction(nameof(ShowTwoFactorAuthenticatorRecoveryCodes));
                }
                else
                {
                    // invalid
                    ModelState.AddModelError("Code", Resources.ManageController.InvalidVerificationCode);
                    await LoadSharedKeyAndQrCodeUriAsync(user, model);
                    return View(model);
                }
            }
            else
            {
                // リトライ
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }
        }

        /// <summary>ShowTwoFactorAuthenticatorRecoveryCodes（初期表示）</summary>
        /// <returns>IActionResult</returns>
        [HttpGet]
        public ActionResult ShowTwoFactorAuthenticatorRecoveryCodes()
        {
            string[] recoveryCodes = (string[])TempData[RecoveryCodesKey];

            if (recoveryCodes != null)
            {
                ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel model
                = new ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };

                return View(model); 
            }
            else
            {
                return RedirectToAction(nameof(Index));
            }
        }

        #endregion

        #region ManageTwoFactorAuthenticator

        /// <summary>ManageTwoFactorAuthenticator</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> ManageTwoFactorAuthenticator()
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            ManageTwoFactorAuthenticationViewModel model
                = new ManageTwoFactorAuthenticationViewModel
            {
                Is2faEnabled = user.TwoFactorEnabled,
                HasAuthenticator = !string.IsNullOrEmpty(await UserManager.GetAuthenticatorKeyAsync(user)),
                RecoveryCodesLeft = await UserManager.CountRecoveryCodesAsync(user),
            };

            return View(model);
        }

        #endregion

        #region ResetTwoFactorAuthenticator

        /// <summary>ResetTwoFactorAuthenticator（初期表示）</summary>
        /// <returns>IActionResult</returns>
        [HttpGet]
        public ActionResult ResetTwoFactorAuthenticator()
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            return View();
        }

        /// <summary>ResetTwoFactorAuthenticator</summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetTwoFactorAuthenticator(string x)
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            //await UserManager.SetTwoFactorEnabledAsync(user, false); // これ要る？
            // 確かにAuthenticatorKeyはRollingする（が、nullにはならない）。
            //await UserManager.ResetAuthenticatorKeyAsync(user);

            // 自前で、AuthenticatorKeyとTokensを、nullクリアする
            user.TotpTokens = null;
            user.TotpAuthenticatorKey = null;

            // **SecurityStamp も更新する**（#294。保存も、これが行う）。
            //   **以前は更新しておらず、ほかのセッションが残っていた**（ResetAuthenticatorKeyAsync は更新する）。
            await UserManager.UpdateSecurityStampAsync(user);

            // 再ログイン（SecurityStamp が変わったため）
            await this.ReSignInAsync(user.Id);

            Logging.MyOperationTrace(string.Format(
                            "User with id '{0}' has reset their authentication app key.", user.Id));

            return RedirectToAction(nameof(Index));
        }

        #endregion

        #region TwoFactorAuthenticatorRecoveryCodes

        /// <summary>GenerateTwoFactorAuthenticatorRecoveryCodes（初期表示）</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult GenerateTwoFactorAuthenticatorRecoveryCodes()
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            return View();
        }

        /// <summary>GenerateTwoFactorAuthenticatorRecoveryCodes</summary>
        /// <param name="s">dummy</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> GenerateTwoFactorAuthenticatorRecoveryCodes(string s)
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (user.TwoFactorEnabled)
            {
                IEnumerable<string> recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                Logging.MyOperationTrace(string.Format(
                            "User with ID {0} has generated new 2FA recovery codes.", user.Id));

                ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel model
                    = new ManageShowTwoFactorAuthenticatorRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

                return View("ShowTwoFactorAuthenticatorRecoveryCodes", model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }            
        }

        #endregion

        #endregion

        #endregion
    }
}
