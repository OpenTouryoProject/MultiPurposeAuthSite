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
//**********************************************************************************

/*
電話番号の登録・検証・削除、2 要素認証の有効化・無効化、
TOTP の認証アプリ・回復コードを担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;

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

                    // 検証コード生成
                    string code = await UserManager.GenerateChangePhoneNumberTokenAsync(user, model.Number);

                    // メッセージをSMSで送信する。
                    await SmsSender.SendAsync(model.Number,
                        GetContentOfLetter.Get("AddPhoneNumber",
                        CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code);

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
        [HttpGet]
        public async Task<ActionResult> EnableTwoFactorAuthenticator()
        {
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
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthenticator(ManageEnableTwoFactorAuthenticatorViewModel model)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (ModelState.IsValid)
            {
                // トークン検証
                bool is2faTokenValid = await UserManager.VerifyTwoFactorTokenAsync(
                    user, UserManager.Options.Tokens.AuthenticatorTokenProvider,
                    model.Code.Replace(" ", string.Empty).Replace("-", string.Empty));

                if (is2faTokenValid)
                {
                    // valid
                    Logging.MyOperationTrace(string.Format(
                        "User with ID {0} has enabled 2FA with an authenticator app.", user.Id));

                    IEnumerable<string> recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

                    return RedirectToAction(nameof(ShowTwoFactorAuthenticatorRecoveryCodes));
                }
                else
                {
                    // invalid
                    ModelState.AddModelError("Code", "Verification code is invalid.");
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
            return View();
        }

        /// <summary>ResetTwoFactorAuthenticator</summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetTwoFactorAuthenticator(string x)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            //await UserManager.SetTwoFactorEnabledAsync(user, false); // これ要る？
            // 確かにAuthenticatorKeyはRollingする（が、nullにはならない）。
            //await UserManager.ResetAuthenticatorKeyAsync(user);

            // 自前で、AuthenticatorKeyとTokensを、nullクリアする
            user.TotpTokens = null;
            user.TotpAuthenticatorKey = null;
            await UserManager.UpdateAsync(user);

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
            return View();
        }

        /// <summary>GenerateTwoFactorAuthenticatorRecoveryCodes</summary>
        /// <param name="s">dummy</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> GenerateTwoFactorAuthenticatorRecoveryCodes(string s)
        {
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
