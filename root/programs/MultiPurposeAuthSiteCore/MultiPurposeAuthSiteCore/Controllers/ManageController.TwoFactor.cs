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
//*  2026/10/30  玄人 幸道         2FA の無効化・電話番号の削除でパスワードを確かめる・SMS の間隔を電話番号ごとに・
//*                                SMS の失敗で 500 にしない・TOTP の鍵を利用者に結び付ける（#294）
//*  2026/10/30  玄人 幸道         登録済みの TOTP の鍵を出さない・電話番号の追加・認証アプリのリセット・
//*                                回復コードの再発行でパスワードを確かめる（#294）
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

using System;
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
        /// <param name="password">今のパスワード（#294）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(ManageAddPhoneNumberViewModel model, string password)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPhoneNumberViewModelの検証に成功

                    // **パスワードを確かめる**（#294。2 要素認証の手段を足す操作なので）。
                    //   **検証コードは、ここを通った後でしか作らない**（`VerifyPhoneNumber` は、そのコードが無いと通らない）。
                    string error = await this.CheckPasswordForEditingAsync(user, password);
                    if (error != null)
                    {
                        ModelState.AddModelError("", error);
                        return View(model);
                    }

                    // **同じ電話番号に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）。
                    //   **電話番号ごとに数える** — 打ち間違いを直した番号へは、すぐに送れる。
                    if (Sts.MailThrottle.TryAcquireForDestination(Sts.MailThrottle.PurposePhoneNumber, model.Number, user.Id))
                    {
                        // 検証コード生成
                        string code = await UserManager.GenerateChangePhoneNumberTokenAsync(user, model.Number);

                        // メッセージをSMSで送信する。
                        //   **送れなくても 500 にしない**（#294。メールと同じく記録して、間隔に数えない）。
                        try
                        {
                            await SmsSender.SendAsync(model.Number,
                                GetContentOfLetter.Get("AddPhoneNumber",
                                CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code);
                        }
                        catch (Exception ex)
                        {
                            Logging.MyOperationTrace(string.Format(
                                "The {0} SMS to {1} could not be sent. ({2})",
                                Sts.MailThrottle.PurposePhoneNumber, user.Id, ex.GetType().Name));
                            Logging.MyDebugLogForEx(ex);

                            Sts.MailThrottle.ReleaseForDestination(Sts.MailThrottle.PurposePhoneNumber, model.Number);
                        }
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
        /// <param name="password">今のパスワード（#294）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber(string password)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEditPhone && Config.EnableEditingOfUserAttribute)
            {
                // **パスワードを確かめる**（#294。2 要素認証の手段を減らす操作なので）。
                EnumManageMessageId? error = await this.VerifyPasswordAsync(user, password);
                if (error != null)
                {
                    return RedirectToAction("Index", new { Message = error });
                }

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
        /// <param name="password">今のパスワード（#294）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication(string password)
        {
            ApplicationUser user = await UserManager.GetUserAsync(User);

            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // **パスワードを確かめる**（#294。以前はセッションだけで 2FA を外せた）。
                EnumManageMessageId? error = await this.VerifyPasswordAsync(user, password);
                if (error != null)
                {
                    return RedirectToAction("Index", new { Message = error });
                }

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
        /// <remarks>
        /// **鍵は、ここでは保存しない**（#294。`LoadSharedKeyAndQrCodeUri`）。
        /// **登録済みなら、この画面は出さない**（#294）。**以前は保存済みの鍵を何度でも出していた**ので、
        /// セッションさえあれば、認証アプリと同じコードを作れるようになった。**登録し直すときは、リセットを通す。**
        /// </remarks>
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

            if (!string.IsNullOrEmpty(await UserManager.GetAuthenticatorKeyAsync(user)))
            {
                // 登録済み
                return RedirectToAction(nameof(ManageTwoFactorAuthenticator));
            }

            // QRコード生成
            ManageEnableTwoFactorAuthenticatorViewModel model
                = new ManageEnableTwoFactorAuthenticatorViewModel();

            this.LoadSharedKeyAndQrCodeUri(user, model);

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

            if (!string.IsNullOrEmpty(await UserManager.GetAuthenticatorKeyAsync(user)))
            {
                // **登録済みなら受けない**（#294。GET と同じ。登録し直すときは、リセットを通す）。
                return RedirectToAction(nameof(ManageTwoFactorAuthenticator));
            }

            if (ModelState.IsValid)
            {
                string code = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

                // トークン検証
                //   **画面に出した鍵（TempData）で確かめる。** **この利用者のために作った鍵だけ**（#294）。
                string pendingKey = this.PeekPendingAuthenticatorKey(user);

                bool is2faTokenValid = !string.IsNullOrEmpty(pendingKey)
                    && await this.VerifyPendingAuthenticatorCodeAsync(user, pendingKey, code);

                if (is2faTokenValid)
                {
                    // valid
                    // **ここで初めて鍵を保存する**（SecurityStamp も更新する。ResetAuthenticatorKeyAsync と同じ）。
                    user.TotpAuthenticatorKey = pendingKey;
                    await UserManager.UpdateSecurityStampAsync(user);
                    TempData.Remove(PendingAuthenticatorKey);

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
                    this.LoadSharedKeyAndQrCodeUri(user, model);
                    return View(model);
                }
            }
            else
            {
                // リトライ
                this.LoadSharedKeyAndQrCodeUri(user, model);
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
        /// <param name="password">今のパスワード（#294）</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetTwoFactorAuthenticator(string password)
        {
            if (!(Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute))
            {
                // エラー画面
                return View("Error");
            }

            ApplicationUser user = await UserManager.GetUserAsync(User);

            // **パスワードを確かめる**（#294。2 要素認証の手段を外す操作なので）。
            string error = await this.CheckPasswordForEditingAsync(user, password);
            if (error != null)
            {
                ModelState.AddModelError("", error);
                return View();
            }

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
        /// <param name="password">今のパスワード（#294）</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> GenerateTwoFactorAuthenticatorRecoveryCodes(string password)
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
                // **パスワードを確かめる**（#294）。
                //   **回復コードは、それだけで 2FA を通れる**ので、セッションだけでは出さない。
                string error = await this.CheckPasswordForEditingAsync(user, password);
                if (error != null)
                {
                    ModelState.AddModelError("", error);
                    return View();
                }

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
