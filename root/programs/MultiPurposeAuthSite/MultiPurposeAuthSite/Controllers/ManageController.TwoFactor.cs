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
//*  2026/10/29  玄人 幸道         SMS を続けて送らない（#294）
//*  2026/10/30  玄人 幸道         2FA の無効化・電話番号の削除でパスワードを確かめる・SMS の間隔を電話番号ごとに・
//*                                SMS の失敗で 500 にしない（#294）
//*  2026/10/30  玄人 幸道         電話番号の追加でパスワードを確かめる（#294）
//*  2026/10/30  玄人 幸道         電話番号の追加で、送ると決めてから検証コードを作る（net10.0 版に揃えた。#294）
//**********************************************************************************

/*
電話番号の登録・検証・削除、2 要素認証の有効化・無効化を担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Threading.Tasks;

using System.Web.Mvc;

using Microsoft.AspNet.Identity;

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
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddPhoneNumberViewModelの検証に成功

                    // **パスワードを確かめる**（#294。2 要素認証の手段を足す操作なので）。
                    //   **検証コードは、ここを通った後でしか作らない**（`VerifyPhoneNumber` は、そのコードが無いと通らない）。
                    string error = await this.CheckPasswordForEditingAsync(
                        await UserManager.FindByIdAsync(User.Identity.GetUserId()), password);
                    if (error != null)
                    {
                        ModelState.AddModelError("", error);
                        return View(model);
                    }

                    // メッセージをSMSで送信する。
                    //   **同じ電話番号に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）。
                    //   **電話番号ごとに数える** — 打ち間違いを直した番号へは、すぐに送れる。
                    if (UserManager.SmsService != null
                        && MailThrottle.TryAcquireForDestination(
                            MailThrottle.PurposePhoneNumber, model.Number, User.Identity.GetUserId()))
                    {
                        // 検証コード生成
                        //   **送ると決めてから作る**（#294。net10.0 版と同じ。以前は送らないときも作っていた）。
                        string code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), model.Number);

                        IdentityMessage message = new IdentityMessage
                        {
                            Destination = model.Number,
                            Body = GetContentOfLetter.Get(
                                "AddPhoneNumber", CustomEncode.UTF_8, Resources.ManageController.CodeForAddPhoneNumber) + code
                        };

                        //   **送れなくても 500 にしない**（#294。メールと同じく記録して、間隔に数えない）。
                        try
                        {
                            await UserManager.SmsService.SendAsync(message);
                        }
                        catch (Exception ex)
                        {
                            Logging.MyOperationTrace(string.Format(
                                "The {0} SMS to {1} could not be sent. ({2})",
                                MailThrottle.PurposePhoneNumber, User.Identity.GetUserId(), ex.GetType().Name));
                            Logging.MyDebugLogForEx(ex);

                            MailThrottle.ReleaseForDestination(MailThrottle.PurposePhoneNumber, model.Number);
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
            if (Config.CanEditPhone
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageVerifyPhoneNumberViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageVerifyPhoneNumberViewModelの検証に成功

                    // 電話番号の検証（電話番号の登録の際に、SMSで送信した検証コードを検証）
                    IdentityResult result = await UserManager.ChangePhoneNumberAsync(
                        User.Identity.GetUserId(), model.PhoneNumber, model.Code);

                    // 電話番号の検証結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

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
            if (Config.CanEditPhone && Config.EnableEditingOfUserAttribute)
            {
                // **パスワードを確かめる**（#294。2 要素認証の手段を減らす操作なので）。
                EnumManageMessageId? error = await this.VerifyPasswordAsync(
                    await UserManager.FindByIdAsync(User.Identity.GetUserId()), password);
                if (error != null)
                {
                    return RedirectToAction("Index", new { Message = error });
                }

                // null クリア
                IdentityResult result = await UserManager.SetPhoneNumberAsync(User.Identity.GetUserId(), "");

                // 結果の確認
                if (result.Succeeded)
                {
                    // 電話番号削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
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
            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // 2FAの有効化
                await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), true);

                // 再ログイン
                await this.ReSignInAsync();

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
            if (Config.CanEdit2FA
                && Config.EnableEditingOfUserAttribute)
            {
                // **パスワードを確かめる**（#294。以前はセッションだけで 2FA を外せた）。
                EnumManageMessageId? error = await this.VerifyPasswordAsync(
                    await UserManager.FindByIdAsync(User.Identity.GetUserId()), password);
                if (error != null)
                {
                    return RedirectToAction("Index", new { Message = error });
                }

                // 2FAの無効化
                await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), false);

                // 再ログイン
                await this.ReSignInAsync();

                return RedirectToAction("Index", "Manage");
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
