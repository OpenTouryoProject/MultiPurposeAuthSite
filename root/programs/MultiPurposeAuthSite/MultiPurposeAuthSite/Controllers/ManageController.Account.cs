//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController の利用者名・パスワード・メアド
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         パスワードの確認をサインインから切り離した・
//*                                メアドの変更の判定をメアドで行う（#294）
//**********************************************************************************

/*
利用者名の変更、パスワードの設定・変更、
メアドの変更・検証を担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;

using System;
using System.Threading.Tasks;

using System.Web.Mvc;

using Microsoft.AspNet.Identity;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController の利用者名・パスワード・メアド**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region UserName

        /// <summary>
        /// UserNameの編集画面
        /// GET: /Manage/ChangeUserName
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ChangeUserName()
        {
            // **利用者名の編集は、常に出せる**（#151 の段階 3）。
            //   以前は「利用者名＝メアド」の配備では出せなかった（メアドの編集で兼ねていた）。
            if (Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                return View(new ManageChangeUserNameViewModel { UserNameForEdit = user.UserName });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// UserNameの編集画面
        /// POST: /Manage/ChangeUserName
        /// </summary>
        /// <param name="model">ManageChangeUserNameViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangeUserName(ManageChangeUserNameViewModel model)
        {
            ApplicationUser user = null;

            // **利用者名の編集は、常に出せる**（#151 の段階 3）。
            //   以前は「利用者名＝メアド」の配備では出せなかった（メアドの編集で兼ねていた）。
            if (Config.AllowEditingUserName
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageChangeUserNameViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageChangeUserNameViewModelの検証に成功

                    // ユーザの取得
                    user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック（サインインはしない。#294）
                        string error = await this.CheckPasswordForEditingAsync(user, model.Password);

                        if (error != null)
                        {
                            // Passwordが一致しない。
                            // 再表示
                            ModelState.AddModelError("", error);
                            return View(model);
                        }
                    }
                    else
                    {
                        // ノーチェック
                        // 処理を継続
                    }

                    string oldUserName = user.UserName;

                    // UserNameの更新
                    user.UserName = model.UserNameForEdit;
                    IdentityResult result = await UserManager.UpdateAsync(user);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 再ログイン
                        if (await this.ReSignInAsync())
                        {
                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) has changed own user name to {2}.", user.Id, oldUserName, user.UserName));

                            // 再ログインに成功
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeUserNameSuccess });
                        }
                        else
                        {
                            // 再ログインに失敗
                        }
                    }
                    else
                    {
                        // E-mail更新に失敗
                    }

                    return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeUserNameFailure });
                }
                else
                {
                    // ManageChangeUserNameViewModelの検証に失敗
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

        #region Password

        #region Create

        /// <summary>
        /// パスワード設定画面（初期表示）
        /// GET: /Manage/SetPassword
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult SetPassword()
        {
            if (Config.EnableEditingOfUserAttribute)
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
        /// パスワード設定画面（パスワード設定）
        /// POST: /Manage/SetPassword
        /// </summary>
        /// <param name="model">ManageSetPasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(ManageSetPasswordViewModel model)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // ManageSetPasswordViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageSetPasswordViewModelの検証に成功
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    // パスワード設定
                    IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

                    // 結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has set own local password.", user.Id, user.UserName));

                        // Index - SetPasswordSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.SetPasswordSuccess });
                    }
                    else
                    {
                        // 失敗
                        this.AddErrors(result);
                    }
                }
                else
                {
                    // ManageSetPasswordViewModelの検証に失敗
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

        #region Update

        /// <summary>
        /// パスワード変更画面（初期表示）
        /// GET: /Manage/ChangePassword
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult ChangePassword()
        {
            if (Config.EnableEditingOfUserAttribute)
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
        /// パスワード変更画面（パスワード変更）
        /// POST: /Manage/ChangePassword
        /// </summary>
        /// <param name="model">ManageChangePasswordViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ManageChangePasswordViewModel model)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // ManageChangePasswordViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageChangePasswordViewModelの検証に成功
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    // パスワード変更
                    IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);

                    // パスワードの変更結果の確認
                    if (result.Succeeded)
                    {
                        // 成功

                        // 再ログイン
                        await this.ReSignInAsync();

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format("{0}({1}) has changed own password.", user.Id, user.UserName));

                        // Index - ChangePasswordSuccess
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        // 失敗
                        this.AddErrors(result);
                    }
                }
                else
                {
                    // ManageChangePasswordViewModelの検証に失敗
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

        #region E-mail

        #region Update (Edit/Change)

        /// <summary>
        /// E-mailの編集画面（初期表示）
        /// GET: /Manage/ChangeEmail
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> ChangeEmail()
        {
            // **メアドの編集は CanEditEmail が持つ**（#151 の段階 3）。
            //   以前は AllowEditingUserName で出し分けていた（メアド＝利用者名だったため）。
            if (Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                return View(new ManageEmailViewModel { Email = user.Email });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// E-mailの編集画面（E-mailの編集）
        /// POST: /Manage/ChangeEmail
        /// </summary>
        /// <param name="model">ManageEmailViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangeEmail(ManageEmailViewModel model)
        {
            // **メアドの編集は CanEditEmail が持つ**（#151 の段階 3）。
            //   以前は AllowEditingUserName で出し分けていた（メアド＝利用者名だったため）。
            if (Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageEmailViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageEmailViewModelの検証に成功

                    // 先ず、ユーザを取得しておく。
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    // Passwordチェック
                    if (Config.RequirePasswordInEditingUserNameAndEmail)
                    {
                        // パスワードのチェック（サインインはしない。#294）
                        string error = await this.CheckPasswordForEditingAsync(user, model.Password);

                        if (error != null)
                        {
                            // Passwordが一致しない。
                            // 再表示
                            ModelState.AddModelError("", error);
                            return View(model);
                        }
                    }
                    else
                    {
                        // ノーチェック
                        // 処理を継続
                    }

                    // **いまのメアドと比べる**（#294）。
                    //   **以前は利用者名と比べていた**（「利用者名＝メアド」だった頃の名残。#151）。
                    if (!string.Equals(user.Email, model.Email, StringComparison.OrdinalIgnoreCase))
                    {
                        // メアドが更新された場合。

                        // 既存のメアドかどうかのチェック
                        ApplicationUser anotherUser = await UserManager.FindByEmailAsync(model.Email);

                        if (anotherUser == null)
                        {
                            // 既存のメアドでない場合。

                            // 確認メールの送信（確認の符号の保存も、ここで行う）
                            this.SendConfirmEmail(user, model.Email);
                        }
                        else
                        {
                            // 既存のメアドの場合。
                            //   **送らずに、送った場合と同じ画面を出す**（#294）。
                            //   **他の利用者のメアドかどうかを、画面から分からせない。**
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) requested an e-mail address that is already in use.", user.Id, user.UserName));
                        }

                        // 表示
                        return View("VerifyEmailAddress");
                    }
                    else
                    {
                        // メアドが更新されていない場合。
                        ModelState.AddModelError("", Resources.ManageController.EmailNotChanged);
                    }
                }
                else
                {
                    // ManageEmailViewModelの検証に失敗
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

        #region メアド検証

        /// <summary>
        /// メアド検証画面（メールからのリンクで結果表示）
        /// GET: /Manage/EmailConfirmation
        /// </summary>
        /// <param name="userId">string</param>
        /// <param name="code">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> EmailConfirmation(string userId, string code)
        {
        	// ユーザの取得
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (Config.CanEditEmail
                && Config.EnableEditingOfUserAttribute)
            {
                // 入力の検証 1
                if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
                {
                    // ・・・
                }
                else
                {
                    // 入力の検証 2
                    if (User.Identity.GetUserId() == userId)
                    {
                        string email = CustomizedConfirmationProvider.GetInstance()
                            .CheckCustomizedConfirmationData(userId, code, out bool isExpired);

                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            // **メアドを変えても、利用者名は変えない**（#151 の段階 3）。
                            //   以前は「利用者名＝メアド」だったので、両方を書き換えていた。
                            string oldUserName = user.UserName;
                            user.Email = email;

                            // 場合によっては、Email & UserName を更新するため。
                            //IdentityResult result = await UserManager.SetEmailAsync(User.Identity.GetUserId(), (string)Session["Email"]);
                            IdentityResult result = await UserManager.UpdateAsync(user);

                            // 結果の確認
                            if (result.Succeeded)
                            {
                                // メアド検証の成功

                                // 再ログイン
                                if (await this.ReSignInAsync())
                                {
                                    // 再ログインに成功
                                    // メールの送信
                                    this.SendChangeCompletedEmail(user);

                                    // オペレーション・トレース・ログ出力
                                    //   **利用者名ではなくメアドが変わった**ので、新しいメアドを出す（#151 の段階 3）。
                                    Logging.MyOperationTrace(string.Format(
                                        "{0}({1}) has changed own e-mail address to {2}.", user.Id, oldUserName, user.Email));
                                    return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeEmailSuccess });
                                }
                                else
                                {
                                    // 再ログインに失敗
                                }
                            }
                            else
                            {
                                // E-mail更新に失敗
                                return RedirectToAction("Index", new { Message = EnumManageMessageId.ChangeEmailFailure });
                            }
                        }
                        else
                        {
                            if (isExpired)
                            {
                                // 有効期限切れ
                            }
                            else
                            {
                                // 使用済みリンク
                            }
                        }
                    }
                }
            }

            // エラー画面
            return View("Error");
        }

        #endregion

        #endregion
    }
}
