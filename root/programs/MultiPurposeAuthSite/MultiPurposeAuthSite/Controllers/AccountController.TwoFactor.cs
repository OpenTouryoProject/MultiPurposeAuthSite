//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の 2 要素認証
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//*  2026/10/28  玄人 幸道         ブラウザ記憶の既定を外し、アカウント記憶は RememberMe で決める、2FA のサインインをログに残す（#294）
//*  2026/10/28  玄人 幸道         SendCode で選択肢を照合する（net10.0 版に揃えた。#294）
//**********************************************************************************

/*
2 要素認証（Email・SMS・MobileApp のコードの送信と検証）を担うAccountControllerの一部
（TOTP の認証アプリ・回復コードは net10.0 版だけ）
*/

using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Log;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Web.Mvc;

using Microsoft.AspNet.Identity.Owin;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 2 要素認証**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region Email, SMS, MobileApp

        #region 2FA画面のコード送信

        /// <summary>
        /// 2FA画面のコード送信画面（初期表示）
        /// GET: /Account/SendCode
        /// </summary>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            // 検証されたアカウントのUIDを取得
            string userId = await SignInManager.GetVerifiedUserIdAsync();

            if (userId == null)
            {
                // UID == null

                // エラー
                return View("Error");
            }
            else
            {
                // UID != null

                // 2FA画面のコード送信画面に遷移
                return View(await this.CreateSendCodeViewModelAsync(userId, returnUrl, rememberMe));
            }
        }

        /// <summary>
        /// 2FA画面のコード送信画面のモデルを作る（#214）
        /// </summary>
        /// <param name="userId">検証されたアカウントのUID</param>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <returns>AccountSendCodeViewModelを非同期に返す</returns>
        /// <remarks>
        /// 初期表示（GET）と、送信に失敗したときの再表示（POST）で共用する。
        /// **2 箇所で一覧の作り方が食い違わないように、1 箇所にまとめる。**
        /// </remarks>
        private async Task<AccountSendCodeViewModel> CreateSendCodeViewModelAsync(
            string userId, string returnUrl, bool rememberMe)
        {
            // UIDから、2FAのプロバイダを取得する。
            IList<string> userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);

            // 2FAのプロバイダの一覧を取得する
            List<SelectListItem> factorOptions = userFactors.Select(
                purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();

            return new AccountSendCodeViewModel
            {
                Providers = factorOptions,  // 2FAのプロバイダの一覧
                ReturnUrl = returnUrl,      // 戻り先のURL
                RememberMe = rememberMe     // アカウント記憶
            };
        }

        /// <summary>
        /// 2FA画面のコード送信画面でコード送信
        /// POST: /Account/SendCode
        /// </summary>
        /// <param name="model">SendCodeViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(AccountSendCodeViewModel model)
        {
            // AccountSendCodeViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountSendCodeViewModelの検証に成功

                // 検証されたアカウントのUIDを取得
                string userId = await SignInManager.GetVerifiedUserIdAsync();

                if (userId == null)
                {
                    // 2FA の途中ではない（GET と同じ扱い。#214）
                    return View("Error");
                }

                //  **画面に出した選択肢の中から選ばれたか**（#294）。
                //    以前は確かめず、そのまま SendTwoFactorCodeAsync に渡していた。
                AccountSendCodeViewModel offered = await this.CreateSendCodeViewModelAsync(
                    userId, model.ReturnUrl, model.RememberMe);

                if (!offered.Providers.Any(p => p.Value == model.SelectedProvider))
                {
                    ModelState.AddModelError("", Resources.AccountController.SendCodeError);
                    return View(offered);
                }

                // Generate the token and send it. トークンを生成して送信します。
                // **送信の失敗を、処理されない例外にしない**（#214）。
                //   SendTwoFactorCodeAsync の中でメール / SMS を送るため、
                //   ネットワーク障害や資格情報の誤りで例外になりうる。
                bool sent = false;

                try
                {
                    sent = await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider);
                }
                catch (Exception ex)
                {
                    // **原因は、記録に残す。** 例外を受け止めると、
                    //   これまで OnException が ACCESS ログに書いていた内容が失われるため。
                    Logging.MyDebugLogForEx(ex);
                }

                if (sent)
                {
                    // 成功

                    // 2FA画面でコードの検証用のViewへ
                    //   **ブラウザ記憶は、既定で入れない**（#294。利用者が画面で選ぶ）。
                    //   以前は常に true を渡していたので、既定のままだと、そのブラウザでは次から 2FA を飛ばしていた。
                    return RedirectToAction("VerifyCode", new
                    {
                        Provider = model.SelectedProvider,  // 2FAプロバイダ
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                        RememberBrowser = false             // ブラウザ記憶(2FA)
                    });
                }
                else
                {
                    // 失敗（送信できなかったことを画面で伝え、別の送信先を選び直せるようにする）
                    ModelState.AddModelError("", Resources.AccountController.SendCodeError);
                }
            }
            else
            {
                // AccountSendCodeViewModelの検証に失敗
            }

            // 再表示
            // **モデルを渡さないとビューが落ちる**（Model.ReturnUrl などを読むため）（#214）。
            string currentUserId = await SignInManager.GetVerifiedUserIdAsync();

            if (currentUserId == null)
            {
                // 2FA の途中ではない
                return View("Error");
            }

            return View(await this.CreateSendCodeViewModelAsync(
                currentUserId, model.ReturnUrl, model.RememberMe));
        }

        #endregion

        #region 2FA画面のコード検証

        /// <summary>
        /// 2FA画面のコード検証（初期表示）
        /// GET: /Account/VerifyCode
        /// </summary>
        /// <param name="provider">2FAプロバイダ</param>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <param name="rememberBrowser">ブラウザ記憶(2FA)</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe, bool rememberBrowser)
        {
            // Require that the user has already logged in via username/password or external login
            // ユーザーが既にユーザ名/パスワードまたは外部ログイン経由でログイン済みであることが必要。
            bool hasBeenVerified = await SignInManager.HasBeenVerifiedAsync();

            if (!hasBeenVerified)
            {
                // エラー画面
                return View("Error");
            }
            else
            {
                // 2FA画面のコード検証（初期表示）
                return View(
                    new AccountVerifyCodeViewModel
                    {
                        Provider = provider,                    // 2FAプロバイダ
                        ReturnUrl = returnUrl,                  // 戻り先のURL
                        RememberMe = rememberMe,                // アカウント記憶
                        RememberBrowser = rememberBrowser       // ブラウザ記憶(2FA)
                    });
            }
        }

        /// <summary>
        /// 2FA画面のコード検証
        /// POST: /Account/VerifyCode
        /// </summary>
        /// <param name="model">VerifyCodeViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(AccountVerifyCodeViewModel model)
        {
            // AccountVerifyCodeViewModelの検証
            if (ModelState.IsValid)
            {
                // AccountVerifyCodeViewModelの検証に成功

                // The following code protects for brute force attacks against the two factor codes. 
                // If a user enters incorrect codes for a specified amount of time then the user account will be locked out for a specified amount of time. 
                // You can configure the account lockout settings in IdentityConfig( = ApplicationSignInManager, ApplicationUserManager, SmsService, EmailService)

                // 次のコードは、2FAコードに対するブルートフォース攻撃から保護します。
                // 指定時間の間にコード入力の誤りが指定の回数に達すると、アカウントは、指定時間の間ロックアウトされる。
                // IdentityConfig.cs(ApplicationUserManager.Create)でアカウントロックアウトの設定を行うことができる。
                //   **ログに残すため、サインインの前に 2FA の途中の利用者を引いておく**（#294。後では User から引けない）。
                string userId = await SignInManager.GetVerifiedUserIdAsync();

                SignInStatus result = await SignInManager.TwoFactorSignInAsync(
                    provider: model.Provider,                                  // 2FAプロバイダ
                    code: model.Code,                                          // 2FAコ－ド
                    isPersistent: model.RememberMe,                            // アカウント記憶（#294。以前は RememberBrowser を使っていた）
                    rememberBrowser: model.RememberBrowser                     // ブラウザ記憶(2FA)
                    );

                // SignInStatus
                switch (result)
                {
                    case SignInStatus.Success:
                        // サインイン成功

                        // セッションの初期化
                        this.InitSessionAfterlogin();

                        // オペレーション・トレース・ログ出力
                        await this.LogTwoFactorSignInAsync(userId);

                        return RedirectToLocal(model.ReturnUrl);

                    case SignInStatus.LockedOut:
                        // ロックアウト
                        return View("Lockout");

                    case SignInStatus.Failure:
                    // サインイン失敗
                    default:
                        // その他
                        // "無効なコード。"
                        ModelState.AddModelError("", Resources.AccountController.InvalidCode);
                        break;
                }
            }
            else
            {
                // VerifyCodeViewModelの検証に失敗
            }

            // 再表示
            return View(model);
        }

        /// <summary>
        /// 2FAのプッシュ承認の状態を返す（#216）
        /// GET: /Account/TwoFactorPushStatus
        /// </summary>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <param name="rememberBrowser">ブラウザ記憶(2FA)</param>
        /// <returns>
        /// 承認済みなら { "approved": true, "redirectUrl": "..." }、まだなら { "approved": false }
        /// </returns>
        /// <remarks>
        /// **待っているのはブラウザである。**
        /// 認証デバイスは `/2fa_result` に承認を送るだけで、サインインは完了できない
        /// （2FA のセッションはブラウザの Cookie にあり、端末からは触れない）。
        /// そこで、コードの入力画面（VerifyCode）からこの口をポーリングし、
        /// 承認されていれば、そのコードでサインインを完了させる。
        ///
        /// 承認は 1 回取り出すと消える（TwoFactorPushProvider.Receive）。
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> TwoFactorPushStatus(string returnUrl, bool rememberMe, bool rememberBrowser)
        {
            // 2FA のセッション（Cookie）から利用者を取る
            string userId = await SignInManager.GetVerifiedUserIdAsync();

            if (userId == null)
            {
                // 2FA の途中ではない
                return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
            }

            // 認証デバイスからの承認（無ければ null）
            string code = Sts.TwoFactorPushProvider.Receive(userId);

            if (string.IsNullOrEmpty(code))
            {
                // まだ承認されていない
                return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
            }

            // 承認されたコードでサインインを完了させる。
            // **検証は、画面から入力された場合と同じ経路を通る**（プロバイダも同じ）。
            SignInStatus result = await SignInManager.TwoFactorSignInAsync(
                provider: MobileAppTokenProvider.ProviderName,   // 2FAプロバイダ
                code: code,                                     // 2FAコ－ド
                isPersistent: rememberMe,                       // アカウント記憶（#294。以前は rememberBrowser を使っていた）
                rememberBrowser: rememberBrowser                // ブラウザ記憶(2FA)
                );

            if (result == SignInStatus.Success)
            {
                // セッションの初期化
                this.InitSessionAfterlogin();

                // オペレーション・トレース・ログ出力
                await this.LogTwoFactorSignInAsync(userId);

                return Json(new
                {
                    approved = true,
                    // **戻り先は、ローカルかを確かめてから返す**（RedirectToLocal と同じ判定）。
                    //   外部のサイトへ誘導されないようにする。
                    redirectUrl = this.Url.IsLocalUrl(returnUrl)
                        ? returnUrl : this.Url.Action("Index", "Home")
                }, JsonRequestBehavior.AllowGet);
            }

            // 承認はあったが、サインインは成立しなかった（コードの期限切れ、ロックアウトなど）。
            // 画面は、そのまま手入力での完了を続けられる。
            return Json(new { approved = false }, JsonRequestBehavior.AllowGet);
        }

        /// <summary>2FA でサインインしたことをログに残す（#294）</summary>
        /// <param name="userId">サインインの前に引いた、2FA の途中の利用者の id</param>
        /// <returns>Task</returns>
        private async Task LogTwoFactorSignInAsync(string userId)
        {
            ApplicationUser user = string.IsNullOrEmpty(userId) ? null : await UserManager.FindByIdAsync(userId);

            if (user != null)
                Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with 2FA.", user.Id, user.UserName));
        }

        #endregion

        #endregion
    }
}
