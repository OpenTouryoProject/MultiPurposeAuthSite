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
//*  2026/10/28  玄人 幸道         TOTP・回復コードでセッションを初期化、コードの誤りの文言、ロックアウトの画面、
//*                                戻り先の保持、選択肢の照合、ブラウザ記憶の既定を直した（#294）
//**********************************************************************************

/*
2 要素認証（Email・SMS・MobileApp のコードの送信と検証、
TOTP の認証アプリ・回復コード）を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using AspNetId = Microsoft.AspNetCore.Identity;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 2 要素認証**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region Email, SMS, MobileApp

        #region 送る手段の名前

        /// <summary>Email（トークンの生成と検証も、この名前に固定する）</summary>
        private const string _2FA_Email = "Email";

        /// <summary>SMS</summary>
        private const string _2FA_SMS = "Phone";

        /// <summary>認証デバイスへのプッシュ通知</summary>
        private const string _2FA_MobileApp = "MobileApp";

        #endregion

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
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                // user == null

                // エラー
                return View("Error");
            }
            else
            {
                // user != null

                // 2FA画面のコード送信画面に遷移
                return View(await this.CreateSendCodeViewModelAsync(user, returnUrl, rememberMe));
            }
        }

        /// <summary>
        /// 2FA画面のコード送信画面のモデルを作る（#214）
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="returnUrl">戻り先のURL</param>
        /// <param name="rememberMe">アカウント記憶</param>
        /// <returns>AccountSendCodeViewModelを非同期に返す</returns>
        /// <remarks>
        /// 初期表示（GET）と、送信に失敗したときの再表示（POST）で共用する。
        /// **2 箇所で一覧の作り方が食い違わないように、1 箇所にまとめる。**
        /// </remarks>
        private async Task<AccountSendCodeViewModel> CreateSendCodeViewModelAsync(
            ApplicationUser user, string returnUrl, bool rememberMe)
        {
            // UIDから、2FAのプロバイダを取得する。
            IList<string> userFactors = await UserManager.GetValidTwoFactorProvidersAsync(user);

            // 2FAのプロバイダの一覧を取得する
            List<SelectListItem> factorOptions = userFactors.Select(
                purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();

            #region 2FAのラインナップに追加
            // プッシュ通知
            if (user.DeviceToken != null)
            {
                factorOptions.Add(new SelectListItem {
                    Text = _2FA_MobileApp,
                    Value = _2FA_MobileApp });
            }
            // , etc.
            #endregion

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
                ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                if (user == null)
                {
                    // 2FA の途中ではない（GET と同じ扱い。#214）
                    return View("Error");
                }

                //  **画面に出した選択肢の中から選ばれたか**（#294）。
                //    以前は確かめず、知らない値は「TOTP」として扱っていた
                //    （認証アプリを登録していない利用者も、TOTP の画面へ送られた）。
                AccountSendCodeViewModel offered = await this.CreateSendCodeViewModelAsync(
                    user, model.ReturnUrl, model.RememberMe);

                if (!offered.Providers.Any(p => p.Value == model.SelectedProvider))
                {
                    ModelState.AddModelError("", Resources.AccountController.SendCodeError);
                    return View(offered);
                }

                //  **TOTP（認証アプリ）はコードを送らない**ので、そのまま入力画面へ。
                if (model.SelectedProvider == UserManager.Options.Tokens.AuthenticatorTokenProvider)
                {
                    return RedirectToAction("LoginWithTwoFactorAuthenticator", new
                    {
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                    });
                }

                // **送信の失敗を、処理されない例外にしない**（#214）。
                //   ネットワーク障害、資格情報の期限切れ、宛先の拒否などで失敗する。
                //   **処理されない例外にすると、原因の分からないエラー画面になる。**
                string code = null;

                try
                {
                    // Generate the token and send it. トークンを生成して送信します。
                    // SelectedProviderではなく、Emailに固定（MobileAppだとエラーになる。
                    code = await UserManager.GenerateTwoFactorTokenAsync(user, _2FA_Email); //model.SelectedProvider);

                    // Identity2.0 では、GenerateTwoFactorTokenAsyncの中で
                    // 自動送信されていたが3.0では手動送信に変更された模様。
                    if (model.SelectedProvider == _2FA_Email)
                    {
                        // Email
                        await EmailSender.SendAsync(user.Email, "Two factor authentication code", code);
                    }
                    else if (model.SelectedProvider == _2FA_SMS)
                    {
                        // SMS
                        await SmsSender.SendAsync(user.PhoneNumber, code);
                    }
                    else if (model.SelectedProvider == _2FA_MobileApp)
                    {
                        // MobileApp
                        await FcmService.GetInstance().SendAsync(
                            user.DeviceToken, "2FA", "Two factor authentication",
                            new Dictionary<string, string>()
                            {
                                { "code", code}
                            });
                    }
                }
                catch (Exception ex)
                {
                    // **原因は、記録に残す。** 例外を受け止めると、
                    //   これまで OnException が ACCESS ログに書いていた内容が失われるため。
                    Logging.MyDebugLogForEx(ex);

                    // 送信できなかったことを画面で伝え、別の送信先を選び直せるようにする。
                    ModelState.AddModelError("", Resources.AccountController.SendCodeError);

                    return View(await this.CreateSendCodeViewModelAsync(
                        user, model.ReturnUrl, model.RememberMe));
                }

                // Email, SMS, MobileApp
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
                // AccountSendCodeViewModelの検証に失敗
            }

            // 再表示
            // **モデルを渡さないとビューが落ちる**（Model.ReturnUrl などを読むため）（#214）。
            ApplicationUser currentUser = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (currentUser == null)
            {
                // 2FA の途中ではない
                return View("Error");
            }

            return View(await this.CreateSendCodeViewModelAsync(
                currentUser, model.ReturnUrl, model.RememberMe));
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
            // 検証されたアカウントのUIDを取得
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
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
                ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                AspNetId.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                        provider: _2FA_Email, // model.Provider,                   // 2FAプロバイダ (固定
                        code: model.Code,                                          // 2FAコ－ド
                        isPersistent: model.RememberMe,                            // アカウント記憶（#294。以前は RememberBrowser を使っていた）
                        rememberClient: model.RememberBrowser                      // ブラウザ記憶 (2FA)
                    );

                // SignInStatus
                if (result.Succeeded)
                {
                    // サインイン成功

                    // セッションの初期化
                    this.InitSessionAfterlogin();

                    // オペレーション・トレース・ログ出力
                    if (user != null)
                        Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with 2FA.", user.Id, user.UserName));

                    return RedirectToLocal(model.ReturnUrl);
                }
                else if (result.IsLockedOut)
                {
                    // ロックアウト
                    return View("Lockout");
                }
                else
                {
                    // サインイン失敗 or その他 "無効なコード。"
                    //   **コードの誤りは Failed で返る**（#294。以前は IsNotAllowed だけを見ていたので、文言が出なかった）。
                    ModelState.AddModelError("", Resources.AccountController.InvalidCode);
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
        /// 2FAのプッシュ承認の状態を返す（#213）
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
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                // 2FA の途中ではない
                return this.Json(new { approved = false });
            }

            // 認証デバイスからの承認（無ければ null）
            string code = TwoFactorPushProvider.Receive(user.Id);

            if (string.IsNullOrEmpty(code))
            {
                // まだ承認されていない
                return this.Json(new { approved = false });
            }

            // 承認されたコードでサインインを完了させる。
            // **検証は、画面から入力された場合と同じ経路を通る**（プロバイダも同じく Email 固定）。
            AspNetId.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                    provider: _2FA_Email,
                    code: code,
                    isPersistent: rememberMe,           // アカウント記憶（#294。以前は rememberBrowser を使っていた）
                    rememberClient: rememberBrowser
                );

            if (result.Succeeded)
            {
                // セッションの初期化
                this.InitSessionAfterlogin();

                // オペレーション・トレース・ログ出力
                Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with 2FA.", user.Id, user.UserName));

                return this.Json(new
                {
                    approved = true,
                    // **戻り先は、ローカルかを確かめてから返す**（RedirectToLocal と同じ判定）。
                    //   外部のサイトへ誘導されないようにする。
                    redirectUrl = this.Url.IsLocalUrl(returnUrl)
                        ? returnUrl : this.Url.Action(nameof(HomeController.Index), "Home")
                });
            }

            // 承認はあったが、サインインは成立しなかった（コードの期限切れ、ロックアウトなど）。
            // 画面は、そのまま手入力での完了を続けられる。
            return this.Json(new { approved = false });
        }

        #endregion

        #endregion

        #region TOTP

        /// <summary>TOTP・回復コードでサインインできたときの後始末（#294）</summary>
        /// <param name="user">2FA の途中の利用者（サインインの前に引いたもの）</param>
        /// <param name="how">ログに書く手段</param>
        /// <remarks>
        /// **パスワード・コードの 2FA・プッシュ承認と同じく、セッションを初期化する。**
        /// 以前は TOTP の 2 か所だけ呼んでいなかったので、
        /// **セッション ID が切り替わらず、`auth_time` と OP のセッション（#310 の `sid`）の Cookie も書かれなかった。**
        /// </remarks>
        private void AfterTwoFactorAuthenticatorSignIn(ApplicationUser user, string how)
        {
            // セッションの初期化
            this.InitSessionAfterlogin();

            // オペレーション・トレース・ログ出力
            Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with {2}.", user.Id, user.UserName, how));
        }

        #region With authenticator

        /// <summary>LoginWithTwoFactorAuthenticator</summary>
        /// <param name="rememberMe">bool</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> LoginWithTwoFactorAuthenticator(bool rememberMe, string returnUrl = null)
        {
            //  **パスワードを通った後（2FA の途中）でなければ、開かない**（#294。SendCode / VerifyCode と同じ）。
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                return View("Error");
            }

            AccountLoginWithTwoFactorAuthenticatorViewModel model
                = new AccountLoginWithTwoFactorAuthenticatorViewModel { RememberMe = rememberMe };

            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        /// <summary>LoginWithTwoFactorAuthenticator</summary>
        /// <param name="model">AccountLoginWithTwoFactorAuthenticatorViewModel</param>
        /// <param name="rememberMe">bool</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> LoginWithTwoFactorAuthenticator(
            AccountLoginWithTwoFactorAuthenticatorViewModel model,
            bool rememberMe, string returnUrl = null)
        {
            //  **再表示でも戻り先を失わない**（#294。フォームは ViewData["ReturnUrl"] から組み立てる）。
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                //  **パスワードを通った後（2FA の途中）でなければ、受けない。**
                //    **ログに残すため、サインインの前に引いておく**（後では User から引けない）。
                ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                if (user == null)
                {
                    return View("Error");
                }

                AspNetId.SignInResult result
                    = await SignInManager.TwoFactorAuthenticatorSignInAsync(
                        model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty),
                        rememberMe, model.RememberMachine);

                if (result.Succeeded)
                {
                    this.AfterTwoFactorAuthenticatorSignIn(user, "an authenticator app");
                    return RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    // ロックアウト（#294。Lockout はアクションではなく画面なので、View で返す）
                    return View("Lockout");
                }
                else
                {
                    // "無効なコード。"
                    ModelState.AddModelError(string.Empty, Resources.AccountController.InvalidCode);
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }

        #endregion

        #region With recovery code

        /// <summary>LoginWithTwoFactorAuthenticatorRecoveryCode</summary>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> LoginWithTwoFactorAuthenticatorRecoveryCode(string returnUrl = null)
        {
            //  **パスワードを通った後（2FA の途中）でなければ、開かない**（#294）。
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>LoginWithTwoFactorAuthenticatorRecoveryCode</summary>
        /// <param name="model">AccountLoginWithTwoFactorAuthenticatorRecoveryCodeViewModel</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithTwoFactorAuthenticatorRecoveryCode(
            AccountLoginWithTwoFactorAuthenticatorRecoveryCodeViewModel model, string returnUrl = null)
        {
            //  **再表示でも戻り先を失わない**（#294）。
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                //  **パスワードを通った後（2FA の途中）でなければ、受けない。**
                ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                if (user == null)
                {
                    return View("Error");
                }

                AspNetId.SignInResult result
                    = await SignInManager.TwoFactorRecoveryCodeSignInAsync(
                        model.RecoveryCode.Replace(" ", string.Empty));

                if (result.Succeeded)
                {
                    this.AfterTwoFactorAuthenticatorSignIn(user, "a recovery code");
                    return RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    // ロックアウト（#294。Lockout はアクションではなく画面なので、View で返す）
                    return View("Lockout");
                }
                else
                {
                    // "無効なコード。"
                    ModelState.AddModelError(string.Empty, Resources.AccountController.InvalidCode);
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }

        #endregion

        #endregion
    }
}
