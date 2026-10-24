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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using Token = MultiPurposeAuthSite.TokenProviders;
using Saml = MultiPurposeAuthSite.SamlProviders;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;
using Stj = System.Text.Json;

using System.Web;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using AspNetId = Microsoft.AspNetCore.Identity;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 2 要素認証**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region Action Method

        #region IdP (Identity Provider)

        #region 2 要素認証 (2FA :2 factor authentication)

        #region Email, SMS, MobileApp

        #region 
        /// <summary>プッシュ通知</summary>
        private string _2FA_Email = "Email";
        private string _2FA_SMS = "Phone";
        private string _2FA_MobileApp = "MobileApp";
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
                    Text = this._2FA_MobileApp,
                    Value = this._2FA_MobileApp });
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
        // 
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

                // **送信の失敗を、処理されない例外にしない**（#214）。
                //   ネットワーク障害、資格情報の期限切れ、宛先の拒否などで失敗する。
                //   以前は例外がそのまま出て、原因の分からないエラー画面になっていた。
                string code = null;

                try
                {
                    // Generate the token and send it. トークンを生成して送信します。
                    // SelectedProviderではなく、Emailに固定（MobileAppだとエラーになる。
                    code = await UserManager.GenerateTwoFactorTokenAsync(user, this._2FA_Email); //model.SelectedProvider);

                    // Identity2.0 では、GenerateTwoFactorTokenAsyncの中で
                    // 自動送信されていたが3.0では手動送信に変更された模様。
                    if (model.SelectedProvider == this._2FA_Email)
                    {
                        // Email
                        await EmailSender.SendAsync(user.Email, "Two factor authentication code", code);
                    }
                    else if (model.SelectedProvider == this._2FA_SMS)
                    {
                        // SMS
                        await SmsSender.SendAsync(user.PhoneNumber, code);
                    }
                    else if (model.SelectedProvider == this._2FA_MobileApp)
                    {
                        // MobileApp
                        await FcmService.GetInstance().SendAsync(
                            user.DeviceToken, "2FA", "Two factor authentication",
                            new Dictionary<string, string>()
                            {
                                { "code", code}
                            });
                    }
                    else
                    {
                        // TOTP authenticator
                        code = "";
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

                if (!string.IsNullOrEmpty(code))
                {
                    // Email or SMS
                    // 2FA画面でコードの検証用のViewへ
                    return RedirectToAction("VerifyCode", new
                    {
                        Provider = model.SelectedProvider,  // 2FAプロバイダ
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                        RememberBrowser = true              // ブラウザ記憶(2FA)
                    });
                }
                else
                {
                    // TOTP authenticator
                    return RedirectToAction("LoginWithTwoFactorAuthenticator", new
                    {
                        ReturnUrl = model.ReturnUrl,        // 戻り先のURL
                        RememberMe = model.RememberMe,      // アカウント記憶
                    });
                }
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
                AspNetId.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                        provider: this._2FA_Email, // model.Provider,              // 2FAプロバイダ (固定
                        code: model.Code,                                          // 2FAコ－ド
                        isPersistent: model.RememberBrowser, // model.RememberMe,  // アカウント記憶 ( ・・・仕様として解り難いので、RememberBrowserを使用 )
                        rememberClient: model.RememberBrowser                      // ブラウザ記憶 (2FA)
                    );

                // SignInStatus
                if (result.Succeeded)
                {
                    // サインイン成功

                    // セッションの初期化
                    this.InitSessionAfterlogin();

                    //// オペレーション・トレース・ログ出力 できない（User.Identity.GetUserId() == null
                    //ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    //Logging.MyOperationTrace(string.Format("{0}({1}) did 2fa sign in.", user.Id, user.UserName));

                    return RedirectToLocal(model.ReturnUrl);
                }
                else if (result.IsLockedOut)
                {
                    // ロックアウト
                    return View("Lockout");
                }
                else if (result.IsNotAllowed)
                {
                    // サインイン失敗
                    // その他 "無効なコード。"
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
        public async Task<ActionResult> TwoFactorPushStatus(string returnUrl, bool rememberBrowser)
        {
            // 2FA のセッション（Cookie）から利用者を取る
            ApplicationUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                // 2FA の途中ではない
                return this.Json(new { approved = false });
            }

            // 認証デバイスからの承認（無ければ null）
            string code = Sts.TwoFactorPushProvider.Receive(user.Id);

            if (string.IsNullOrEmpty(code))
            {
                // まだ承認されていない
                return this.Json(new { approved = false });
            }

            // 承認されたコードでサインインを完了させる。
            // **検証は、画面から入力された場合と同じ経路を通る**（プロバイダも同じく Email 固定）。
            AspNetId.SignInResult result = await SignInManager.TwoFactorSignInAsync(
                    provider: this._2FA_Email,
                    code: code,
                    isPersistent: rememberBrowser,
                    rememberClient: rememberBrowser
                );

            if (result.Succeeded)
            {
                // セッションの初期化
                this.InitSessionAfterlogin();

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

        #region With authenticator

        /// <summary>LoginWithTwoFactorAuthenticator</summary>
        /// <param name="rememberMe">bool</param>
        /// <param name="returnUrl">string</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult LoginWithTwoFactorAuthenticator(bool rememberMe, string returnUrl = null)
        {
            //// Ensure the user has gone through the username & password screen first
            //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

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
            if (ModelState.IsValid)
            {
                //// Ensure the user has gone through the username & password screen first
                //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                AspNetId.SignInResult result
                    = await SignInManager.TwoFactorAuthenticatorSignInAsync(
                        model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty),
                        rememberMe, model.RememberMachine);

                if (result.Succeeded)
                {
                    //_logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                    return RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    //_logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    return RedirectToAction("Lockout");
                }
                else
                {
                    //_logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                    return View();
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
        public ActionResult LoginWithTwoFactorAuthenticatorRecoveryCode(string returnUrl = null)
        {
            //// Ensure the user has gone through the username & password screen first
            //var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

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
            if (ModelState.IsValid)
            {
                //// Ensure the user has gone through the username & password screen first
                //var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

                AspNetId.SignInResult result
                    = await SignInManager.TwoFactorRecoveryCodeSignInAsync(
                        model.RecoveryCode.Replace(" ", string.Empty));

                if (result.Succeeded)
                {
                    //_logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                    return RedirectToLocal(returnUrl);
                }
                if (result.IsLockedOut)
                {
                    //_logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    return RedirectToAction("Lockout");
                }
                else
                {
                    //_logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                    return View();
                }
            }
            else
            {
                return View(model);
            }
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}
