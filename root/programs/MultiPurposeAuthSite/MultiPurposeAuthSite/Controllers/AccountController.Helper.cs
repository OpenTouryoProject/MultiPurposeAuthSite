//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の メール送信・初期化
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//*  2026/10/27  玄人 幸道         テスト用の種まきを net10.0 版に揃えた（利用者は接尾辞の super_tanaka で判定、クライアントは起動ごとに 1 回。#294）
//*  2026/10/28  玄人 幸道         メアド検証・パスワード リセットのメールを、同じ利用者に続けて送らない（#294）
//*  2026/10/28  玄人 幸道         メールを要求から切り離して送る（async void をやめた）、完了メールの空送りをやめた、
//*  2026/11/02  玄人 幸道         E2E 専用のクライアントを 2 つのサイトが同時に作っても、サインイン画面を落とさない（#325）
//*  2026/11/03  玄人 幸道         テスト データの作成を AccountController.TestData.cs と Util/Test へ移した（#294）
//*                                初期化の確認を 1 回に、管理者の作成の失敗を記録、テスト利用者のメアドを example.com に（#294）
//**********************************************************************************

/*
主に「各種通知メールの送信処理」と
「初期データ作成・テストデータのシード処理」の
2つの責務を持ったAccountControllerクラスの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.Test;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の メール送信・初期化**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region メール送信処理

        /// <summary>
        /// メールを、要求から切り離して送る（#294）。
        /// </summary>
        /// <param name="purpose">用途（ログと MailThrottle の用途。間隔で絞らないメールは null）</param>
        /// <param name="userId">宛先の利用者の id（ログに書く。メアドは書かない）</param>
        /// <param name="destination">宛先</param>
        /// <param name="subject">件名</param>
        /// <param name="body">本文</param>
        /// <remarks>
        /// **以前は `async void` で送っていた**（呼ぶ側は待たない）。
        /// **SMTP の失敗**（サーバの停止・資格情報の誤り・宛先の拒否）**が処理されない例外になり、**
        /// **net10.0 版ではプロセスが落ち、net48 版では要求の完了と競合した**（サインアップ・パスワードの失念は、誰でも押せる）。
        /// **要求が終わった後に `HttpContext` / `Url` を触ることもあった**（トークンの生成が非同期のとき）。
        ///
        /// - **送る値は、呼ぶ側が要求の中で作り終えている**（ここでは `HttpContext` も `UserManager` も触らない）
        /// - **失敗は受け止めて、記録する**（利用者の id と例外の型だけ。詳細はデバッグ ログ）
        /// - **応答の時間が、送ったかどうかで変わらない**（SMTP を待たない）
        /// </remarks>
        private void SendMailInBackground(
            string purpose, string userId, string destination, string subject, string body)
        {
            //  **UserManager.SendEmailAsync は使わない**（UserManager は要求の後に破棄される）。
            //    **送り先は同じ EmailService**（ApplicationUserManager に登録しているもの）。
            Task.Run(async () =>
            {
                try
                {
                    await new EmailService().SendAsync(new IdentityMessage()
                    {
                        Destination = destination,
                        Subject = subject,
                        Body = body
                    });
                }
                catch (Exception ex)
                {
                    Logging.MyOperationTrace(string.Format(
                        "The {0} mail to {1} could not be sent. ({2})",
                        purpose ?? "notification", userId, ex.GetType().Name));
                    Logging.MyDebugLogForEx(ex);

                    // **送れなかった分は、間隔に数えない**（すぐに送り直せるように）。
                    if (purpose != null)
                    {
                        MailThrottle.Release(purpose, userId);
                    }
                }
            });
        }

        #region メアド検証、PWDリセット

        /// <summary>
        /// メアド検証で使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Task（**送信は待たない**。トークンと URL を作り終えたら戻る）</returns>
        private async Task SendConfirmEmail(ApplicationUser user)
        {
            // **同じ利用者に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）
            if (!MailThrottle.TryAcquire(MailThrottle.PurposeEmailConfirmation, user.Id))
            {
                return;
            }

            string code;
            string callbackUrl;

            // メアド検証用のメールを送信
            code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Account",
                    new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);

            // E-mailの送信
            string subject = GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm);
            string body = GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg);
            this.SendMailInBackground(MailThrottle.PurposeEmailConfirmation, user.Id,
                user.Email, subject, string.Format(body, callbackUrl, user.UserName));
        }

        /// <summary>
        /// パスワード リセットで使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Task（**送信は待たない**。トークンと URL を作り終えたら戻る）</returns>
        private async Task SendConfirmEmailForPasswordReset(ApplicationUser user)
        {
            // **同じ利用者に、続けて送らない**（#294。`MailResendIntervalSeconds`。画面は変えない）
            if (!MailThrottle.TryAcquire(MailThrottle.PurposePasswordReset, user.Id))
            {
                return;
            }

            string code;
            string callbackUrl;

            // パスワード リセット用のメールを送信
            code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);

            // URLの生成
            callbackUrl = Url.Action(
                    "ResetPassword", "Account",
                    new { userId = user.Id, code = code }, protocol: Request.Url.Scheme
                );

            // E-mailの送信
            this.SendMailInBackground(MailThrottle.PurposePasswordReset, user.Id,
                    user.Email, GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
                    string.Format(GetContentOfLetter.Get("PasswordResetMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset_msg), callbackUrl));
        }

        #endregion

        #region 完了メール送信処理

        /// <summary>
        /// 完了メールを送る（文面が無ければ送らない。#294）
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="titleKey">件名の文面の名前</param>
        /// <param name="msgKey">本文の文面の名前</param>
        /// <remarks>
        /// **完了メールの文面には、既定値（リソース）が無い。**
        /// **以前は、文面のファイルが無いと、件名も本文も空のメールを送っていた。**
        /// </remarks>
        private void SendCompletedEmail(ApplicationUser user, string titleKey, string msgKey)
        {
            string subject = GetContentOfLetter.Get(titleKey, CustomEncode.UTF_8, "");
            string body = GetContentOfLetter.Get(msgKey, CustomEncode.UTF_8, "");

            if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(body))
            {
                Logging.MyOperationTrace(string.Format(
                    "The {0} mail to {1} was not sent. (no letter)", titleKey, user.Id));
                return;
            }

            this.SendMailInBackground(null, user.Id, user.Email, subject, string.Format(body, user.UserName));
        }

        /// <summary>
        /// アカウント登録の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private void SendRegisterCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            this.SendCompletedEmail(user, "RegistationWasCompletedEmailTitle", "RegistationWasCompletedEmailMsg");
        }

        /// <summary>
        /// パスワード リセットの完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private void SendPasswordResetCompletedEmail(ApplicationUser user)
        {
            // パスワード リセットの完了メールを送信
            this.SendCompletedEmail(user, "PasswordResetWasCompletedEmailTitle", "PasswordResetWasCompletedEmailMsg");
        }

        #endregion

        #endregion

        #region ユーザとロールの初期化（テスト）

        #region メンバ変数

        /// <summary>初期化処理のクリティカルセクション化</summary>
        private static SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        /// <summary>ロールと管理者（初期データ）を、このプロセスで確かめ終えたか（mem・DB の両方。#294）</summary>
        /// <remarks>
        /// **メモリ ストアはプロセスと一緒に消える**ので、プロセスごとに 1 回でよい。
        /// **DB ストアも、初期化済みと分かったら、このプロセスでは聞き直さない**（#294）。
        /// 以前は、サインイン画面を開くたびに、プロセス全体のロックの中で `IsDBMSInitialized` を DB に聞いていた。
        /// **DB のロールを全部消して初期化し直させるときは、サイトを起動し直す。**
        /// </remarks>
        private static volatile bool HasInitializedStore = false;

        #endregion

        #region メソッド
        
        /// <summary>
        /// テストデータの作成、Login か Register の画面を開くたびに走る。
        /// - ロールと管理者（初期データ）は、ストアが初期化済みでなければ作る（HasInitializedStore、IsDBMSInitialized）。
        /// - **本番（テスト データを撒かない配備）では、確かめ終えたら、ロックも問い合わせもしない**（#294）。
        /// - テストユーザは、この接尾辞で初期化済みでなければ作る（IsTestUsersInitialized）。
        /// - E2E 専用のクライアントは、起動ごとに 1 回だけ作る。
        /// - WebAuthn の資格情報のまき直し（#277）は、net10.0 版だけ（net48 版は WebAuthn の種を持たない）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// manager.PasswordHasher = new CustomPasswordHasher();
        /// より後に動く処理の実装位置が不明だったので、巡り巡って
        /// MvcApplication(Global.asax).Application_Startからコチラに移動してきた。
        /// </remarks>
        private async Task CreateData()
        {
            //  **確かめ終えていて、テスト データも撒かない配備（本番）は、ロックも問い合わせもせずに戻る**（#294）。
            if (AccountController.HasInitializedStore && !AccountController.SeedsTestData)
            {
                return;
            }

            // ロックを取得する
            await _semaphoreSlim.WaitAsync();

            try
            {
                if (OnlySts.STSOnly_P)
                {
                    // STS専用モードなので。
                    return; // break;
                }

                // 初期化済みか？（mem、db）
                //   **このプロセスで確かめ終えていれば、聞かない**（#294）。
                bool initialized = AccountController.HasInitializedStore;

                if (initialized)
                {
                    // 確かめ終えている。
                }
                else if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    // Memory Providerの場合、プロセスの初回なので、初期化する。
                }
                else if (Config.UserStoreType == EnumUserStoreType.SqlServer
                    || Config.UserStoreType == EnumUserStoreType.ODPManagedDriver
                    || Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                {
                    // DBMS Providerの場合、
                    initialized = await DataAccess.IsDBMSInitialized();
                }

                // 初期化済みでない場合、初期化する。
                if (!initialized)
                {
                    #region 初期化コード

                    ApplicationUser user = null;
                    IdentityResult result = null;

                    #region ロール

                    await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_SystemAdmin });
                    await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_Admin });
                    await this.RoleManager.CreateAsync(new ApplicationRole() { Name = Const.Role_User });

                    #endregion

                    #region 管理者ユーザ

                    user = ApplicationUser.CreateUser(
                            UserIdentifier.UserNameFromEmail(Config.AdministratorUID),
                            Config.AdministratorUID, true);
                    result = await this.UserManager.CreateAsync(user, Config.AdministratorPWD);

                    if (result.Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(user.Id, Const.Role_SystemAdmin);
                        await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                        await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);
                    }
                    else
                    {
                        //  **作れなかった理由を残す**（#294。AdministratorPWD がパスワードの規則に合わないなど）。
                        //    以前は何も残らず、管理者の居ない状態で動き続けた。
                        Logging.MyOperationTrace(string.Format(
                            "The administrator could not be created. ({0})",
                            string.Join(", ", result.Errors)));
                    }

                    #endregion

                    #endregion
                }

                // **最後まで通ってから立てる**（#294。途中で例外なら、次の呼び出しでやり直す）。
                //   以前は、メモリ ストアのフラグを初期化の前に立てていた。
                AccountController.HasInitializedStore = true;

                #region テスト・ユーザ

                // **ロールを使うので、初期化コードの後に置く。**
                // **本番では IsDebug が false なので、何もしない。**
                if (AccountController.SeedsTestData)
                {
                    // #260：この接尾辞のテスト利用者を、初期化済みでなければ作る。
                    await this.CreateTestUsers();

                    // #264：E2E 専用のクライアントを、起動ごとに 1 回「無ければ作る」。
                    TestClients.RegisterInStore();
                }

                #endregion
            }
            finally
            {
                // ロックを解放する。
                _semaphoreSlim.Release();
            }
        }

        #endregion

        #endregion
    }
}
