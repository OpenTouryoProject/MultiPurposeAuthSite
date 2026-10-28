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
                        Sts.MailThrottle.Release(purpose, userId);
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
            if (!Sts.MailThrottle.TryAcquire(Sts.MailThrottle.PurposeEmailConfirmation, user.Id))
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
            this.SendMailInBackground(Sts.MailThrottle.PurposeEmailConfirmation, user.Id,
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
            if (!Sts.MailThrottle.TryAcquire(Sts.MailThrottle.PurposePasswordReset, user.Id))
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
            this.SendMailInBackground(Sts.MailThrottle.PurposePasswordReset, user.Id,
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

        /// <summary>テスト データを撒く配備か（IsDebug ＋ TestUserPWD）</summary>
        private static bool SeedsTestData
        {
            get
            {
                return Config.IsDebug
                    && !string.IsNullOrWhiteSpace(Config.TestUserPWD);
            }
        }

        /// <summary>このプロセスが E2E 専用のクライアント登録を済ませたか（起動ごとに 1 回。#294）</summary>
        /// <remarks>
        /// **メモリと DB の両方で使う。** 登録は「無ければ作る」なので、
        /// このフラグは**ストアに聞きに行くのを、プロセスごとに 1 回にする**ためのもの。
        /// </remarks>
        private static volatile bool HasCreatedTestClients = false;

        /// <summary>
        /// 2 人目のテスト利用者に仕込む、標準クレームのサンプル（#261）。
        /// </summary>
        /// <remarks>
        /// **OIDC Core 5.1 の標準クレームを、`UnstructuredData`（JSON）に入れた例**である。
        /// **`UserClaimsMapping` で対応付けると、`/userinfo` と id_token に出る**（#230）。
        /// 雛形の対応付けは `_appsettings.json` / `_app.config` にコメントで置いてある。
        ///
        /// **`name` と `address.locality` は、わざと入れていない。**
        /// 雛形の対応付けは、その 2 つを **`usd1` / `usd2`（管理画面で入れられる 2 欄）**に
        /// 向けてある（**画面から入れた値が返ることを E2E で測り続けるため**。`RT-230.*`）。
        ///
        /// **`preferred_username` / `email` / `phone_number` も入れていない。**
        /// **`user:` で `ApplicationUser` から直に取れる**ので、二重に持たない（#151）。
        ///
        /// > **この JSON は、管理画面で保存すると消える。**
        /// > 画面（`ManageAddUnstructuredDataViewModel`）は `usd1` / `usd2` しか持たないので、
        /// > **読み込みで他のキーが捨てられ、保存で JSON ごと置き換わる。**
        /// > **仕込み先を 2 人目にしてあるのは、そのため**である
        /// > （`RT-230.*` は 1 人目の画面を叩く）。
        /// </remarks>
        private const string SampleUnstructuredData =
            "{"
            + "\"given_name\":\"Taro\","
            + "\"family_name\":\"Tanaka\","
            + "\"nickname\":\"taro\","
            + "\"profile\":\"https://example.com/taro\","
            + "\"picture\":\"https://example.com/taro.png\","
            + "\"website\":\"https://example.com/\","
            + "\"gender\":\"male\","
            + "\"birthdate\":\"1990-01-23\","
            + "\"zoneinfo\":\"Asia/Tokyo\","
            + "\"locale\":\"ja-JP\","
            + "\"updated_at\":1759449600,"
            + "\"address\":{"
            + "\"formatted\":\"100-0001 1-1 Chiyoda, Chiyoda-ku, Tokyo, JP\","
            + "\"street_address\":\"1-1 Chiyoda, Chiyoda-ku\","
            + "\"region\":\"Tokyo\","
            + "\"postal_code\":\"100-0001\","
            + "\"country\":\"JP\""
            + "}"
            + "}";

        /// <summary>テスト利用者のメアドのドメイン（#294）</summary>
        /// <remarks>
        /// **RFC 2606 の `example.com` にする**（以前は `@gmail.com` で、実在するドメインだった）。
        /// **テスト利用者は IsDebug のときだけ作られ、そのときはメールを送らない**が、
        /// **DB ストアで作った後に本番の設定へ切り替えると、第三者に届きうる。**
        /// **E2E の `TestEnv.TestUserEmail` も同じ値で揃える。**
        /// </remarks>
        private const string TestUserEmailDomain = "@example.com";

        #endregion

        #region メソッド
        
        /// <summary>
        /// この接尾辞のテスト利用者を、初期化済みか（#294）
        /// </summary>
        /// <returns>初期化済みなら true</returns>
        /// <remarks>
        /// **最初に作る利用者（super_tanaka ＋ 接尾辞）が居れば、初期化済みとみなす。**
        /// IsDBMSInitialized が、最初に入れる [Roles] の件数で判定するのと同じ考え方。
        ///
        /// - **ストアに聞く**ので、メモリと DB の両方で使え、起動し直しても答えが変わらない。
        /// - **接尾辞を変えた・DB を共有する後発のサイト**では居ないので、作る（#260）。
        /// - **super_tanaka 自身を消すと、その接尾辞の利用者は全部作り直す**
        ///   （ロールを全部消すと、IsDBMSInitialized が初期化し直すのと同じ）。
        /// </remarks>
        private async Task<bool> IsTestUsersInitialized()
        {
            return await this.UserManager.FindByNameAsync(
                "super_tanaka" + Config.TestUserSuffix) != null;
        }

        /// <summary>
        /// テスト利用者を作る（呼ぶ側が SeedsTestData を確かめる）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **名前に接尾辞を付けられる**（`TestUserSuffix`。#260）。**空なら付けない。**
        ///
        /// **E2E は net48 版と net10.0 版を同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ため、分けないと
        /// **同じ利用者の属性（`DeviceToken` / `UnstructuredData`）を書き換え合う。**
        ///
        /// **この接尾辞の利用者が初期化済みなら、何もしない**（IsTestUsersInitialized。#294）。
        /// **接尾辞を変えても、DB を作り直さなくてよい**（#260）。
        /// **デバッグで消したテスト利用者を、起動し直しても戻さない**（#294）。
        /// </remarks>
        private async Task CreateTestUsers()
        {
            if (await this.IsTestUsersInitialized())
            {
                // 接尾辞のテスト利用者を、初期化済み
                return;
            }

            // 接尾辞のテスト利用者を、初期化する。
            string password = Config.TestUserPWD;
            string suffix = Config.TestUserSuffix;
            string superName = "super_tanaka" + suffix;
            string normalName = "tanaka" + suffix;

            #region ユーザを作成

            // 管理者ユーザを作成
            if (await this.UserManager.FindByNameAsync(superName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    superName, superName + TestUserEmailDomain, true);

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(superName)).Id, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(superName)).Id, Const.Role_Admin);
                }
            }

            // 一般ユーザを作成
            if (await this.UserManager.FindByNameAsync(normalName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    normalName, normalName + TestUserEmailDomain, true);

                // **標準クレームのサンプルを持たせる**（#261）。
                user.UnstructuredData = SampleUnstructuredData;

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        (await this.UserManager.FindByNameAsync(normalName)).Id, Const.Role_User);
                }
            }
            else
            {
                // **既に居る利用者にも、空なら入れる**（#261）。
                //   **ここに来るのは、super_tanaka を消して tanaka だけが残っている場合だけ**
                //   （両方居れば、IsTestUsersInitialized で先に戻る）。
                //   **空のときだけ**なので、利用者が自分で入れた値は上書きしない。
                ApplicationUser user = await this.UserManager.FindByNameAsync(normalName);

                if (user != null
                    && string.IsNullOrEmpty(user.UnstructuredData))
                {
                    user.UnstructuredData = SampleUnstructuredData;
                    await this.UserManager.UpdateAsync(user);
                }
            }
            
            #endregion
        }

        /// <summary>
        /// E2E 専用のクライアントを登録する（呼ぶ側が SeedsTestData を確かめる）。
        /// </summary>
        /// <remarks>
        /// **起動ごとに 1 回だけ通す**（HasCreatedTestClients。#294）。
        /// **IsTestUsersInitialized の判定には入れない。** 接尾辞が無く 2 つのサイトで共有し、
        /// **TestClients に後から足したクライアントを、既存の DB に入れる役目もある**ため。
        /// </remarks>
        private void CreateTestClients()
        {
            if (AccountController.HasCreatedTestClients)
            {
                // 起動ごとの 1 回が済んでいる。
                return;
            }

            #region E2E 専用のクライアント登録

            // E2E だけが使うクライアント登録を、構成ファイルの既存のクライアントを写して作り、user store に無ければ入れる。
            //   **user store に寄せてある**ので、**件数に上限が無い**
            //   （環境変数で差し込むと、net48 版は一覧ごと 1 本になり、件数に上限が出る。#262 / #264）。
            //   **接尾辞は付けない。** E2E が client_name と固定の client_id で引くため
            //   （Sts.TestClients の表と、E2E の KnownClients を同じ値で揃える）。
            foreach (Sts.TestClients.Entry entry in Sts.TestClients.Entries)
            {
                // 写す元（構成ファイル）から、登録を作る。
                ViewModels.ManageAddSaml2OAuth2DataViewModel saml2OAuth2Data = Sts.TestClients.CreateSaml2OAuth2Data(entry);

                if (saml2OAuth2Data == null)
                {
                    // **写す元が構成ファイルに無い。** その分は E2E が Skip する。
                    continue;
                }

                // **所有者（OwnerUserId）は持たせない**（#307）。
                //   構成ファイルの owner 無しのクライアントと同じく、**配備全体のもの**である。
                //   **所有者の無い登録を作るのは、ここだけ**（管理画面と DCR は、必ず所有者を書く）。

                // **この client_id の登録が無ければ入れる**（在れば触らない）。
                //   **DB ストアでは 2 つのサイトが同じ user store を共有する**（#260）ので、
                //   **書き込みを 1 回に閉じる。**
                if (Sts.Saml2OAuth2DataProvider.Get(entry.ClientId) == null)
                {
                    Sts.Saml2OAuth2DataProvider.Create(entry.ClientId, saml2OAuth2Data);
                }
            }

            #endregion

            // **最後まで通ってから立てる**（途中で例外なら、次の呼び出しでやり直す）。
            AccountController.HasCreatedTestClients = true;
        }

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
                    this.CreateTestClients();
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
