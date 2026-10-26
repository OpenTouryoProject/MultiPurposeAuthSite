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
//*  2026/10/27  玄人 幸道         CreateTestUsers の呼び出しを、CreateData の末尾の 1 か所にまとめた（#294）
//*  2026/10/27  玄人 幸道         テスト利用者とクライアントの作成を起動ごとに 1 回にした（毎回は WebAuthn の資格情報だけ。#294）
//*  2026/10/27  玄人 幸道         テスト利用者は、接尾辞の super_tanaka が居るかで初期化済みを判定する（#294）
//**********************************************************************************

/*
主に「各種通知メールの送信処理」と
「初期データ作成・テストデータのシード処理」の
2つの責務を持ったAccountControllerクラスの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の メール送信・初期化**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region メール送信処理

        #region メアド検証、PWDリセット

        /// <summary>
        /// メアド検証で使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendConfirmEmail(ApplicationUser user)
        {
            string code;
            string callbackUrl;

            // メアド検証用のメールを送信
            code = await UserManager.GenerateEmailConfirmationTokenAsync(user);

            // URLの生成
            callbackUrl = this.Url.Action(
                    "EmailConfirmation", "Account",
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

            // E-mailの送信
            string subject = GetContentOfLetter.Get("EmailConfirmationTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm);
            string body = GetContentOfLetter.Get("EmailConfirmationMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_emailconfirm_msg);
            await EmailSender.SendAsync(user.Email, subject, string.Format(body, callbackUrl, user.UserName));
        }

        /// <summary>
        /// パスワード リセットで使用するメール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendConfirmEmailForPasswordReset(ApplicationUser user)
        {
            string code;
            string callbackUrl;

            // パスワード リセット用のメールを送信
            code = await UserManager.GeneratePasswordResetTokenAsync(user);

            // URLの生成
            callbackUrl = Url.Action(
                    "ResetPassword", "Account",
                    new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme
                );

            // E-mailの送信
            await EmailSender.SendAsync(
                    user.Email, GetContentOfLetter.Get("PasswordResetTitle", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset),
                    string.Format(GetContentOfLetter.Get("PasswordResetMsg", CustomEncode.UTF_8, Resources.AccountController.SendEmail_passwordreset_msg), callbackUrl));
        }

        #endregion

        #region 完了メール送信処理

        /// <summary>
        /// アカウント登録の完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendRegisterCompletedEmail(ApplicationUser user)
        {
            // アカウント登録の完了メールを送信
            await EmailSender.SendAsync(
                user.Email, GetContentOfLetter.Get("RegistationWasCompletedEmailTitle", CustomEncode.UTF_8, ""), 
                string.Format(GetContentOfLetter.Get("RegistationWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        /// <summary>
        /// パスワード リセットの完了メール送信処理。
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        private async void SendPasswordResetCompletedEmail(ApplicationUser user)
        {
            // パスワード リセット用のメールを送信
            await EmailSender.SendAsync(
                user.Email, GetContentOfLetter.Get("PasswordResetWasCompletedEmailTitle", CustomEncode.UTF_8, ""),
                string.Format(GetContentOfLetter.Get("PasswordResetWasCompletedEmailMsg", CustomEncode.UTF_8, ""), user.UserName));
        }

        #endregion

        #endregion

        #region ユーザとロールの初期化（テスト）

        #region メンバ変数

        /// <summary>初期化処理のクリティカルセクション化</summary>
        private static SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        /// <summary>メモリ ストアを初期化済みか（DB ストアは IsDBMSInitialized で DB に聞く）</summary>
        /// <remarks>メモリ ストアはプロセスと一緒に消えるので、static で覚えておける。</remarks>
        private static volatile bool HasInitializedMemoryStore = false;

        /// <summary>このプロセスが E2E 専用のクライアント登録を済ませたか（起動毎に 1 回。#294）</summary>
        /// <remarks>
        /// **メモリと DB の両方で使う。** 登録は「無ければ作る」なので、
        /// このフラグは**ストアに聞きに行くのを、プロセスごとに 1 回にする**ためのもの。
        /// </remarks>
        private static volatile bool HasCreatedTestClients = false;

        /// <summary>
        /// manager.PasswordHasher = new CustomPasswordHasher();
        /// より後に動く処理の実装位置が不明だったので、巡り巡って
        /// MvcApplication(Global.asax).Application_Startからコチラに移動してきた。
        /// </summary>
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
        /// テスト利用者を作る（呼ぶ側が IsDebug ＋ TestUserPWD を確かめる）。
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
                    superName, superName + "@gmail.com", true);

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(superName), Const.Role_User);
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(superName), Const.Role_Admin);
                }
            }

            // 一般ユーザを作成
            if (await this.UserManager.FindByNameAsync(normalName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    normalName, normalName + "@gmail.com", true);

                // **標準クレームのサンプルを持たせる**（#261）。
                user.UnstructuredData = SampleUnstructuredData;

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(normalName), Const.Role_User);
                }
            }
            else
            {
                // **既に居る利用者にも、空なら入れる**（#261）。
                //   **#260 より前に作られた DB を、作り直させないため。**
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
        /// E2E 専用のクライアントを登録する（呼ぶ側が IsDebug ＋ TestUserPWD を確かめる）。
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

            // E2E だけが使うクライアント登録を、構成ファイルの既存のクライアントを写して作り、user store に無ければ入れる
            foreach (Sts.TestClients.Entry entry in Sts.TestClients.Entries)
            {
                // 入れ物に入れる
                ViewModels.ManageAddSaml2OAuth2DataViewModel saml2OAuth2Data = Sts.TestClients.CreateSaml2OAuth2Data(entry);

                if (saml2OAuth2Data == null)
                {
                    // **写す元が構成ファイルに無い。** その分は E2E が Skip する。
                    continue;
                }

                // owner属性がない場合、ownerが無いレコードが出来るが、このようなレコードは、ココでしか作成されない。
                // （E2Eテストのために作成されたレコード。E2Eテストでは、ownerが無いレコードを作成することがある）

                // DBストアの場合初期化済みか？
                if (Sts.Saml2OAuth2DataProvider.Get(entry.ClientId) == null)
                {
                    // 初期化済みで無いので登録
                    Sts.Saml2OAuth2DataProvider.Create(entry.ClientId, saml2OAuth2Data);
                }
            }

            #endregion

            // **最後まで通ってから立てる**（途中で例外なら、次の呼び出しでやり直す）。
            AccountController.HasCreatedTestClients = true;
        }

        /// <summary>
        /// WebAuthn の資格情報を持つテスト利用者を、まき直す（呼ぶ側が IsDebug ＋ TestUserPWD を確かめる）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **毎回通す**（#277）。**E2E が途中で資格情報を消す**ので、次のテストの前に戻す。
        /// **触るのは専用の利用者（webauthn_tanaka）だけ**なので、
        /// デバッグで他のテスト利用者を触っても戻されない（#294）。
        /// </remarks>
        private async Task SeedWebAuthnTestUser()
        {
            string password = Config.TestUserPWD;

            #region WebAuthn の資格情報（#277）

            //  **専用の利用者に、資格情報を 3 件持たせる。**
            //    **資格情報を作れるのは認証器だけ**なので、**E2E では 1 件も作れない。**
            //    **削除（/Manage/RemoveWebAuthnData）を測るための前提**である（`RT-277.3`）。
            //
            //    **テスト利用者（super_tanaka / tanaka）には付けない。**
            //    **`RT-137.1` / `RT-137.2` が「この利用者は認証器を登録していない」ことを
            //    前提に書かれている**ため。
            //
            //    **何度通っても増えない**（`TestCredentials` が、消えた分だけ作り直す）。
            if (Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
            {
                string webAuthnName = "webauthn_tanaka" + Config.TestUserSuffix;

                if (await this.UserManager.FindByNameAsync(webAuthnName) == null)
                {
                    ApplicationUser user = ApplicationUser.CreateUser(
                        webAuthnName, webAuthnName + "@gmail.com", true);

                    if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            await this.UserManager.FindByNameAsync(webAuthnName), Const.Role_User);
                    }
                }

                if (await this.UserManager.FindByNameAsync(webAuthnName) != null)
                {
                    FIDO.TestCredentials.Seed(webAuthnName);
                }
            }

            #endregion
        }

        /// <summary>
        /// テストデータの作成、Login か Register の画面を開くたびに走る。
        /// - テストデータは、初期化済みでなければ作る（HasInitializedMemoryStore、IsDBMSInitialized）。
        /// - テストユーザは、この接尾辞で初期化済みでなければ作る（IsTestUsersInitialized）。
        /// - E2E 専用のクライアントは、起動ごとに 1 回だけ作る。
        /// - E2E が途中で消すユーザのWebAuthn資格情報は、次のテストが始まる前に毎回戻す。
        /// </summary>
        /// <returns>Task</returns>
        private async Task CreateData()
        {
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
                bool initialized = false;

                if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    // Memory Providerの場合、
                    initialized = AccountController.HasInitializedMemoryStore;
                    AccountController.HasInitializedMemoryStore = true;
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
                        await this.UserManager.AddToRoleAsync(user, Const.Role_SystemAdmin);
                        await this.UserManager.AddToRoleAsync(user, Const.Role_User);
                        await this.UserManager.AddToRoleAsync(user, Const.Role_Admin);
                    }

                    #endregion

                    #endregion
                }

                #region テスト・ユーザ

                // **ロールを使うので、初期化コードの後に置く。**
                // **本番では IsDebug が false なので、何もしない。**
                if (Config.IsDebug
                    && !string.IsNullOrWhiteSpace(Config.TestUserPWD))
                {
                    // 接尾辞の利用者を初期化（サイトの接尾辞毎、1 回 だけ実行）
                    await this.CreateTestUsers();

                    // #264：E2E 専用のクライアントを、起動ごとに 1 回「無ければ作る」。
                    this.CreateTestClients();

                    // #277：E2E が消すもの（WebAuthn の資格情報）を、毎回まき直す。
                    await this.SeedWebAuthnTestUser();
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
