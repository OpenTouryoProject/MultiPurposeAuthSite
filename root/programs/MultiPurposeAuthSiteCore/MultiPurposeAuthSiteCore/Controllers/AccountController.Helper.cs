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
        #region Helper

        #region メール送信処理

        #region メアド検証、パスワード リセット

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

        #region ユーザとロールの初期化（テストコード）

        /// <summary>初期化処理のクリティカルセクション化</summary>
        private static SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        /// <summary>テストコード</summary>
        private static volatile bool HasCreated = false;

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

        /// <summary>
        /// テスト利用者を作る（IsDebug ＋ TestUserPWD が在るときだけ）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **名前に接尾辞を付けられる**（`TestUserSuffix`。#260）。**空なら付けない。**
        ///
        /// **E2E は net48 版と net10.0 版を同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ため、分けないと
        /// **同じ利用者の属性（`DeviceToken` / `UnstructuredData`）を書き換え合う。**
        ///
        /// **居なければ作る**（**初期化済みの DB でも呼ばれる**）。
        /// **接尾辞を変えても、DB を作り直さなくてよい**ようにするため。
        /// </remarks>
        private async Task CreateTestUsers()
        {
            string password = Config.TestUserPWD;

            if (!Config.IsDebug
                || string.IsNullOrWhiteSpace(password))
            {
                return;
            }

            string suffix = Config.TestUserSuffix;
            string superName = "super_tanaka" + suffix;
            string normalName = "tanaka" + suffix;

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
                string webAuthnName = "webauthn_tanaka" + suffix;

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

            // **E2E 専用のクライアント登録**（#264）。
            //   **利用者の登録（saml2OAuth2Data）に寄せてある**ので、**件数に上限が無い**
            //   （環境変数で差し込むと、net48 版は一覧ごと 1 本になり、件数に上限が出る。#262）。
            //
            //   **接尾辞は付けない。** client_name は E2E が名前で引くため
            //   （Sts.TestClients の表と、E2E の KnownClients を同じ値で揃える）。
            //   **サイトごとに分ける必要も無い**（作った後は読むだけで、書き換え合わない。#260）。
            foreach (Sts.TestClients.Entry entry in Sts.TestClients.Entries)
            {
                ViewModels.ManageAddSaml2OAuth2DataViewModel saml2OAuth2Data
                    = Sts.TestClients.CreateSaml2OAuth2Data(entry);

                if (saml2OAuth2Data == null)
                {
                    // **写す元が構成ファイルに無い。** その分は E2E が Skip する。
                    continue;
                }

                //  **クライアントごとの利用者は作らない**（所有者は `Saml2OAuth2Data.OwnerUserId`。#307）。
                //
                //  **種データの登録は、所有者を持たない**（`OwnerUserId` は空）。
                //    **構成ファイルのクライアントと同じ立場**である（配備全体のもの）。
                //    **`ClientName` は入る**（**ラベル**。E2E が名前で引く）。

                // **登録が無ければ入れる**（在れば触らない）。
                //   **DB ストアでは 2 つのサイトが同じ user store を共有する**（#260）ので、
                //   **書き込みを 1 回に閉じる。**
                if (Sts.Saml2OAuth2DataProvider.Get(entry.ClientId) == null)
                {
                    Sts.Saml2OAuth2DataProvider.Create(entry.ClientId, saml2OAuth2Data);
                }
            }
        }

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

                if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    // Memory Providerの場合、
                    if (AccountController.HasCreated)
                    {
                        // **初期化済みでも、テスト用の種はまき直す**（#277）。
                        //   **E2E が消すものがある**（WebAuthn の資格情報）ので、
                        //   **DB ストアと同じく「居なければ作る」を毎回通す。**
                        //   **本番では IsDebug が false なので、CreateTestUsers は即座に戻る。**
                        await this.CreateTestUsers();

                        // 初期化済み。
                        return; // break;
                    }
                    else
                    {
                        AccountController.HasCreated = true; // 初期化済みに変更。
                    }
                }
                else if (Config.UserStoreType == EnumUserStoreType.SqlServer
                    || Config.UserStoreType == EnumUserStoreType.ODPManagedDriver
                    || Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                {
                    // DBMS Providerの場合、
                    if (await DataAccess.IsDBMSInitialized())
                    {
                        // **初期化済みでも、テスト利用者だけは作り足す**（#260）。
                        //   **接尾辞（TestUserSuffix）を変えたら、その利用者は未作成**である。
                        //   **DB を作り直させないため**に、足りなければここで作る。
                        await this.CreateTestUsers();

                        // 初期化済み。
                        return; // break;
                    }
                }

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

                #region テスト・ユーザ

                await this.CreateTestUsers();

                #endregion

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
