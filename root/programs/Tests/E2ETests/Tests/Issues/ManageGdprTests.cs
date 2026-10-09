//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：ManageGdprTests
//* クラス日本語名  ：RT-277 GDPR 対応（自分のデータの参照と消去）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-277 GDPR 対応（`/Manage/ManageGdprData` の参照と消去）。
    /// </summary>
    /// <remarks>
    /// **2 つの口がある**（どちらも `CanUseGdprFunction` で開け閉めする）。
    ///
    /// | | |
    /// |---|---|
    /// | 参照 | `ReferGdprPersonalData`。**自分の利用者データを `user.json` として返す** |
    /// | 消去 | `DeleteGdprPersonalData`。**属性を利用者 id で塗り潰し、サインアウトする** |
    ///
    /// **消去は、行を消すのではない。** **利用者名・メアド・電話番号を id に置き換え、
    /// パスワードの控えを空にし、外部ログインとクレームを外す。**
    /// **結果として、その利用者ではもうサインインできない。**
    ///
    /// **使い捨ての利用者を、その都度ひとつ作る**（`RT-277.4` 〜 `.6` と同じ流儀）。
    /// **消去は元に戻せない**ので、**テスト利用者を使ってはならない。**
    ///
    /// **持ち出せる項目は、`ApplicationUser` の `[JsonProperty]` が決める**（OptIn）。
    /// **付けなければ出ない**ので、**プロパティを足しても、黙って持ち出せる物は増えない。**
    /// </remarks>
    public class ManageGdprTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ManageGdprTests(ITestOutputHelper output) : base(output) { }

        #region RT-277.7

        /// <summary>RT-277.7 GDPR の参照は、自分のデータを JSON で返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27707_GDPRの参照は自分のデータをJSONで返す(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name = ManageGdprTests.UniqueName();
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-277.7",
                    "GDPR の参照は、自分の利用者データを JSON のファイルとして返す",
                    "**自分のデータを持ち出せること**（データ ポータビリティ）を見る。"
                    + "**ファイルとして返す**ので、`Content-Type` と `Content-Disposition` も押さえる。"
                    + "**中身は自分のもの**であること（利用者名とメアドが入っている）。",
                    "#277 / ManageController.ReferGdprPersonalData");

                r.Target("POST /Manage/ReferGdprPersonalData（利用者 " + name + "）");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作って、サインインする");

                    Assert.True(ManageGdprTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password),
                            "前提: 作った利用者でサインインできること");

                        r.Step("(2) 参照の口を叩く");

                        HttpResponseMessage res = await ManageGdprTests.PostAsync(
                            user, "/Manage/ManageGdprData", "/Manage/ReferGdprPersonalData");

                        r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                        string mediaType = (res.Content.Headers.ContentType == null)
                            ? "（無し）" : res.Content.Headers.ContentType.MediaType;

                        r.VerifyEqual("application/json で返る", "application/json", mediaType);

                        string disposition = (res.Content.Headers.ContentDisposition == null)
                            ? "" : res.Content.Headers.ContentDisposition.ToString();

                        r.Verify("ファイル名が user.json である",
                            disposition.Contains("user.json"),
                            "user.json",
                            string.IsNullOrEmpty(disposition) ? "**Content-Disposition が無い**"
                                : disposition);

                        r.Step("(3) 中身が自分のものである");

                        string body = await res.Content.ReadAsStringAsync();

                        JsonElement json;

                        try
                        {
                            json = JsonDocument.Parse(body).RootElement;
                        }
                        catch (JsonException e)
                        {
                            r.Verify("JSON として読める", false, "読める", "**" + e.Message + "**");
                            throw;
                        }

                        r.Verify("JSON として読める", true, "読める", "読める");

                        r.VerifyEqual("利用者名が自分のものである",
                            name, ManageGdprTests.Text(json, "UserName"));

                        r.VerifyEqual("メアドが自分のものである",
                            email, ManageGdprTests.Text(json, "Email"));

                        //  **資格情報の材料は持ち出させない。**
                        //    **`ApplicationUser` は OptIn で直列化する**ので、
                        //    **`[JsonProperty]` を付けた物だけが出る。**
                        //    **足した物が黙って出ることはない**が、
                        //    **うっかり付けたら出てしまう**ので、名指しで押さえる。
                        List<string> names = ManageGdprTests.Names(json);

                        foreach (string secret in new string[] {
                            "PasswordHash", "SecurityStamp",
                            "TotpAuthenticatorKey", "TotpTokens", "DeviceToken" })
                        {
                            r.Verify(secret + " は入っていない",
                                !names.Contains(secret),
                                "入っていない",
                                names.Contains(secret) ? "**入っている**" : "入っていない");
                        }
                    }
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-277.8

        /// <summary>RT-277.8 GDPR の消去で、個人情報が消えてサインインできなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27708_GDPRの消去で個人情報が消える(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name = ManageGdprTests.UniqueName();
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");
                string id = null;

                TestReport r = this.Report("RT-277.8",
                    "GDPR の消去で、個人情報が消え、その利用者ではサインインできなくなる",
                    "**消去は、行を消すのではない。**"
                    + "**利用者名・メアド・電話番号を利用者 id で塗り潰し、"
                    + "パスワードの控えを空にし、外部ログインとクレームを外す。**"
                    + "**属性データ（`UnstructuredData`）も空にする。**"
                    + "**結果として、その利用者ではもうサインインできない。**",
                    "#277 / ManageController.DeleteGdprPersonalData");

                r.Target("POST /Manage/DeleteGdprPersonalData（利用者 " + name + "）");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作って、属性データを入れる");

                    Assert.True(ManageGdprTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    id = UsersAdmin.FindId(
                        await (await UsersAdmin.IndexAsync(admin)).Content.ReadAsStringAsync(),
                        name);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作った利用者の id を引けること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password),
                            "前提: 作った利用者でサインインできること");

                        await ManageGdprTests.PostFormAsync(user, "/Manage/AddUnstructuredData",
                            new Dictionary<string, string>()
                            {
                                { "UnstructuredData1", "rt27708" },
                                { "UnstructuredData2", "rt27708" }
                            });

                        string index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("属性データが入っている（前提）",
                            (index ?? "").Contains("RemoveUnstructuredData"),
                            "入っている",
                            (index ?? "").Contains("RemoveUnstructuredData")
                                ? "入っている" : "**入っていない**");

                        r.Step("(2) 消去の口を叩く");

                        HttpResponseMessage res = await ManageGdprTests.PostAsync(
                            user, "/Manage/ManageGdprData", "/Manage/DeleteGdprPersonalData");

                        r.Verify("どこかへリダイレクトする（消去の成功）",
                            ManageGdprTests.IsRedirect(res),
                            "リダイレクト", ((int)res.StatusCode).ToString());

                        r.Step("(3) サインアウトしている");

                        HttpResponseMessage after = await user.GetAsync("/Manage/Index");

                        r.Verify("管理画面が開かない",
                            after.StatusCode != HttpStatusCode.OK,
                            "開かない", ((int)after.StatusCode).ToString());
                    }

                    r.Step("(4) 消した利用者では、もうサインインできない");

                    bool byName = await this.TrySignInAsync(targetKey, name, password);
                    bool byEmail = await this.TrySignInAsync(targetKey, email, password);

                    r.Verify("利用者名では入れない", !byName,
                        "入れない", byName ? "**入れてしまう**" : "入れない");

                    r.Verify("メアドでも入れない", !byEmail,
                        "入れない", byEmail ? "**入れてしまう**" : "入れない");

                    r.Step("(5) 管理画面の一覧からも、元の利用者名が消えている");

                    string list = await (await UsersAdmin.IndexAsync(admin))
                        .Content.ReadAsStringAsync();

                    r.Verify("元の利用者名が出ない",
                        UsersAdmin.FindId(list, name) == null,
                        "出ない",
                        (UsersAdmin.FindId(list, name) == null) ? "出ない" : "**出る**");

                    r.Verify("元のメアドが出ない",
                        !(list ?? "").Contains(email),
                        "出ない", (list ?? "").Contains(email) ? "**出る**" : "出ない");

                    r.Note("**行そのものは残る。** **利用者名は利用者 id に置き換わる**ので、"
                        + "**一覧には id の名前で出る。** 後片付けは、その名前で消している。");

                    r.Note("**「入れない」を作っているのは、消去の 1 行ではない。**"
                        + "**実測** : 利用者名・メアド・パスワードの控え・ロックアウトの期限を"
                        + "**どれも消さないようにしても、やはり入れなかった** — "
                        + "**`EmailConfirmed = false`** が効いている"
                        + "（サインインは `IsEmailConfirmedAsync` を見る）。"
                        + "**退行をいちばん早く捕まえるのは、(5) の一覧の確認**である。");
                }
                finally
                {
                    // **消去の後は、利用者名が id になっている**ので、そちらで消す。
                    if (!string.IsNullOrEmpty(id))
                    {
                        await UsersAdmin.DeleteByUserNameAsync(admin, id);
                    }

                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>管理者でサインインした client を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }

        /// <summary>新しい client で、サインインを試す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="userName">利用者名（またはメアド）</param>
        /// <param name="password">パスワード</param>
        /// <returns>入れたら true</returns>
        private async Task<bool> TrySignInAsync(
            string targetKey, string userName, string password)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                return await client.TrySignInAsync(userName, password);
            }
        }

        /// <summary>画面のボタンを押す（AntiForgeryToken は、その画面から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="screen">ボタンが在る画面</param>
        /// <param name="path">送り先</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostAsync(
            IdPClient client, string screen, string path)
        {
            string html = await client.GetStringAsync(screen);

            Assert.False(string.IsNullOrEmpty(html), "前提: " + screen + " が開くこと");

            return await client.PostFormAsync(path,
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", Html.Antiforgery(html) }
                });
        }

        /// <summary>画面のフォームを送る（AntiForgeryToken は、その画面から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="path">パス</param>
        /// <param name="values">送る値</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostFormAsync(
            IdPClient client, string path, Dictionary<string, string> values)
        {
            string html = await client.GetStringAsync(path);

            Assert.False(string.IsNullOrEmpty(html), "前提: " + path + " が開くこと");

            Dictionary<string, string> form = new Dictionary<string, string>(values)
            {
                { "__RequestVerificationToken", Html.Antiforgery(html) }
            };

            return await client.PostFormAsync(path, form);
        }

        /// <summary>JSON の文字列を返す（無ければ「（無し）」）</summary>
        /// <param name="json">JSON</param>
        /// <param name="name">項目名</param>
        /// <returns>値</returns>
        private static string Text(JsonElement json, string name)
        {
            return (json.TryGetProperty(name, out JsonElement v)
                && v.ValueKind == JsonValueKind.String)
                ? v.GetString() : "（無し）";
        }

        /// <summary>JSON の項目名を並べる</summary>
        /// <param name="json">JSON</param>
        /// <returns>項目名</returns>
        private static List<string> Names(JsonElement json)
        {
            List<string> names = new List<string>();

            foreach (JsonProperty p in json.EnumerateObject())
            {
                names.Add(p.Name);
            }

            return names;
        }

        /// <summary>リダイレクトか</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        /// <summary>この回だけの利用者名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_gdpr_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        #endregion
    }
}
