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
//* クラス名        ：RefreshTokenUserTests
//* クラス日本語名  ：RT-294.71 / .72 refresh_token と利用者（削除・パスワードの変更）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（#294）
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

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.71 / .72 refresh_token は、利用者が消されたり、パスワードが変わったりしたら使えない（#294）。
    /// </summary>
    /// <remarks>
    /// **以前は、どちらでも access_token を取り続けられた。**
    /// **`RefreshTokenDictionary` には利用者の列が無く**、
    /// **更新は預けた payload から作り直すだけで、利用者を確かめていなかった**（`ANALYSIS-IdP.md` の C-54）。
    ///
    /// **使い捨ての利用者で測る**（作成と削除は `/UsersAdmin`。`RT-257.7` と同じ流儀）。
    /// **管理者でサインインする**ので、管理画面のテストと同じコレクションに入れる（並行させない）。
    /// </remarks>
    [Collection(UsersAdminTests.AdminScreenCollection)]
    public class RefreshTokenUserTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RefreshTokenUserTests(ITestOutputHelper output) : base(output) { }

        /// <summary>RT-294.71 消された利用者の refresh_token は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29471_消された利用者のrefresh_tokenは使えない(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                string name = RefreshTokenUserTests.UniqueName();
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-294.71",
                    "利用者を消したら、その人の refresh_token では access_token を取れない",
                    "**利用者の削除（管理画面・GDPR の削除）は、その人への発行を止めることでもある。**"
                    + "**以前は `RefreshTokenDictionary` に利用者の列が無く、更新は利用者を確かめなかった**ので、"
                    + "**消された利用者の access_token を、RP が取り続けられた。**",
                    "#294（CmnEndpoints.GrantRefreshTokenCredentials。ANALYSIS-IdP.md の C-54）");

                r.Target("使い捨ての利用者 = " + name + " / client_name=" + KnownClients.MvcSample);

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                bool deleted = false;

                try
                {
                    r.Step("(1) 使い捨ての利用者を作り、その人で refresh_token を得る");

                    Assert.True(RefreshTokenUserTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    Assert.True(await user.TrySignInAsync(name, password),
                        "前提: 作った利用者でサインインできること");

                    ClientRegistration reg = Flows.Registration(user, KnownClients.MvcSample);

                    JsonResponse first = await Flows.RunAuthorizationCodeFlowAsync(
                        user, KnownClients.MvcSample, "openid email");

                    Assert.False(string.IsNullOrEmpty(first.RefreshToken),
                        "前提: refresh_token が発行されること");

                    JsonResponse second = await Flows.RefreshAsync(user, reg, first.RefreshToken);

                    r.Verify("消す前は、更新できる",
                        !string.IsNullOrEmpty(second.AccessToken) && !string.IsNullOrEmpty(second.RefreshToken),
                        "できる",
                        string.IsNullOrEmpty(second.AccessToken)
                            ? "**できない**（error=" + (second.Error ?? "なし") + "）" : "できる");

                    Assert.False(string.IsNullOrEmpty(second.RefreshToken),
                        "前提: 更新で新しい refresh_token が返ること");

                    r.Step("(2) 管理者が、その利用者を消す");

                    deleted = await UsersAdmin.DeleteByUserNameAsync(admin, name);

                    Assert.True(deleted, "前提: 利用者を消せること");

                    r.Step("(3) 消された利用者の refresh_token で更新する");

                    JsonResponse after = await Flows.RefreshAsync(user, reg, second.RefreshToken);

                    r.VerifyEqual("invalid_grant で断る", "invalid_grant", after.Error);

                    r.Verify("**access_token を返さない**",
                        string.IsNullOrEmpty(after.AccessToken),
                        "返さない",
                        string.IsNullOrEmpty(after.AccessToken) ? "返さない" : "**返してしまった**");
                }
                finally
                {
                    if (!deleted)
                    {
                        await UsersAdmin.DeleteByUserNameAsync(admin, name);
                    }
                }

                r.Note("**発行済みの access_token は、期限まで残る**（短命なので、ここでは失効させない）。");

                r.Done();
            }
        }

        /// <summary>RT-294.72 パスワードを変えたら、それより前の refresh_token は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29472_パスワードを変えたら前のrefresh_tokenは使えない(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                string name = RefreshTokenUserTests.UniqueName();
                string email = name + "@example.com";
                string password1 = admin.Config.Get("TestUserPWD");

                // **新しいパスワードは、構成ファイルの値から作る**（`TESTING.md` 9 節）。
                string password2 = password1 + "Zz9";

                TestReport r = this.Report("RT-294.72",
                    "パスワードを変えたら、それより前に発行した refresh_token は使えない（照会も active=false）",
                    "**パスワードを変えるのは、漏れたと思ったときである。**"
                    + "**そのとき、漏れた先で取られた refresh_token も止まらなければならない。**"
                    + "**SecurityStamp のハッシュを refresh_token に預け、更新と照会で照合する**"
                    + "（パスワードの変更・リセットなど、Identity が SecurityStamp を変える操作で止まる）。",
                    "#294（CmnEndpoints.CheckUserOfRefreshToken。ANALYSIS-IdP.md の C-54）");

                r.Target("使い捨ての利用者 = " + name + " / client_name=" + KnownClients.MvcSample);

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作り、その人で refresh_token を得る");

                    Assert.True(RefreshTokenUserTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    Assert.True(await user.TrySignInAsync(name, password1),
                        "前提: 作った利用者でサインインできること");

                    ClientRegistration reg = Flows.Registration(user, KnownClients.MvcSample);

                    JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                        user, KnownClients.MvcSample, "openid email");

                    Assert.False(string.IsNullOrEmpty(token.RefreshToken),
                        "前提: refresh_token が発行されること");

                    JsonResponse before = await Flows.IntrospectAsync(
                        user, reg, token.RefreshToken, "refresh_token");

                    r.Verify("変える前は、照会が active=true",
                        before.KindOf("active") == JsonValueKind.True,
                        "active=true", before.KindOf("active").ToString());

                    r.Verify("**照会に、預けた SecurityStamp のハッシュが出ない**",
                        !(before.Body ?? "").Contains("security_stamp"),
                        "出ない",
                        (before.Body ?? "").Contains("security_stamp") ? "**出ている**" : "出ない");

                    r.Step("(2) 本人がパスワードを変える");

                    HttpResponseMessage changed = await RefreshTokenUserTests.PostAsync(
                        user, "/Manage/ChangePassword",
                        new Dictionary<string, string>()
                        {
                            { "OldPassword", password1 },
                            { "NewPassword", password2 },
                            { "ConfirmPassword", password2 }
                        });

                    Assert.True(RefreshTokenUserTests.IsRedirect(changed),
                        "前提: パスワードを変えられること（HTTP " + (int)changed.StatusCode + "）");

                    r.Step("(3) 変える前の refresh_token を照会し、更新する");

                    JsonResponse introspected = await Flows.IntrospectAsync(
                        user, reg, token.RefreshToken, "refresh_token");

                    r.Verify("照会が active=false",
                        introspected.KindOf("active") == JsonValueKind.False,
                        "active=false", introspected.KindOf("active").ToString());

                    JsonResponse after = await Flows.RefreshAsync(user, reg, token.RefreshToken);

                    r.VerifyEqual("更新は invalid_grant で断る", "invalid_grant", after.Error);

                    r.Verify("**access_token を返さない**",
                        string.IsNullOrEmpty(after.AccessToken),
                        "返さない",
                        string.IsNullOrEmpty(after.AccessToken) ? "返さない" : "**返してしまった**");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Note("**値は出していない。** 新しいパスワードは構成ファイルの値から作っている（`TESTING.md` 9 節）。");

                r.Done();
            }
        }

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

        /// <summary>管理画面のフォームを送る（AntiForgeryToken は画面から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="path">パス</param>
        /// <param name="values">送る値</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostAsync(
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
            return "e2e_rt_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        #endregion
    }
}
