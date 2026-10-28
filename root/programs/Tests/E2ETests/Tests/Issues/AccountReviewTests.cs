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
//* クラス名        ：AccountReviewTests
//* クラス日本語名  ：RT-294.23 〜 .25 ID 連携の戻り先・外部ログイン（AccountController.*.cs の全体のレビュー）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.23 〜 .25 ID 連携の戻り先・外部ログイン（#294）。
    /// </summary>
    /// <remarks>
    /// **`AccountController.*.cs` の全体のレビューで見つけた穴を、直した形で押さえる。**
    ///
    /// | ケース | 以前の振る舞い |
    /// |---|---|
    /// | RT-294.23 OIDC の ID 連携の後の戻り先 | **常に Home へ戻した**（認可要求の途中で使うと、RP への認可が続かなかった） |
    /// | RT-294.24 SAML2 の ID 連携の後の戻り先 | **同上** |
    /// | RT-294.25 知らない外部ログインの provider | **500**（`Challenge` が例外を出した。net10.0 版） |
    /// </remarks>
    public class AccountReviewTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AccountReviewTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-294.23 OIDC の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29423_OIDCのID連携の後はReturnUrlへ戻る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);
                string returnUrl = AccountReviewTests.LocalPath(client, "/Manage/Index");

                TestReport r = this.Report("RT-294.23",
                    "OIDC の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る",
                    "**以前は、ID 連携の後は常に Home へ戻していた**"
                    + "（`RedirectToLocal(絶対 URL)` はローカルと判定されず Home になる）。"
                    + "**認可要求の途中で ID 連携を使うと、RP への認可が続かなかった。**"
                    + "**連携を始めるときに ReturnUrl を控え、戻ってきたら、そこへ返す**ようにした。",
                    "#294（AccountController.*.cs のレビュー：ID 連携の戻り先）");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + " / ReturnUrl = " + returnUrl);

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream), "前提: 上流にサインインできること");

                r.Step("ReturnUrl を付けて「ID連携でサインイン」を押し、最後まで流す");

                FederationResult fed = await IdFederation.FederateAsync(
                    client, TestEnv.TestUserName(targetKey), "", returnUrl);

                Assert.True(fed.Authorized, "前提: 上流が認可応答を返すこと");

                string location = (fed.Callback == null || fed.Callback.Headers.Location == null)
                    ? null : fed.Callback.Headers.Location.ToString();

                r.Verify("**ReturnUrl へ戻る**（Home ではない）",
                    AccountReviewTests.PathOf(location) == returnUrl,
                    returnUrl, location ?? "**リダイレクトしない**");

                r.Done();
            }
        }

        /// <summary>RT-294.24 SAML2 の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29424_SAML2のID連携の後はReturnUrlへ戻る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);
                string returnUrl = AccountReviewTests.LocalPath(client, "/Manage/Index");

                TestReport r = this.Report("RT-294.24",
                    "SAML2 の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る",
                    "**RT-294.23 と同じ穴が、SAML2 の ID 連携にもあった。**",
                    "#294（AccountController.*.cs のレビュー：ID 連携の戻り先）");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + " / ReturnUrl = " + returnUrl);

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream), "前提: 上流にサインインできること");

                r.Step("ReturnUrl を付けて「SAML2 の ID 連携」を押し、最後まで流す");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client, "", returnUrl);

                Assert.False(string.IsNullOrEmpty(fed.AcsUrl), "前提: 上流が下流の ACS へ応答を返すこと");

                r.Verify("**ReturnUrl へ戻る**（Home ではない）",
                    AccountReviewTests.PathOf(fed.AcsLocation) == returnUrl,
                    returnUrl, fed.AcsLocation ?? ("**リダイレクトしない**（HTTP " + (int)fed.AcsStatusCode + "）"));

                r.Done();
            }
        }

        /// <summary>RT-294.25 登録されていない外部ログインの provider は、サインイン画面へ戻す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29425_知らない外部ログインのproviderはサインイン画面へ戻す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.25",
                    "登録されていない外部ログインの provider は、500 にならず、サインイン画面へ戻す",
                    "**net10.0 版は、知らない provider で `Challenge` が例外を出し、500 になっていた。**"
                    + "**登録されている provider かを確かめてから始める**ようにした（両版）。",
                    "#294（AccountController.*.cs のレビュー B4）");

                r.Target("provider = \"Bogus\"");

                HttpResponseMessage login = await client.GetAsync("/Account/Login");
                string loginHtml = await login.Content.ReadAsStringAsync();

                HttpResponseMessage post = await client.PostFormAsync("/Account/ExternalLogin", new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", Html.Antiforgery(loginHtml) },
                    { "provider", "Bogus" }
                });

                string location = (post.Headers.Location == null) ? "" : post.Headers.Location.ToString();

                r.Verify("**500 にならない**", (int)post.StatusCode < 500,
                    "500 未満", "HTTP " + (int)post.StatusCode);

                r.Verify("**サインイン画面へ戻す**",
                    location.Contains("/Account/Login"),
                    "/Account/Login へ", string.IsNullOrEmpty(location) ? "HTTP " + (int)post.StatusCode : location);

                r.Done();
            }
        }

        #region 補助

        /// <summary>サイトの中のパスを、パス ベースも含めた形にする</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="path">/ 始まりのパス</param>
        /// <returns>パス</returns>
        private static string LocalPath(IdPClient client, string path)
        {
            return new Uri(client.Target.Url(path)).AbsolutePath;
        }

        /// <summary>URL のパスの部分（相対でも絶対でも）</summary>
        /// <param name="url">URL</param>
        /// <returns>パス（無ければ null）</returns>
        private static string PathOf(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return null;
            }

            Uri uri = new Uri(url, UriKind.RelativeOrAbsolute);

            return uri.IsAbsoluteUri ? uri.AbsolutePath : url.Split('?')[0];
        }

        #endregion
    }
}
