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
//* クラス名        ：SectorIdentifierTests
//* クラス日本語名  ：RT-364 動的登録の sector_identifier_uri
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/12  玄人 幸道         新規（#364）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-364 動的登録の `sector_identifier_uri`（#364）。
    /// </summary>
    /// <remarks>
    /// **以前は、`sector_identifier_uri` を確かめずに登録し（`201`）、値も捨てていた**
    /// （適合性テストの `oidcc-registration-sector-bad`）。
    ///
    /// **OIDC Registration 1.0 §5**：OP は `sector_identifier_uri` を取りに行き、
    /// **中身（JSON の配列）に、登録する `redirect_uris` がすべて含まれていることを確かめる。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-364.1`** | **中身に `redirect_uris` がすべて在れば、登録できる**（`201`） |
    /// | **`RT-364.2`** | **1 つでも無ければ、`400` ＋ `invalid_client_metadata`** |
    /// | **`RT-364.3`** | **読めなければ（取れない・配列でない・文字列でない要素・`https` でない）、`400` ＋ `invalid_client_metadata`** |
    ///
    /// **相手の `sector_identifier_uri` は、`jwks_uri` と同じ静的配信のコンテナで用意する**（`Infrastructure.JwksUri`。44305）。
    /// **上がっていなければ Skip する。**
    /// **平文の http で配っている**が、**ループバックだけは `http` を許している**（`jwks_uri` と同じ扱い）。
    /// </remarks>
    public class SectorIdentifierTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SectorIdentifierTests(ITestOutputHelper output) : base(output) { }

        /// <summary>登録する折り返し先（1）</summary>
        private const string UriA = "https://localhost:44300/e2e/rt364/a";

        /// <summary>登録する折り返し先（2）</summary>
        private const string UriB = "https://localhost:44300/e2e/rt364/b";

        /// <summary>根拠</summary>
        private const string Basis = "OIDC Registration 1.0 §5 / #364";

        #region RT-364.1

        /// <summary>RT-364.1 中身に redirect_uris がすべて在れば、登録できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36401_sector_identifier_uriにredirect_urisが在れば登録できる(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-364.1",
                    "動的登録で `sector_identifier_uri` を付け、**その中身（JSON の配列）に `redirect_uris` がすべて在れば**、登録できる",
                    "**OP は `sector_identifier_uri` を取りに行き、登録する `redirect_uris` がすべて含まれることを確かめる**（§5）。"
                    + "**含まれていれば登録する**（一覧に、登録しない URI が余分に在ってもよい）。",
                    SectorIdentifierTests.Basis);

                r.Target("POST registration_endpoint（sector_identifier_uri ＋ redirect_uris）");

                string name = SectorIdentifierTests.NameOf("rt364_1", targetKey);

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) redirect_uris の 2 つと、余分な 1 つを並べた配列を、その URL に置く");

                        JwksUri.WriteRaw(name, "[\"" + UriA + "\",\"" + UriB + "\",\"https://localhost:44300/e2e/rt364/extra\"]");

                        r.Observe("sector_identifier_uri", JwksUri.Url(name));

                        r.Step("(2) redirect_uris に 2 つを入れ、sector_identifier_uri を付けて登録する");

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            SectorIdentifierTests.Body(JwksUri.Url(name), UriA, UriB));

                        r.VerifyEqual("HTTP の状態は 201", "201",
                            ((int)created.StatusCode).ToString());

                        r.Verify("client_id が返る",
                            !string.IsNullOrEmpty(created.String("client_id")),
                            "返る", string.IsNullOrEmpty(created.String("client_id"))
                                ? "**返らない**（" + created.ToString() + "）" : "返った");
                    }
                    finally
                    {
                        JwksUri.Delete(name);
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-364.2

        /// <summary>RT-364.2 中身に redirect_uri が 1 つでも無ければ、400 で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36402_sector_identifier_uriに無いredirect_uriが在れば断る(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-364.2",
                    "`sector_identifier_uri` の中身に、**登録する `redirect_uris` の 1 つが無ければ**、`400` ＋ `invalid_client_metadata` で断る",
                    "**登録する `redirect_uris` は、すべて中身に含まれなければならない**（§5）。"
                    + "**以前は確かめずに `201` で登録していた**（適合性テストの `oidcc-registration-sector-bad`）。"
                    + "**確かめずに受けると、別の RP のホストを名乗れる**（Sector をそのホストにすると、その RP と同じ pairwise の `sub` を得られる。OIDC Core 1.0 §8.1）。",
                    SectorIdentifierTests.Basis);

                r.Target("POST registration_endpoint（sector_identifier_uri に無い redirect_uri）");

                string name = SectorIdentifierTests.NameOf("rt364_2", targetKey);

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) redirect_uris の 1 つ（a）だけを並べた配列を、その URL に置く");

                        JwksUri.WriteRaw(name, "[\"" + UriA + "\"]");

                        r.Step("(2) redirect_uris に a と b を入れて登録する（b は中身に無い）");

                        JsonResponse rejected = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            SectorIdentifierTests.Body(JwksUri.Url(name), UriA, UriB));

                        r.VerifyEqual("HTTP の状態は 400", "400",
                            ((int)rejected.StatusCode).ToString());

                        r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                            rejected.String("error") ?? "（無い）");

                        r.Observe("error_description", rejected.String("error_description") ?? "（無い）");

                        r.Step("(3) 同じ中身で、redirect_uris を a だけにすれば登録できる（取りに行った中身で判定している）");

                        JsonResponse accepted = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            SectorIdentifierTests.Body(JwksUri.Url(name), UriA));

                        r.VerifyEqual("HTTP の状態は 201", "201",
                            ((int)accepted.StatusCode).ToString());
                    }
                    finally
                    {
                        JwksUri.Delete(name);
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-364.3

        /// <summary>RT-364.3 読めない sector_identifier_uri は、400 で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36403_読めないsector_identifier_uriは断る(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-364.3",
                    "`sector_identifier_uri` が**読めなければ**（取れない・配列でない・文字列でない要素・`https` でない）、`400` ＋ `invalid_client_metadata` で断る",
                    "**中身は `redirect_uri` の値を並べた JSON の配列で、URL は `https`**（§5）。"
                    + "**確かめられないものは、含まれていると見なさない。**"
                    + "**ループバックだけは `http` を許す**（`jwks_uri` と同じ扱い。RFC 8252 §7.3）。",
                    SectorIdentifierTests.Basis);

                r.Target("POST registration_endpoint（読めない sector_identifier_uri）");

                string name = SectorIdentifierTests.NameOf("rt364_3", targetKey);

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        //  **置くもの（名前・中身）と、登録に書く URL。** 名前が null なら置かない。
                        List<(string Label, string File, string Content, string Url)> cases
                            = new List<(string, string, string, string)>()
                        {
                            ("(1) 置いていない URL（404）",
                                null, null, JwksUri.Url(name + "_missing")),
                            ("(2) 配列でない（オブジェクト）",
                                name + "_object", "{\"redirect_uris\":[\"" + UriA + "\"]}", JwksUri.Url(name + "_object")),
                            ("(3) 文字列でない要素が在る",
                                name + "_number", "[\"" + UriA + "\",1]", JwksUri.Url(name + "_number")),
                            ("(4) https でない（ループバックでもない http）",
                                null, null, "http://sector.e2e.invalid/" + name + ".json")
                        };

                        foreach (var c in cases)
                        {
                            r.Step(c.Label);

                            if (c.File != null)
                            {
                                JwksUri.WriteRaw(c.File, c.Content);
                            }

                            JsonResponse rejected = await DynamicClientRegistration.RegisterAsync(
                                client, endpoint, token,
                                SectorIdentifierTests.Body(c.Url, UriA));

                            r.VerifyEqual(c.Label + "：HTTP の状態は 400", "400",
                                ((int)rejected.StatusCode).ToString());

                            r.VerifyEqual(c.Label + "：error は invalid_client_metadata", "invalid_client_metadata",
                                rejected.String("error") ?? "（無い）");
                        }
                    }
                    finally
                    {
                        JwksUri.Delete(name + "_object");
                        JwksUri.Delete(name + "_number");
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>回ごとに別の名前にする（同じサイトに回し直しても、前の回の控えに当たらないように）</summary>
        /// <param name="prefix">接頭辞</param>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>名前</returns>
        private static string NameOf(string prefix, string targetKey)
        {
            return prefix + "_" + targetKey + "_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>登録の本文</summary>
        /// <param name="sectorIdentifierUri">sector_identifier_uri</param>
        /// <param name="redirectUris">redirect_uris</param>
        /// <returns>JSON</returns>
        private static string Body(string sectorIdentifierUri, params string[] redirectUris)
        {
            return "{\"redirect_uris\":[\"" + string.Join("\",\"", redirectUris) + "\"],"
                + "\"scope\":\"openid\","
                + "\"subject_type\":\"pairwise\","
                + "\"sector_identifier_uri\":\"" + sectorIdentifierUri + "\"}";
        }

        /// <summary>リダイレクトか（画面の成功）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(System.Net.Http.HttpResponseMessage res)
        {
            int status = (int)res.StatusCode;

            return 300 <= status && status < 400;
        }

        /// <summary>動的登録を使えるようにして、本体を回す</summary>
        /// <param name="admin">管理者の IdPClient</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="body">本体（client / registration_endpoint / 専用トークン）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`JwksUriTests.WithDcrAsync` と同じ手順**（使い捨ての利用者に管理 API 用のクライアントを登録し、
        /// その資格で専用 scope のトークンを取る。終わったら利用者を消す。その人の登録も一緒に消える）。
        /// **ROPC と動的登録の両方が開いている配備でしか測れない**（開いていなければ Skip）。
        /// </remarks>
        private async Task WithDcrAsync(
            IdPClient admin, string targetKey, Func<IdPClient, string, string, Task> body)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);
            await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "password");

            string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

            string user = "e2e_rt364_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string password = admin.Config.Get("TestUserPWD");

            Assert.True(SectorIdentifierTests.IsRedirect(await UsersAdmin.CreateAsync(
                admin, user, user + "@example.com", "Admin")),
                "前提: 使い捨ての利用者を作れること");

            try
            {
                using (IdPClient client = this.Client(targetKey))
                {
                    Assert.True(await client.TrySignInAsync(user, password),
                        "前提: 使い捨ての利用者でサインインできること");

                    (string ClientId, string ClientSecret) registered =
                        await ManageClientRegistration.RegisterWithSecretAsync(client,
                            new Dictionary<string, string>()
                            {
                                { "Scopes", DynamicClientRegistration.Scope }
                            });

                    Assert.False(string.IsNullOrEmpty(registered.ClientId),
                        "前提: 管理 API 用のクライアントを登録できること");

                    JsonResponse token = await DynamicClientRegistration.TokenAsync(
                        client, registered.ClientId, registered.ClientSecret, user, password);

                    string accessToken = token.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: 専用 scope のトークンが取れること"
                        + "（error=" + (token.String("error") ?? "なし") + "）");

                    await body(client, endpoint, accessToken);
                }
            }
            finally
            {
                await UsersAdmin.DeleteByUserNameAsync(admin, user);
            }
        }

        #endregion
    }
}
