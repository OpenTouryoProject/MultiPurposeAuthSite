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
//* クラス名        ：JwksUriTests
//* クラス日本語名  ：RT-309 クライアントの鍵を jwks_uri から引く
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#309 の段階 1）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-309 クライアントの鍵を `jwks_uri` から引く（#309 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **`jwks`（鍵そのもの）は受け付けていたが、`jwks_uri` は断っていた**（#307 の段階 3）。
    /// **`jwks_uri` は、RP が鍵を入れ替えても登録を直さなくてよくするための項目**である。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-309.1`** | **動的登録で `jwks_uri` を登録でき、その URL の鍵で `private_key_jwt` が通る**（**`jwks` との併記は `400`**／**読めない URL は `400`**） |
    /// | **`RT-309.2`** | **画面から登録した `jwks_uri`**（**取りに行っていない**）**は、1 回目に断られ、背景で補充された後は通る** |
    /// | **`RT-309.3`** | **同じ URL の鍵を入れ替えると、`PUT` で読み直して新しい鍵で通る**（**読み直すまではキャッシュが効く**） |
    /// | **`RT-309.4`** | **`software_statement` の中だけで主張された `jwks_uri`** でも登録でき、**1 回目のクライアント認証から通る**（**段階 2**。段階 1 では `400` だった） |
    ///
    /// **要求の経路は同期である** — **クライアント認証は `static bool` の鎖**で、
    /// **`/token` / `/par` / `/ciba_authz` / `/revoke` / `/introspect` の全部から呼ばれる。
    /// そこで取得を待つと net48 で止まる**（継続が同期コンテキストへ戻れない）ので、
    /// **要求ではキャッシュを読むだけ**にしてある（#309 の決め (A)）。
    ///
    /// | 取りに行くのは | |
    /// |---|---|
    /// | **登録のとき**（`POST` / `PUT`） | **あの口は `async`**。**取れなければ登録を断る**（決め (B)） |
    /// | **背景**（要求で引けなかったとき） | **その 1 本は断り、次の試行で通す**（決め (C)(1)） |
    ///
    /// **測るのは `/revoke`** である（`RT-309.2` / `.3`）。
    /// **クライアント認証だけを通る口**なので、**鍵の出どころだけを見られる**
    /// （RFC 7009 §2.1 は「トークン エンドポイントと同じクライアント認証」を求めている。
    /// **知らないトークンは成功**＝ `200`。RFC 7009 §2.2）。
    ///
    /// **相手の `jwks_uri` は、静的配信のコンテナで用意する**（`Infrastructure.JwksUri`。44305）。
    /// **上がっていなければ Skip する** — **既定の通しでは Skip になる。**
    /// </remarks>
    public class JwksUriTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public JwksUriTests(ITestOutputHelper output) : base(output) { }

        /// <summary>登録する折り返し先</summary>
        private const string UriA = "https://localhost:44300/e2e/rt309/a";

        #region RT-309.1

        /// <summary>RT-309.1 動的登録で jwks_uri を登録すると、その URL の鍵で認証できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30901_jwks_uriを登録するとその鍵で認証できる(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-309.1",
                    "動的登録で `jwks_uri` を登録でき、**その URL に置いた鍵**の "
                    + "`client_assertion` で `/token` が通る",
                    "**`jwks_uri` は断っていた**（#307 の段階 3）。"
                    + "**受け取って無視すると `private_key_jwt` が黙って通らなくなる**ので、"
                    + "**断る方に倒していた。** **`jwks`（鍵そのもの）だけが使えたため、"
                    + "RP は鍵を入れ替えるたびに登録を直す必要があった** — "
                    + "**`jwks_uri` が在れば、置いてある鍵を替えるだけで済む。**",
                    "RFC 7591 §2 / RFC 7523 §2.2 / #309 の段階 1");

                r.Target("POST registration_endpoint（jwks_uri）→ POST /token（client_assertion）");

                string name = "rt309_1_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) 相手の JWK Set を、その URL に置く");

                        JwksUri.Write(name, JwsSigner.PublicRsaJwk(client));

                        r.Observe("jwks_uri", JwksUri.Url(name));

                        r.Note("**本来この URL は RP が公開する。** "
                            + "**E2E のクライアントは HTTP サーバを持たない**ので、"
                            + "**静的配信のコンテナ（44305）に置いている**（#309 の決め (H)）。");

                        r.Step("(2) jwks_uri ＋ token_endpoint_auth_method=private_key_jwt で登録する");

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid email\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\"}");

                        r.VerifyEqual("HTTP の状態は 201", "201",
                            ((int)created.StatusCode).ToString());

                        string clientId = created.String("client_id");

                        Assert.False(string.IsNullOrEmpty(clientId),
                            "前提: client_id が返ること（" + created.ToString() + "）");

                        r.VerifyEqual("応答に jwks_uri が返る", JwksUri.Url(name),
                            created.String("jwks_uri") ?? "（無い）");

                        r.VerifyEqual("応答に jwks は返らない（排他）", "False",
                            (created.IsJson && created.Json.TryGetProperty(
                                "jwks", out JsonElement _)).ToString());

                        r.Step("(3) その URL の鍵の client_assertion で、認可コードを交換する");

                        ClientRegistration reg = new ClientRegistration()
                        {
                            ClientId = clientId,
                            ClientSecret = created.String("client_secret"),
                            RedirectUri = UriA
                        };

                        AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-309", "nonce-309", UriA);

                        Assert.False(string.IsNullOrEmpty(authz.Code),
                            "前提: 認可コードが取れること（error=" + (authz.Error ?? "なし") + "）");

                        JsonResponse byAssertion = await client.TokenAsync(
                            JwksUriTests.WithAssertion(client, clientId,
                                new Dictionary<string, string>()
                                {
                                    { "grant_type", "authorization_code" },
                                    { "code", authz.Code },
                                    { "redirect_uri", UriA }
                                }));

                        r.VerifyEqual("HTTP の状態は 200", "200",
                            ((int)byAssertion.StatusCode).ToString());

                        r.Verify("access_token が返る",
                            !string.IsNullOrEmpty(byAssertion.AccessToken),
                            "返る", string.IsNullOrEmpty(byAssertion.AccessToken)
                                ? "**返らない**（" + byAssertion.ToString() + "）"
                                : "返った（値は伏せる）");

                        r.Note("**鍵は列に無い** — **この認証は、URL から引いた鍵で通っている。**");

                        r.Step("(4) jwks と jwks_uri の併記は 400（RFC 7591 §2 の MUST NOT）");

                        JsonResponse both = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\","
                            + "\"jwks\":{\"keys\":[" + JwsSigner.PublicRsaJwk(client) + "]}}");

                        r.VerifyEqual("HTTP の状態は 400", "400",
                            ((int)both.StatusCode).ToString());

                        r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                            both.String("error") ?? "（無い）");

                        r.Step("(5) 読めない jwks_uri は 400（登録のその場で断る）");

                        JsonResponse unreadable = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name + "_missing") + "\"}");

                        r.VerifyEqual("HTTP の状態は 400", "400",
                            ((int)unreadable.StatusCode).ToString());

                        r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                            unreadable.String("error") ?? "（無い）");

                        r.Note("**登録の口は `async` なので、ここでは取りに行って待てる**（決め (B)）。"
                            + "**後から黙って `private_key_jwt` が通らなくなるより、"
                            + "登録のその場で分かる方が良い。**");
                    }
                    finally
                    {
                        //  **置いたものは、同じテストの中で消す**（#308 の段階 3 で踏んだこと）。
                        JwksUri.Delete(name);
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-309.2

        /// <summary>RT-309.2 画面から登録した jwks_uri は、1 回目に断られ、その後は通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30902_取りに行っていないjwks_uriは1回目に断られる(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                TestReport r = this.Report("RT-309.2",
                    "**画面から登録した `jwks_uri`**（**まだ取りに行っていない**）**は、"
                    + "1 回目のクライアント認証で断られ、背景で補充された後は通る**",
                    "**要求の経路ではキャッシュを読むだけ**にしてある（#309 の決め (A)）。"
                    + "**クライアント認証は同期の鎖**で、**そこで取得を待つと net48 で止まる** — "
                    + "**継続が `AspNetSynchronizationContext` へ Post され、"
                    + "その順番を握っているのは待っている自分**だからである。"
                    + "**キャッシュはプロセスの中に在る**ので、"
                    + "**画面から登録した直後・再起動の直後は、空である。**"
                    + "**そのときは断って、背景で取り直す**（決め (C)(1)）。",
                    "#309 の段階 1 / RFC 7009 §2.1 / RemoteJwkSetStore.RefillInBackground");

                r.Target("POST /revoke（client_assertion。鍵は画面で登録した jwks_uri の先）");

                string name = "rt309_2_" + targetKey;
                string user = "e2e_rt309_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string password = admin.Config.Get("TestUserPWD");

                //  **`Admin` で作る** — **クライアント登録の画面は
                //    `SystemAdmin` か `Admin` でなければ開かない**（`ManageController`）。
                Assert.True(JwksUriTests.IsRedirect(await UsersAdmin.CreateAsync(
                    admin, user, user + "@example.com", "Admin")),
                    "前提: 使い捨ての利用者を作れること");

                try
                {
                    r.Step("(1) 相手の JWK Set を、その URL に置く");

                    JwksUri.Write(name, JwsSigner.PublicRsaJwk(admin));

                    r.Observe("jwks_uri", JwksUri.Url(name));

                    r.Note("**この URL は、この回のテストでしか使わない名前にしてある** — "
                        + "**キャッシュはプロセスの中で URL ごと**なので、"
                        + "**他のケースと同じ URL では「空の状態」を測れない。**");

                    using (IdPClient client = this.Client(targetKey))
                    {
                        Assert.True(await client.TrySignInAsync(user, password),
                            "前提: 使い捨ての利用者でサインインできること");

                        r.Step("(2) 画面から、jwks_uri ＋ private_key_jwt で登録する");

                        (string ClientId, string ClientSecret) registered =
                            await ManageClientRegistration.RegisterWithSecretAsync(client,
                                new Dictionary<string, string>()
                                {
                                    { "RedirectUriCode", UriA },
                                    { "JwksUri", JwksUri.Url(name) },
                                    { "TokenEndpointAuthMethod", "private_key_jwt" }
                                });

                        Assert.False(string.IsNullOrEmpty(registered.ClientId),
                            "前提: 画面からクライアントを登録できること");

                        r.Note("**画面は取りに行かない** — "
                            + "**動的登録の口だけが、登録の前に 1 回取りに行く**（決め (B)）。");

                        r.Step("(3) 1 回目のクライアント認証は断られる（キャッシュが空）");

                        JsonResponse first = await client.RevokeAsync(
                            JwksUriTests.WithAssertion(client, registered.ClientId,
                                new Dictionary<string, string>()
                                {
                                    { "token", "e2e-rt309-unknown-token" }
                                }));

                        r.VerifyEqual("error は invalid_client", "invalid_client",
                            first.String("error") ?? "（無い）");

                        r.Observe("HTTP の状態", ((int)first.StatusCode).ToString());

                        r.Step("(4) 背景で補充された後は通る（再試行する）");

                        Stopwatch sw = Stopwatch.StartNew();
                        JsonResponse retried = null;
                        int attempts = 0;

                        for (int i = 0; i < 20; i++)
                        {
                            attempts = i + 1;

                            await Task.Delay(250);

                            retried = await client.RevokeAsync(
                                JwksUriTests.WithAssertion(client, registered.ClientId,
                                    new Dictionary<string, string>()
                                    {
                                        { "token", "e2e-rt309-unknown-token" }
                                    }));

                            if (string.IsNullOrEmpty(retried.String("error")))
                            {
                                break;
                            }
                        }

                        sw.Stop();

                        r.Verify("再試行すると通る",
                            retried != null && string.IsNullOrEmpty(retried.String("error")),
                            "通る", (retried == null)
                                ? "**1 回も試せていない**"
                                : (string.IsNullOrEmpty(retried.String("error"))
                                    ? "通った" : "**" + retried.String("error") + "**"));

                        r.VerifyEqual("HTTP の状態は 200（知らないトークンは成功。RFC 7009 §2.2）",
                            "200", (retried == null)
                                ? "（無い）" : ((int)retried.StatusCode).ToString());

                        r.Observe("通るまでの試行", attempts.ToString() + " 回 / "
                            + sw.ElapsedMilliseconds.ToString() + " ミリ秒");

                        r.Note("**1 回断られることは、仕様である**（#309 の決め (C)(1)）。"
                            + "**起動時に登録済みの `jwks_uri` を温める形は段階 2** — "
                            + "**温めが間に合わない窓は、どちらにしても残る**ので、"
                            + "**先にこの振る舞いを決めてある。**");
                    }
                }
                finally
                {
                    JwksUri.Delete(name);

                    //  **利用者を消すと、その人の登録も消える**（cascade。#307 の段階 5-a-1）。
                    await UsersAdmin.DeleteByUserNameAsync(admin, user);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-309.3

        /// <summary>RT-309.3 同じ URL の鍵を入れ替えると、PUT で読み直す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30903_同じURLの鍵を入れ替えるとPUTで読み直す(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-309.3",
                    "**同じ `jwks_uri` の中身を入れ替える**と、**`PUT` で読み直して"
                    + "新しい鍵で認証でき、古い鍵では認証できなくなる**",
                    "**これが `jwks_uri` の存在理由**である — "
                    + "**鍵を入れ替えても、登録のメタデータを書き換えずに済む。**"
                    + "**登録の時点で 1 回引いて列に焼く形**（起票時の案 (c)）**では、"
                    + "この性質が消える**ので、**「対応した」と言えない。**",
                    "RFC 7591 §2 / #309 の段階 1 / RemoteJwkSetStore.WarmUpAsync");

                r.Target("POST /revoke（client_assertion）→ PUT registration_client_uri");

                string name = "rt309_3_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) RSA の鍵を置いて登録し、その鍵で認証できることを見る");

                        JwksUri.Write(name, JwsSigner.PublicRsaJwk(client));

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid email\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\"}");

                        string clientId = created.String("client_id");
                        string clientUri = created.String("registration_client_uri");
                        string clientToken = created.String("registration_access_token");

                        Assert.False(string.IsNullOrEmpty(clientId),
                            "前提: client_id が返ること（" + created.ToString() + "）");
                        Assert.False(string.IsNullOrEmpty(clientUri),
                            "前提: registration_client_uri が返ること");

                        JsonResponse byRsa = await JwksUriTests.RevokeAsync(
                            client, clientId, false);

                        r.VerifyEqual("RSA の鍵で通る（error は無い）", "（無い）",
                            byRsa.String("error") ?? "（無い）");

                        r.Step("(2) 置いてある鍵を EC に入れ替える（登録は触らない）");

                        JwksUri.Write(name, JwsSigner.PublicEcJwk(client));

                        JsonResponse stillRsa = await JwksUriTests.RevokeAsync(
                            client, clientId, false);

                        r.VerifyEqual("まだ RSA の鍵で通る（キャッシュが効いている）", "（無い）",
                            stillRsa.String("error") ?? "（無い）");

                        r.Note("**取り直しの下限は 1 分**（`RemoteJwkSetStore.MinRefetchInterval`）。"
                            + "**`kid` を偽った要求を並べれば、外から取得を起こせる**ので、"
                            + "**背景の補充には下限を置いてある。**"
                            + "**何もしなくても、最大でその下限ぶんで追随する** — "
                            + "**E2E では 1 分待たない**ので、ここは `PUT` で測る。");

                        r.Step("(3) PUT で同じ jwks_uri を出し直すと、読み直す");

                        JsonResponse updated = await DynamicClientRegistration.UpdateAsync(
                            client, clientUri, clientToken,
                            "{\"client_id\":\"" + clientId + "\","
                            + "\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid email\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\"}");

                        r.VerifyEqual("HTTP の状態は 200", "200",
                            ((int)updated.StatusCode).ToString());

                        JsonResponse oldKey = await JwksUriTests.RevokeAsync(
                            client, clientId, false);

                        r.VerifyEqual("古い鍵（RSA）では通らなくなる", "invalid_client",
                            oldKey.String("error") ?? "（無い）");

                        JsonResponse newKey = await JwksUriTests.RevokeAsync(
                            client, clientId, true);

                        r.VerifyEqual("新しい鍵（EC / ES256）で通る", "（無い）",
                            newKey.String("error") ?? "（無い）");

                        r.Note("**登録の口は、取り直しの下限を見ない**（**毎回取りに行く**）。"
                            + "**認可が要り**（専用 scope のトークン）**レート制限も掛かっている**ので、"
                            + "**外から叩く経路にはならない。**"
                            + "**鍵を入れ替えた相手は、`PUT` でその場で反映できる。**");
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

        #region RT-309.4

        /// <summary>RT-309.4 software_statement が主張した jwks_uri でも登録できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30904_statementが主張したjwks_uriでも登録できる(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-309.4",
                    "**`software_statement` の中だけで主張された `jwks_uri`** でも登録でき、"
                    + "**その URL の鍵で、1 回目のクライアント認証から通る**",
                    "**段階 1 では断っていた** — **「署名を検証する前に、本文の外の URL へ"
                    + "出て行かない」**という理由だったが、**過剰だった。**"
                    + "**同じ呼び出し元は、本文の `jwks_uri` に任意の URL を書ける**"
                    + "（段階 1 で既に取りに行く）ので、**statement の中に書いても、"
                    + "行き先の範囲は変わらない。** "
                    + "**キャッシュは信頼ではない** — **URL → 鍵の対応**でしかなく、"
                    + "**statement の検証が落ちれば登録は作られない**ので、"
                    + "**温めた分は誰にも使われない。**",
                    "RFC 7591 §2.3 / #309 の段階 2");

                r.Target("POST registration_endpoint（statement が jwks_uri を主張する）");

                JwksUriTests.SkipIfNoSoftwareStatement();

                string name = "rt309_4_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) 相手の JWK Set を置き、statement だけが jwks_uri を主張する");

                        JwksUri.Write(name, JwsSigner.PublicRsaJwk(client));

                        Dictionary<string, object> claims = JwksUriTests.StatementClaims();

                        claims.Add("jwks_uri", JwksUri.Url(name));

                        string statement = JwsSigner.SignRS256(client, claims);

                        //  **本文には `jwks_uri` を書かない**（**ここが段階 2 の論点**）。
                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"software_statement\":\"" + statement + "\"}");

                        r.VerifyEqual("HTTP の状態は 201", "201",
                            ((int)created.StatusCode).ToString());

                        string clientId = created.String("client_id");

                        Assert.False(string.IsNullOrEmpty(clientId),
                            "前提: client_id が返ること（" + created.ToString() + "）");

                        r.VerifyEqual("応答に jwks_uri が返る（statement の値）",
                            JwksUri.Url(name), created.String("jwks_uri") ?? "（無い）");

                        r.Note("**段階 1 では `400` ＋ `invalid_client_metadata`"
                            + "（`The jwks_uri could not be read.`）だった** — "
                            + "**本文の値しか温めていなかった**ためである。");

                        r.Step("(2) 1 回目のクライアント認証から通る（登録のときに温めてある）");

                        JsonResponse first = await JwksUriTests.RevokeAsync(
                            client, clientId, false);

                        r.VerifyEqual("error は無い（1 回目から通る）", "（無い）",
                            first.String("error") ?? "（無い）");

                        r.VerifyEqual("HTTP の状態は 200"
                            + "（知らないトークンは成功。RFC 7009 §2.2）",
                            "200", ((int)first.StatusCode).ToString());

                        r.Note("**`jwks` を 1 本も登録していない** — "
                            + "**`private_key_jwt` の「材料」として `jwks_uri` を数えている**"
                            + "（#309 の段階 1）。");
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

        #region 私的なヘルパ

        /// <summary>リダイレクトか（画面の成功）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(System.Net.Http.HttpResponseMessage res)
        {
            int status = (int)res.StatusCode;

            return 300 <= status && status < 400;
        }

        /// <summary>この配備が statement の発行者を設定していなければ Skip する</summary>
        /// <remarks>
        /// **`ClientRegistrationTests` と同じしるし**（`MPAS_SOFTWARE_STATEMENT_ISS`）を見る。
        /// **あちらは `private`** なので、**ここにも置いてある** —
        /// **しるしの名前だけは、必ず同じ値を使うこと**（**サイトへ渡した値と食い違わせない**）。
        /// </remarks>
        private static void SkipIfNoSoftwareStatement()
        {
            Skip.If(string.IsNullOrEmpty(
                Environment.GetEnvironmentVariable("MPAS_SOFTWARE_STATEMENT_ISS")),
                "この配備は software_statement の発行者を設定していません"
                + "（test.ps1 -Launch が、SpRp_RsaPfxFilePath と対の .cer を渡す。#307 の段階 4）。");
        }

        /// <summary>statement の最小のクレーム</summary>
        /// <returns>クレーム</returns>
        /// <remarks>
        /// **`iss` は必須**（RFC 7591 §2.3）。**`exp` / `aud` は入れない**（任意）。
        /// **`scope` は主張しない** — **発行者ごとの上限（#307 の段階 6）に当たらないため**で、
        /// **本文の `scope` が、そのまま登録の値になる。**
        /// </remarks>
        private static Dictionary<string, object> StatementClaims()
        {
            return new Dictionary<string, object>()
            {
                {
                    "iss",
                    Environment.GetEnvironmentVariable("MPAS_SOFTWARE_STATEMENT_ISS") ?? ""
                },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                { "software_id", "e2e-rt309" },
                { "software_version", "1.0.0" }
            };
        }

        /// <summary>`/revoke` を、client_assertion で叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="es256">true なら ES256（EC の鍵）で署名する</param>
        /// <returns>JsonResponse</returns>
        /// <remarks>
        /// **知らないトークンを渡す** — **クライアント認証だけを見たい**ためである
        /// （**認証が通れば `200`**。RFC 7009 §2.2 : 無効なトークンはエラーにしない）。
        /// </remarks>
        private static Task<JsonResponse> RevokeAsync(
            IdPClient client, string clientId, bool es256)
        {
            return client.RevokeAsync(JwksUriTests.WithAssertion(client, clientId,
                new Dictionary<string, string>()
                {
                    { "token", "e2e-rt309-unknown-token" }
                }, es256));
        }

        /// <summary>client_assertion（`private_key_jwt`）を足す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id（`iss` ＝ `sub`。RFC 7523 §3）</param>
        /// <param name="items">送る項目</param>
        /// <param name="es256">true なら ES256（EC の鍵）で署名する</param>
        /// <returns>送る項目（アサーション入り）</returns>
        /// <remarks>
        /// **`aud` はトークン エンドポイント**である（実装が照合している）。
        /// **`/revoke` を叩くときも、`aud` はトークン エンドポイントのまま** —
        /// **RFC 7009 §2.1 が「同じクライアント認証」と定めている**ためである。
        ///
        /// **ヘッダに `kid` は入れない**（RFC 7515 §4.1.4 は任意）。
        /// **実装は、`kid` が無ければ JWK Set に在る鍵を順に試す**（上限あり）。
        /// </remarks>
        private static Dictionary<string, string> WithAssertion(
            IdPClient client, string clientId,
            IDictionary<string, string> items, bool es256 = false)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            };

            return new Dictionary<string, string>(items)
            {
                {
                    "client_assertion",
                    es256 ? JwsSigner.SignES256(client, payload)
                          : JwsSigner.SignRS256(client, payload)
                },
                {
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                }
            };
        }

        /// <summary>動的登録を使えるようにして、本体を回す</summary>
        /// <param name="admin">管理者の IdPClient</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="body">本体（client / registration_endpoint / 専用トークン）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **使い捨ての利用者を 1 人作り、その人に管理 API 用のクライアントを登録する。**
        /// **その資格で専用 scope のトークンを取り、そのトークンで動的登録を叩く。**
        /// **終わったら利用者を消す** — **その人の登録も一緒に消える**（cascade）。
        ///
        /// **ROPC と動的登録の両方が開いている配備でしか測れない**（開いていなければ Skip）。
        /// </remarks>
        private async Task WithDcrAsync(
            IdPClient admin, string targetKey, Func<IdPClient, string, string, Task> body)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);
            await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "password");

            string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

            string user = "e2e_rt309_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string password = admin.Config.Get("TestUserPWD");

            //  **`Admin` で作る**（クライアント登録の画面を使う）。
            Assert.True(JwksUriTests.IsRedirect(await UsersAdmin.CreateAsync(
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
                                //  **`GrantTypes` は絞らない** — **絞ると `ResponseTypes` との
                                //    噛み合いを画面が見る**ので、**ROPC だけを登録できない。**
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
