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
//*  2026/11/12  玄人 幸道         RT-363.1（登録を直さずに鍵を入れ替えても、知らない kid の 1 回目から通る）を足した（#363）
//*  2026/11/17  玄人 幸道         client_assertion の aud を issuer にした（クライアント認証は issuer だけを受ける。RFC 10070 §4。#398）
//*  2026/11/18  玄人 幸道         RT-376.1（内部のアドレスの jwks_uri は、取りに行かずに断る）を足した（#376）
//*  2026/11/18  玄人 幸道         RT-375.1（1MB を超える jwks_uri の応答は読まない）を足した（#375）
//*  2026/11/19  玄人 幸道         RT-374.1（動的登録の request_uris）を足した（#374）
//*  2026/11/19  玄人 幸道         RT-374.2（登録した外部の request_uri を取りに行って使う）を足した（#374）
//*  2026/11/19  玄人 幸道         RT-374.2 で、預けた urn: の認可の URL への送り直しを確かめるようにした（#374）
//*  2026/11/19  玄人 幸道         RT-374.2 で、預けた urn: の認可の URL への送り直しを確かめるようにした（#374）
//*  2026/11/19  玄人 幸道         RT-408.1・.2（jwks_uri の鍵で Request Object・CIBA の署名した要求を検証する）を足した（#408）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Text;
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
    /// | **`RT-309.2`** | **画面から登録した `jwks_uri`**（**取りに行っていない**）**は、1 回目に断られ、背景で補充された後は通る**（**`kid` の無い assertion**。#363 の後も同じ） |
    /// | **`RT-309.3`** | **同じ URL の鍵を入れ替えると、`PUT` で読み直して新しい鍵で通る**（**読み直すまではキャッシュが効く**） |
    /// | **`RT-309.4`** | **`software_statement` の中だけで主張された `jwks_uri`** でも登録でき、**1 回目のクライアント認証から通る**（**段階 2**。段階 1 では `400` だった） |
    /// | **`RT-363.1`** | **登録を直さずに `jwks_uri` の鍵を入れ替えても、新しい鍵（ヘッダに知らない `kid`）が 1 回目から通る**（OIDC Core 1.0 §10.1.1 の準用。#363） |
    /// | **`RT-375.1`** | **1MB を超える `jwks_uri` の応答は読まず、登録を `400` で断る**（同じ鍵を小さく置けば登録できる。共有の HttpClient の大きさの上限。#375） |
    /// | **`RT-374.1`** | **動的登録の `request_uris`**（外部の `request_uri` を取りに行ってよい先）を受けて返し、`PUT` で省けば消える。**内部のアドレス・相対の値・6 件以上は `400`**（#374） |
    /// | **`RT-374.2`** | **登録した `request_uris` の外部の `request_uri` は、取りに行って検証し、その Request Object で認可コードまで進む。** 登録していない URL は `request_uri_not_supported`、署名の無いものは `invalid_request_object`、取れないものは `invalid_request_uri`（どれもエラー画面。#374） |
    /// | **`RT-376.1`** | **内部のアドレス（プライベート・リンクローカル・ユニーク ローカル）の `jwks_uri` は、`400` ＋ `invalid_client_metadata`**（取りに行かない。#376） |
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

                        r.Note("**この assertion はヘッダに `kid` を入れない**ので、キャッシュに在る鍵（RSA）を試して通る。"
                            + "**ヘッダに知らない `kid` があれば、その場で取り直して通す**（#363。`RT-363.1`）。"
                            + "**取り直しの下限は 1 分**（`RemoteJwkSetStore.MinRefetchInterval`）— "
                            + "**`kid` を偽った要求を並べれば、外から取得を起こせる**ので、下限を置いてある。"
                            + "ここは `PUT` で読み直す口を測る。");

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

        #region RT-375.1

        /// <summary>RT-375.1 1MB を超える jwks_uri の応答は読まない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37501_1MBを超えるjwks_uriの応答は読まない(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-375.1",
                    "`jwks_uri` の応答が**1MB を超える**と読まず、登録を `400` ＋ `invalid_client_metadata` で断る。**同じ鍵を小さく置けば登録できる**",
                    "**OP が外へ出す要求（共有の HttpClient）に、時間と大きさの上限を掛けた。**"
                    + "**以前は何も設定しておらず（.NET の既定の 100 秒・大きさの上限なし）、大きな応答を返されるとメモリを使われた。**"
                    + "**既定は 30 秒・1MB**（設定 `OutboundHttpTimeoutSeconds`・`OutboundHttpMaxResponseBytes`）。",
                    "設計：OutboundHttpLimits の remarks / RFC 7591 §3.2.2 / #375");

                r.Target("POST registration_endpoint（jwks_uri の応答が 1MB を超える）");

                string name = "rt375_1_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        string body = "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\"}";

                        r.Step("(1) 有効な JWK Set に、使わない項目を足して 1MB を超えさせる");

                        JwksUri.WriteRaw(name, "{\"keys\":[" + JwsSigner.PublicRsaJwk(client) + "],"
                            + "\"e2e_padding\":\"" + new string('x', 1200 * 1024) + "\"}");

                        JsonResponse rejected = await DynamicClientRegistration.RegisterAsync(client, endpoint, token, body);

                        r.VerifyEqual("HTTP の状態は 400", "400", ((int)rejected.StatusCode).ToString());
                        r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                            rejected.String("error") ?? "（無い）");

                        string description = rejected.String("error_description") ?? "";
                        bool unread = description.Contains("could not be read");

                        r.Verify("断る理由は「読めない」", unread,
                            "could not be read", unread ? "could not be read" : "**" + description + "**");

                        r.Step("(2) 対照：同じ鍵を、足した項目なしで置けば登録できる");

                        JwksUri.Write(name, JwsSigner.PublicRsaJwk(client));

                        JsonResponse accepted = await DynamicClientRegistration.RegisterAsync(client, endpoint, token, body);

                        r.VerifyEqual("HTTP の状態は 201", "201", ((int)accepted.StatusCode).ToString());
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

        #region RT-374.1

        /// <summary>RT-374.1 動的登録の request_uris を受けて返し、PUT で省けば消える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37401_動的登録のrequest_urisを受けて返す(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-374.1",
                    "動的登録の `request_uris` を受けて応答と `GET` に返し、`PUT` で省けば消える。内部のアドレス・相対の値・6 件以上は `400` ＋ `invalid_client_metadata`",
                    "**`request_uris` は、認可要求の `request_uri` に使ってよい外部の URL**（OIDC Core 1.0 §6.2）。**OP が取りに行く先なので、`https` と行き先のアドレスを確かめる**（#376）。"
                    + "**`#` を付けた値も受ける**（RP がキャッシュのために付けてよい）。**以前は受けておらず、外部の `request_uri` は使えなかった**（#362）。",
                    "OIDC Registration 1.0 §2 / RFC 7592 §2.2 / #374");

                r.Target("POST・GET・PUT registration_endpoint（request_uris）");

                string uriA = JwksUri.Url("rt374_1_a");
                string uriB = JwksUri.Url("rt374_1_b") + "#v1";

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    r.Step("(1) request_uris に 2 つを入れて登録する（片方は # 付き）");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"request_uris\":[\"" + uriA + "\",\"" + uriB + "\"]}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)created.StatusCode).ToString());
                    r.Verify("応答に request_uris が返る（a）", created.ArrayContains("request_uris", uriA),
                        uriA, string.Join(" ", created.Strings("request_uris") ?? new string[0]));
                    r.Verify("応答に request_uris が返る（# 付きの b）", created.ArrayContains("request_uris", uriB),
                        uriB, string.Join(" ", created.Strings("request_uris") ?? new string[0]));

                    string clientId = created.String("client_id");
                    string clientUri = created.String("registration_client_uri");
                    string clientToken = created.String("registration_access_token");

                    r.Step("(2) GET でも返る（保存されている）");

                    JsonResponse read = await DynamicClientRegistration.ReadAsync(client, clientUri, clientToken);

                    r.Verify("GET の request_uris に a が在る", read.ArrayContains("request_uris", uriA),
                        uriA, string.Join(" ", read.Strings("request_uris") ?? new string[0]));

                    r.Step("(3) PUT で request_uris を省くと消える（全置換）");

                    JsonResponse updated = await DynamicClientRegistration.UpdateAsync(client, clientUri, clientToken,
                        "{\"client_id\":\"" + clientId + "\","
                        + "\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid\"}");

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)updated.StatusCode).ToString());

                    JsonResponse reread = await DynamicClientRegistration.ReadAsync(client, clientUri, clientToken);
                    string[] left = reread.Strings("request_uris") ?? new string[0];

                    r.VerifyEqual("GET の request_uris は無い", "0", left.Length.ToString());

                    r.Step("(4) 断る値");

                    foreach (KeyValuePair<string, string> c in new Dictionary<string, string>()
                    {
                        { "内部のアドレス", "[\"https://10.0.0.1/e2e/rt374\"]" },
                        { "相対の値", "[\"/e2e/rt374\"]" },
                        { "6 件", "[" + string.Join(",", Enumerable.Range(1, 6).Select(i => "\"" + JwksUri.Url("rt374_1_" + i) + "\"")) + "]" }
                    })
                    {
                        JsonResponse rejected = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"request_uris\":" + c.Value + "}");

                        r.VerifyEqual(c.Key + " : HTTP の状態は 400", "400", ((int)rejected.StatusCode).ToString());
                        r.VerifyEqual(c.Key + " : invalid_client_metadata", "invalid_client_metadata",
                            rejected.String("error") ?? "（無い）");
                        r.Observe(c.Key + " : error_description", rejected.String("error_description") ?? "（無い）");
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-374.2

        /// <summary>RT-374.2 登録した外部の request_uri を取りに行って使う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37402_登録した外部のrequest_uriを取りに行って使う(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-374.2",
                    "登録した `request_uris` の外部の `request_uri` は、取りに行って検証し、その Request Object（`state` など）で認可コードまで進む。"
                    + "登録していない URL は `request_uri_not_supported`、署名の無いものは `invalid_request_object`、取れないものは `invalid_request_uri` のエラー画面",
                    "**OP は、`request_uri` の URL から Request Object を取り、署名を検証して使う**（OIDC Core 1.0 §6.2。動的登録を提供する OP の MUST。§15.2）。"
                    + "**取りに行くのは、登録した `request_uris` だけ。** **署名を検証できないものは受けない**（`alg=none` を受けない方針）。"
                    + "**以前は、外部の `request_uri` を取りに行かずに断っていた**（#362）。",
                    "OIDC Core 1.0 §6.2 / OIDC Core 1.0 §3.1.2.6 / OIDC Registration 1.0 §2 / #374");

                r.Target("GET /authorize?client_id=…&request_uri=（静的配信の足場に置いた Request Object の URL）");

                string roName = "rt374_2_ro_" + targetKey;
                string missingName = "rt374_2_missing_" + targetKey;
                string otherName = "rt374_2_other_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) 鍵（jwks）と request_uris を付けて登録する（Request Object の検証鍵は、登録の列の鍵から引く）");

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks\":{\"keys\":[" + JwsSigner.PublicRsaJwk(client) + "]},"
                            + "\"request_uris\":[\"" + JwksUri.Url(roName) + "\",\"" + JwksUri.Url(missingName) + "\"]}");

                        string clientId = created.String("client_id");

                        Assert.False(string.IsNullOrEmpty(clientId), "前提: 登録できること（" + created.ToString() + "）");

                        r.Step("(2) 署名した Request Object を、登録した URL に置き、request_uri で認可する");

                        JwksUri.WriteRaw(roName, await RequestObjectBuilder.CreateAsync(client, clientId,
                            new Dictionary<string, object>()
                            {
                                { "response_type", "code" },
                                { "redirect_uri", UriA },
                                { "scope", "openid" },
                                { "state", "state-rt3742" },
                                { "nonce", "nonce-rt3742" }
                            }));

                        Tuple<AuthZResponse, string> followed = await JwksUriTests.AuthorizeFollowingUrnAsync(client, clientId, JwksUri.Url(roName));
                        AuthZResponse used = followed.Item1;

                        //  **取りに行ったら、預けた `urn:` の認可の URL へ送り直す**（サインイン・再認証の往復で、取りに行き直さない）。
                        r.Verify("預けた urn: の認可の URL へ送り直す", followed.Item2 != null,
                            "urn: へ送り直す", followed.Item2 == null ? "**送り直さない**" : "送り直した");

                        r.Verify("認可コードが返る", !string.IsNullOrEmpty(used.Code),
                            "code あり", string.IsNullOrEmpty(used.Code) ? "**なし**（" + Html.Describe(used.Body) + "）" : "あり");
                        r.VerifyEqual("state は Request Object の値", "state-rt3742", used.State ?? "（無い）");

                        r.Step("(3) 登録していない URL は、取りに行かずに request_uri_not_supported");

                        JwksUri.WriteRaw(otherName, "unused");

                        JwksUriTests.VerifyRefused(r, "登録していない URL",
                            await JwksUriTests.AuthorizeWithRequestUriAsync(client, clientId, JwksUri.Url(otherName)),
                            "request_uri_not_supported");

                        r.Step("(4) 署名の無い Request Object（alg=none）は invalid_request_object");

                        JwksUri.WriteRaw(roName,
                            Base64Url.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"none\"}")) + "."
                            + Base64Url.Encode(Encoding.UTF8.GetBytes(
                                "{\"iss\":\"" + clientId + "\",\"aud\":\"" + await client.IssuerAsync() + "\","
                                + "\"client_id\":\"" + clientId + "\",\"response_type\":\"code\","
                                + "\"redirect_uri\":\"" + UriA + "\",\"scope\":\"openid\",\"state\":\"state-rt3742-none\"}")) + ".");

                        JwksUriTests.VerifyRefused(r, "署名の無いもの",
                            await JwksUriTests.AuthorizeWithRequestUriAsync(client, clientId, JwksUri.Url(roName)),
                            "invalid_request_object");

                        r.Step("(5) 登録した URL でも、取れない（404）なら invalid_request_uri");

                        JwksUriTests.VerifyRefused(r, "取れないもの",
                            await JwksUriTests.AuthorizeWithRequestUriAsync(client, clientId, JwksUri.Url(missingName)),
                            "invalid_request_uri");
                    }
                    finally
                    {
                        JwksUri.Delete(roName);
                        JwksUri.Delete(otherName);
                    }
                });

                r.Done();
            }
        }

        /// <summary>client_id と request_uri だけで認可する（同意が要れば同意する）</summary>
        /// <param name="client">IdPClient（サインイン済み）</param>
        /// <param name="clientId">client_id</param>
        /// <param name="requestUri">request_uri</param>
        /// <returns>AuthZResponse</returns>
        private static async Task<AuthZResponse> AuthorizeWithRequestUriAsync(IdPClient client, string clientId, string requestUri)
        {
            return (await JwksUriTests.AuthorizeFollowingUrnAsync(client, clientId, requestUri)).Item1;
        }

        /// <summary>client_id と request_uri だけで認可し、`urn:` の認可の URL への送り直し（302）を 1 回だけ追う</summary>
        /// <param name="client">IdPClient（サインイン済み）</param>
        /// <param name="clientId">client_id</param>
        /// <param name="requestUri">request_uri</param>
        /// <returns>応答と、送り直された先の `urn:`（送り直しが無ければ null）</returns>
        /// <remarks>**外部の `request_uri` は、預けた `urn:` の認可の URL へ送り直される**（#374。サインインの往復で取りに行き直さないため）。</remarks>
        private static async Task<Tuple<AuthZResponse, string>> AuthorizeFollowingUrnAsync(IdPClient client, string clientId, string requestUri)
        {
            AuthZResponse res = await client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "client_id", clientId },
                { "request_uri", requestUri }
            });

            string urn = null;
            string redirected = (res.Location == null) ? null : Saml2.QueryValue(res.Location, "request_uri");

            if (redirected != null && redirected.StartsWith("urn:", StringComparison.Ordinal))
            {
                urn = redirected;
                res = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", clientId },
                    { "request_uri", urn }
                });
            }

            return Tuple.Create(res.NeedsConsent ? await client.GrantConsentAsync(res) : res, urn);
        }

        /// <summary>エラー画面で断ったことを確かめる（RP へ返さない）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">場合の名前</param>
        /// <param name="res">AuthZResponse</param>
        /// <param name="error">期待する error</param>
        private static void VerifyRefused(TestReport r, string label, AuthZResponse res, string error)
        {
            r.Verify(label + " : code を返さない", string.IsNullOrEmpty(res.Code),
                "code なし", string.IsNullOrEmpty(res.Code) ? "なし" : "**あり**");

            r.Verify(label + " : エラー画面に " + error + " が出る",
                (res.Body ?? "").Contains("text-danger") && (res.Body ?? "").Contains(error),
                "エラー画面（" + error + "）", Html.Describe(res.Body));
        }

        #endregion

        #region RT-408.1

        /// <summary>RT-408.1 鍵を jwks_uri だけで登録したクライアントの Request Object を、jwks_uri の鍵で検証する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT40801_jwks_uriの鍵でRequest_Objectを検証する(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-408.1",
                    "鍵を `jwks_uri` だけで登録したクライアントの、署名した Request Object を、`jwks_uri` の鍵で検証して受ける"
                    + "（外部の `request_uri`（`/ros` と同じ検証）と、PAR の `request`）",
                    "**`jwks_uri` は、クライアントが要求の署名に使う鍵の置き場所である**（OIDC Registration 1.0 §2）。"
                    + "**Request Object の署名は、クライアントの鍵で検証する**（RFC 9101 §6.2）。"
                    + "**以前は登録の列（`jwks`）の鍵しか見ず、`jwks_uri` のクライアントの Request Object を検証できなかった**（クライアント認証は `jwks_uri` を見ていた）。",
                    "OIDC Registration 1.0 §2 / RFC 9101 §6.2 / #408");

                r.Target("GET /authorize?request_uri=（外部の URL）・POST /par（request）");

                string keyName = "rt408_1_key_" + targetKey;
                string roName = "rt408_1_ro_" + targetKey;

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) 鍵を jwks_uri だけで登録する（jwks は登録しない）");

                        JwksUri.Write(keyName, JwsSigner.PublicRsaJwk(client));

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(keyName) + "\","
                            + "\"request_uris\":[\"" + JwksUri.Url(roName) + "\"]}");

                        string clientId = created.String("client_id");

                        Assert.False(string.IsNullOrEmpty(clientId), "前提: 登録できること（" + created.ToString() + "）");

                        r.Step("(2) 外部の request_uri（/ros と同じ検証）");

                        JwksUri.WriteRaw(roName, await RequestObjectBuilder.CreateAsync(client, clientId,
                            new Dictionary<string, object>()
                            {
                                { "response_type", "code" },
                                { "redirect_uri", UriA },
                                { "scope", "openid" },
                                { "state", "state-rt4081" },
                                { "nonce", "nonce-rt4081" }
                            }));

                        AuthZResponse used = await JwksUriTests.AuthorizeWithRequestUriAsync(client, clientId, JwksUri.Url(roName));

                        r.Verify("外部の request_uri : 認可コードが返る", !string.IsNullOrEmpty(used.Code),
                            "code あり", string.IsNullOrEmpty(used.Code) ? "**なし**（" + Html.Describe(used.Body) + "）" : "あり");
                        r.VerifyEqual("外部の request_uri : state は Request Object の値", "state-rt4081", used.State ?? "（無い）");

                        r.Step("(3) PAR の request（クライアント認証も jwks_uri の鍵）");

                        JsonResponse par = await client.PostJsonAsync("/par", JwksUriTests.WithAssertion(client, clientId,
                            new Dictionary<string, string>()
                            {
                                { "client_id", clientId },
                                {
                                    "request", await RequestObjectBuilder.CreateAsync(client, clientId,
                                        new Dictionary<string, object>()
                                        {
                                            { "response_type", "code" },
                                            { "redirect_uri", UriA },
                                            { "scope", "openid" },
                                            { "state", "state-rt4081-par" },
                                            { "nonce", "nonce-rt4081-par" }
                                        })
                                }
                            }));

                        r.VerifyEqual("PAR : HTTP 201 で預かる", "201", ((int)par.StatusCode).ToString());
                        r.Verify("PAR : request_uri が返る", !string.IsNullOrEmpty(par.String("request_uri")),
                            "request_uri あり", string.IsNullOrEmpty(par.String("request_uri")) ? "**なし**（" + par.ToString() + "）" : "あり");
                    }
                    finally
                    {
                        JwksUri.Delete(keyName);
                        JwksUri.Delete(roName);
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-408.2

        /// <summary>RT-408.2 鍵を jwks_uri だけで登録した fapi_ciba のクライアントの、CIBA の署名した要求を、jwks_uri の鍵で検証する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT40802_jwks_uriの鍵でCIBAの署名した要求を検証する(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-408.2",
                    "鍵を `jwks_uri` だけで登録した fapi_ciba のクライアントの、CIBA の署名した要求（`/ciba_authz` の `request`）を、`jwks_uri` の鍵で検証して先へ進む"
                    + "（居ない利用者を指すので `unknown_user_id`。`invalid_client`・検証の失敗にならない）",
                    "**CIBA の署名した要求は、クライアントの鍵で検証する**（CIBA Core 1.0 §7.1.1）。**`jwks_uri` はクライアントの鍵の置き場所である**（OIDC Registration 1.0 §2）。"
                    + "**以前は、列の鍵が無ければ `invalid_client` で断っていた。**",
                    "CIBA Core 1.0 §7.1.1 / OIDC Registration 1.0 §2 / #408");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_6);

                r.Target("client_name=" + KnownClients.TestClient4_6 + "（fapi_ciba。鍵は jwks_uri だけ。要求は ES256・kid 付き）");

                string jwk = JwsSigner.PublicEcJwk(client);
                string kid;

                using (JsonDocument doc = JsonDocument.Parse(jwk))
                {
                    kid = doc.RootElement.GetProperty("kid").GetString();
                }

                JwksUri.Write("rt408_2_ciba", jwk);

                try
                {
                    r.Step("(1) kid 付きの署名した要求を送る（控えに無い kid なので、OP は jwks_uri を取りに行く）");

                    //  **取り直しには下限（1 分）がある**（起動のときに温めようとした分。鍵はまだ置かれていない）。
                    //    **検証の失敗（invalid_request）の間だけ、時間で打ち切って送り直す**（回数ではなく時間で決める。RT-305.5）。
                    JsonResponse res = null;
                    Stopwatch sw = Stopwatch.StartNew();

                    while (true)
                    {
                        res = await client.CibaAuthorizeWithBasicAuthAsync(
                            new Dictionary<string, string>()
                            {
                                { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                                    new Dictionary<string, object>(), kid) }
                            },
                            reg.ClientId, reg.ClientSecret);

                        if (res.Error != "invalid_request" || sw.Elapsed > TimeSpan.FromSeconds(75))
                        {
                            break;
                        }

                        await Task.Delay(5000);
                    }

                    r.VerifyEqual("署名を検証して先へ進む（居ない利用者なので unknown_user_id）", "unknown_user_id", res.Error ?? "（無い）");
                }
                finally
                {
                    JwksUri.Delete("rt408_2_ciba");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-376.1

        /// <summary>RT-376.1 内部のアドレスの jwks_uri は、取りに行かずに断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37601_内部のアドレスのjwks_uriは断る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-376.1",
                    "動的登録の `jwks_uri` が**内部のアドレス**（プライベート・リンクローカル・ユニーク ローカル）なら、`400` ＋ `invalid_client_metadata` で断る",
                    "**動的登録では、登録できる相手が OP に取りに行かせる URL を書ける。**"
                    + "**以前はスキーム（https か、ループバックの http）しか見ておらず、OP の内側のアドレスへ要求を出させられた。**"
                    + "**既定では内部のアドレスへ行かない**（配備が許可の一覧で開ける）。",
                    "RFC 7591 §2 / #376");

                r.Target("POST registration_endpoint（jwks_uri が内部のアドレス）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    foreach (string url in new string[]
                        {
                            "https://10.0.0.1/e2e/rt376",
                            "https://192.168.0.1/e2e/rt376",
                            "https://169.254.169.254/latest/meta-data",
                            "https://[fd00::1]/e2e/rt376"
                        })
                    {
                        r.Step("jwks_uri = " + url);

                        JsonResponse rejected = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + url + "\"}");

                        r.VerifyEqual(url + " : HTTP 400", "400", ((int)rejected.StatusCode).ToString());
                        r.VerifyEqual(url + " : invalid_client_metadata", "invalid_client_metadata",
                            rejected.String("error") ?? "（無い）");

                        //  **読めなかったのではなく、行き先で断ったこと**（取りに行っていない）。
                        string description = rejected.String("error_description") ?? "";
                        bool byAddress = description.Contains("internal address");

                        r.Verify(url + " : 断る理由は行き先", byAddress,
                            "internal address", byAddress ? "internal address" : "**" + description + "**");
                    }
                });

                r.Done();
            }
        }

        #endregion

        #region RT-363.1

        /// <summary>RT-363.1 登録を直さずに jwks_uri の鍵を入れ替えても、新しい鍵が 1 回目から通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36301_登録を直さずに鍵を入れ替えても新しい鍵が1回目から通る(string targetKey)
        {
            await JwksUri.SkipIfNotAvailableAsync();

            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-363.1",
                    "**`jwks_uri` に置いた鍵を、`kid` の違う鍵に入れ替える**と、**登録を直さなくても、"
                    + "新しい鍵の `client_assertion`（ヘッダにその `kid`）が 1 回目から通る**",
                    "**検証する側は、知らない `kid` を見たら `jwks_uri` を取り直す**（OIDC Core 1.0 §10.1.1。OP の鍵を RP が追う話を、RP の鍵を OP が追う向きに準用する）。"
                    + "**以前は、キャッシュに無い `kid` の 1 本は断り、背景で取り直していた**ので、"
                    + "**入れ替えの後の最初の 1 本が 401 になった**（適合性テストの `oidcc-refresh-token-rp-key-rotation`）。",
                    "OIDC Core 1.0 §10.1.1（準用：RP の鍵の入れ替えを、検証する OP が追う）/ #363");

                r.Target("POST /revoke（client_assertion。鍵は動的登録した jwks_uri の先）");

                //  **回ごとに別の URL にする**（取り直しの下限はプロセスの中で URL ごと。同じサイトに 1 分以内に回し直しても当たらないように）。
                string name = "rt363_1_" + targetKey + "_" + Guid.NewGuid().ToString("N").Substring(0, 8);

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token) =>
                {
                    try
                    {
                        r.Step("(1) RSA の鍵を置いて動的登録し、その鍵で認証できることを見る");

                        JwksUri.Write(name, JwsSigner.PublicRsaJwk(client));

                        JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"redirect_uris\":[\"" + UriA + "\"],"
                            + "\"scope\":\"openid email\","
                            + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                            + "\"jwks_uri\":\"" + JwksUri.Url(name) + "\"}");

                        string clientId = created.String("client_id");

                        Assert.False(string.IsNullOrEmpty(clientId),
                            "前提: client_id が返ること（" + created.ToString() + "）");

                        JsonResponse byRsa = await JwksUriTests.RevokeAsync(client, clientId, false);

                        Assert.True(string.IsNullOrEmpty(byRsa.String("error")),
                            "前提: RSA の鍵で通ること（" + byRsa.ToString() + "）");

                        r.Step("(2) 置いてある鍵を EC に入れ替える（登録は直さない）");

                        string ecJwk = JwsSigner.PublicEcJwk(client);
                        JwksUri.Write(name, ecJwk);

                        string ecKid;
                        using (JsonDocument doc = JsonDocument.Parse(ecJwk))
                        {
                            ecKid = doc.RootElement.GetProperty("kid").GetString();
                        }

                        r.Step("(3) すぐに（取り直しの下限の内側で）、新しい鍵（ヘッダにその kid）で認証する");

                        JsonResponse tooSoon = await client.RevokeAsync(JwksUriTests.WithAssertion(client, clientId,
                            new Dictionary<string, string>()
                            {
                                { "token", "e2e-rt363-unknown-token" }
                            }, true, ecKid));

                        r.VerifyEqual("**下限の内側では取り直さず、断る**（invalid_client）", "invalid_client",
                            tooSoon.String("error") ?? "（無い）");

                        r.Step("(4) 取り直しの下限（1 分）が過ぎるまで待つ");

                        r.Note("**取り直すかどうかは、Open棟梁 の `RemoteJwkSetStore.GetJwkAsync` が、前に取った時刻から 1 分の下限で決める**"
                            + "（`MinRefetchInterval`。`kid` を偽った要求で、外から何度も取得を起こせないように）。"
                            + "**登録のときに取ってから 1 分経たないうちは、知らない `kid` でも取り直さない。**"
                            + "**適合性テストの `oidcc-refresh-token-rp-key-rotation` も、入れ替えの後に 60 秒待ってから送る。**");

                        await Task.Delay(TimeSpan.FromSeconds(65));

                        r.Step("(5) 新しい鍵（EC / ES256）で、ヘッダに その kid（キャッシュに無い kid）を入れて、もう一度認証する");

                        r.Note("**ヘッダに `kid` を入れて送る**（適合性テストの RP と同じ）。"
                            + "**実装は、知らない `kid` を見たときに取り直す**（OIDC Core 1.0 §10.1.1）。"
                            + "**`kid` の無い署名は、キャッシュに在る鍵を順に試すだけ**で、取り直さない。");

                        Stopwatch sw = Stopwatch.StartNew();
                        JsonResponse byEc = await client.RevokeAsync(JwksUriTests.WithAssertion(client, clientId,
                            new Dictionary<string, string>()
                            {
                                { "token", "e2e-rt363-unknown-token" }
                            }, true, ecKid));
                        sw.Stop();

                        r.VerifyEqual("**下限を過ぎた後は、その場で取り直して通る**（error は無い。再試行を待たない）", "（無い）",
                            byEc.String("error") ?? "（無い）");

                        r.VerifyEqual("HTTP の状態は 200", "200", ((int)byEc.StatusCode).ToString());

                        r.Observe("1 回目の応答までの時間", sw.ElapsedMilliseconds.ToString() + " ミリ秒",
                            "取り直しを待つ上限は 3 秒（CmnEndpoints.JwksUriRefetchWait）。");
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
        /// <param name="kid">ヘッダに入れる kid（ES256 のときだけ。null なら入れない。#363）</param>
        /// <returns>送る項目（アサーション入り）</returns>
        /// <remarks>
        /// **`aud` はトークン エンドポイント**である（実装が照合している）。
        /// **`/revoke` を叩くときも、`aud` はトークン エンドポイントのまま** —
        /// **RFC 7009 §2.1 が「同じクライアント認証」と定めている**ためである。
        ///
        /// **ヘッダに `kid` は、既定では入れない**（RFC 7515 §4.1.4 は任意）。
        /// **実装は、`kid` が無ければ JWK Set に在る鍵を順に試す**（上限あり）。
        /// **鍵の入れ替え（`RT-363.1`）は `kid` を入れて測る** — 実装は、知らない `kid` を見たときに取り直す（OIDC Core 1.0 §10.1.1）。
        /// </remarks>
        private static Dictionary<string, string> WithAssertion(
            IdPClient client, string clientId,
            IDictionary<string, string> items, bool es256 = false, string kid = null)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Issuer() },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            };

            return new Dictionary<string, string>(items)
            {
                {
                    "client_assertion",
                    es256 ? JwsSigner.SignES256(client, payload, kid)
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
