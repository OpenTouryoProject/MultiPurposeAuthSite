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
//* クラス名        ：ClientRegistrationTests
//* クラス日本語名  ：RT-307 動的クライアント登録（RFC 7591 / 7592）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/18  玄人 幸道         新規（#307 の段階 1）
//*  2026/10/18  玄人 幸道         管理 API（RFC 7592）のケースを追加（#307 の段階 2）
//*  2026/10/19  玄人 幸道         クライアント認証の方法のケースを追加（#307 の段階 3）
//*  2026/10/20  玄人 幸道         software_statement のケースを追加（#307 の段階 4）
//*  2026/10/20  玄人 幸道         RT-307.3 を「n 件作れる」に書き換えた（#307 の段階 5-a）
//*  2026/10/20  玄人 幸道         RT-307.22〜.24（client_credentials）を追加（#307 の段階 5-b）
//*  2026/10/20  玄人 幸道         RT-307.25/.26（発行者の上限と鍵の入れ替え）を追加（#307 の段階 6）
//*  2026/10/20  玄人 幸道         Noteの文面を段階5-a-1後の形に直した（#307）
//*  2026/10/21  玄人 幸道         RT-307.4 の jwks_uri を「読めない URL は 400」にした（#309 の段階 1）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Fapi;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-307. **動的クライアント登録**（RFC 7591 / 7592。#307 の段階 1 と段階 2）。
    /// </summary>
    /// <remarks>
    /// **以前はクライアント登録に WebUI しか無かった**（`ANALYSIS-IdP.md` の D-4）。
    /// **API が無いので、CI や IaC からクライアントを作れなかった。**
    ///
    /// **段階 1 の形** : **ROPC で専用 scope（`client_registration`）の
    /// アクセス トークンを取り**、**それを Bearer に付けて `registration_endpoint` へ `POST` する。**
    /// **所有者は、そのトークンの `sub` の利用者**である。
    ///
    /// **段階 5-a で、1 利用者 n クライアントになった。**
    /// **所有者の置き場所を `Users.ClientID`（1 枠・NOT NULL・一意）から
    /// `Saml2OAuth2Data.OwnerUserId`（行ごと）へ移した**ためである。
    /// **上限は設けていない**（**洪水はレート制限で受ける**。#305 の段階 3）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-307.1`** | **登録でき、返った資格情報で実際に認可コードが取れる** |
    /// | **`RT-307.2`** | **トークンが無ければ 401／scope が足りなければ 403** |
    /// | **`RT-307.3`** | **2 件目以降も登録できる**（**1 利用者 n クライアント**。#307 の段階 5-a） |
    /// | **`RT-307.4`** | **メタデータの誤りは `400`**（`jwks_uri` / `redirect_uris` 無し / 対応しない組み合わせ） |
    /// | **`RT-307.5`** | **専用トークンは scope も有効期限も絞られている** |
    /// | **`RT-307.6`** | **登録した `response_types` が効く** |
    /// | **`RT-307.7`** | **登録した `grant_types` が効く** |
    /// | **`RT-307.8`** | **登録した `scope` が効く**（DB に登録したクライアントでも） |
    /// | **`RT-307.9`** | **`GET` で登録を読める**（`client_secret` は返さない） |
    /// | **`RT-307.10`** | **`PUT` で全置換でき、置換が実際に効く** |
    /// | **`RT-307.11`** | **`DELETE` で消え、既に出ているトークンも通らなくなり、登録し直せる** |
    /// | **`RT-307.12`** | **管理 API は `registration_access_token` 以外では叩けない** |
    /// | **`RT-307.13`** | **`PUT` の誤りは `400`**（**登録は変わらない**） |
    /// | **`RT-307.14`** | **`private_key_jwt` で登録でき、その鍵で認証できる**（**秘密では通らない**） |
    /// | **`RT-307.15`** | **`tls_client_auth` で登録でき、その証明書で認証できる**（**既定は core だけ**） |
    /// | **`RT-307.16`** | **方法と鍵の誤りは、登録の時点で `400`** |
    /// | **`RT-307.17`** | **`PUT` で方法を省くと秘密に戻るが、鍵は消えない** |
    /// | **`RT-307.18`** | **`software_statement` で登録でき、主張が本文（plain JSON）に勝つ** |
    /// | **`RT-307.19`** | **壊れた statement は `400` ＋ `invalid_software_statement`** |
    /// | **`RT-307.20`** | **知らない発行者は `400` ＋ `unapproved_software_statement`** |
    /// | **`RT-307.21`** | **`PUT` でも statement が効き、省くと本文が通る** |
    ///
    /// **段階 2 は RFC 7592**（`registration_client_uri` ＝ `…/register/{client_id}`）。
    /// **管理のトークンは、登録の応答で 1 回だけ返る**（**こちらはハッシュしか持たない**）。
    ///
    /// **使い捨ての利用者を 2 人使う。**
    /// **段階 5-a で n 件になったので、分ける必要はもう無い**が、
    /// **分けたままにしてある** — **「管理 API を叩く権限」と「登録の所有者」は別物**であり、
    /// **その形で測り続ける方が、本来の使い方に近い。**
    ///
    /// **段階 3 は、クライアント認証の方法**（`token_endpoint_auth_method`）。
    /// **検証する側は実装済み**（`private_key_jwt` は #239 / #129 の段階 2、
    /// `tls_client_auth` は #226）で、**動的登録だけが断っていた。**
    /// **登録された方法は認証でも効く** — **明示が無ければ秘密ベースの 2 つだけ**で、
    /// **鍵や DN を登録しただけでは、その方法では通らない。**
    ///
    /// **段階 4 は `software_statement`**（RFC 7591 §2.3）。
    /// **信頼する発行者が署名した JWT を受け、主張を本文へ重ねる**（**statement が勝つ**）。
    ///
    /// | | |
    /// |---|---|
    /// | **鍵は「発行者ごと」** | **クライアントごとではない**（クライアント自身の鍵は段階 3 の `jwks`） |
    /// | 設定 | **`SoftwareStatementIssuers`**（`iss` / `.cer` / `alg`）。**1 件も無ければ受け付けない** |
    /// | **認可は別** | **statement は 2 つの専用トークンを置き換えない**（**同梱されて配布される ＝ 秘密ではない**） |
    /// | 保管 | **しない。** 応答にも返さない（§3.2.1 で任意）。**＝ 列は増えていない** |
    ///
    /// **E2E は、`SpRp_RsaPfxFilePath` で statement に署名する。**
    /// **サイトには、その対の `.cer` を「発行者の検証鍵」として渡す**（`test.ps1` が渡す）。
    /// **渡っていない配備では、`RT-307.18` 〜 `.21` は Skip する。**
    ///
    /// **Discovery に `registration_endpoint` が載ることは `RT-189.*`（`DiscoveryTests`）ではなく、
    /// ここで測る** — **広告は `EnableDynamicClientRegistration` で出入りする**ので、
    /// **既定の配備の Discovery には載らない。**
    /// </remarks>
    public class ClientRegistrationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientRegistrationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>登録する折り返し先</summary>
        private const string UriA = "https://localhost:44300/e2e/rt307/a";

        /// <summary>登録する折り返し先（2 本目）</summary>
        private const string UriB = "https://localhost:44300/e2e/rt307/b";

        #region RT-307.1

        /// <summary>RT-307.1 登録でき、返った資格情報で認可コードが取れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30701_登録でき返った資格情報で認可コードが取れる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.1",
                    "`registration_endpoint` で登録でき、返った `client_id` / `client_secret` で"
                    + "実際に認可コードが取れる",
                    "**登録が「本当に効いている」ことまで測る。**"
                    + "**201 と `client_id` が返るだけでは、使える登録になったとは言えない** — "
                    + "**`redirect_uri` が正しい列に入っていなければ、認可要求が通らない。**",
                    "RFC 7591 §3.1 / §3.2.1（201 Created）/ OIDC DCR 1.0 §2 / #307");

                r.Target("POST " + "registration_endpoint" + "（専用 scope の AT を Bearer に付ける）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) redirect_uris を 2 本登録する");

                    JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriA, UriB));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)res.StatusCode).ToString());

                    string clientId = res.String("client_id");
                    string clientSecret = res.String("client_secret");

                    r.Verify("client_id が返る", !string.IsNullOrEmpty(clientId),
                        "返る", string.IsNullOrEmpty(clientId) ? "**返らない**" : "返った");

                    r.Verify("client_secret が返る", !string.IsNullOrEmpty(clientSecret),
                        "返る", string.IsNullOrEmpty(clientSecret) ? "**返らない**" : "返った（値は出さない）");

                    r.Verify("client_id_issued_at が返る",
                        res.IsJson && res.Json.TryGetProperty(
                            "client_id_issued_at", out JsonElement _),
                        "返る", res.IsJson ? "—" : "**JSON ではない**");

                    r.VerifyEqual("client_secret_expires_at は 0（期限なし）", "0",
                        (res.IsJson && res.Json.TryGetProperty(
                            "client_secret_expires_at", out JsonElement exp))
                            ? exp.ToString() : "（無い）");

                    r.VerifyEqual("grant_types の既定は authorization_code", "True",
                        res.ArrayContains("grant_types", "authorization_code").ToString());

                    r.VerifyEqual("response_types の既定は code", "True",
                        res.ArrayContains("response_types", "code").ToString());

                    r.VerifyEqual("redirect_uris に 1 本目が入る", "True",
                        res.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("redirect_uris に 2 本目が入る", "True",
                        res.ArrayContains("redirect_uris", UriB).ToString());

                    r.Step("(2) 返った資格情報で、認可コードを取る");

                    ClientRegistration registered = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUri = UriA
                    };

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, registered, "openid email", "state-307", "nonce-307", UriA);

                    r.Verify("code が返る", !string.IsNullOrEmpty(authz.Code),
                        "返る", string.IsNullOrEmpty(authz.Code)
                            ? "**返らない（error=" + (authz.Error ?? "なし") + "）**" : "返った");

                    r.Note("**`client_name` は登録しても無視する**（RFC 7591 §3.2.1 が認めている）— "
                        + "**`ClientName` の列は利用者名であり、"
                        + "`Helper.GetClientName` が「登録が在るか」の判定に使っている。** "
                        + "**応答にも入れない**（利用者名を漏らさないため）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.2

        /// <summary>RT-307.2 トークンが無ければ 401、scope が足りなければ 403</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30702_トークンが無ければ401scopeが足りなければ403(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.2",
                    "トークンが無ければ `401`、scope が足りなければ `403` ＋ `insufficient_scope`",
                    "**この口は、クライアント登録を作れる。**"
                    + "**誰でも叩けてはならないし、普通のアクセス トークンでも叩けてはならない。**"
                    + "**専用 scope（`client_registration`）は、登録に明記したクライアントにしか出さない** — "
                    + "**他の scope の「登録が無ければ制限しない」とは逆の倒し方である。**",
                    "RFC 6750 §3.1（invalid_token / insufficient_scope）/ #307");

                r.Target("POST registration_endpoint（トークン無し／scope 違いのトークン）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) Bearer を付けずに叩く");

                    JsonResponse none = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, null, DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)none.StatusCode).ToString());

                    r.Verify("WWW-Authenticate: Bearer が付く",
                        (none.Header("WWW-Authenticate") ?? "").StartsWith("Bearer"),
                        "付く", none.Header("WWW-Authenticate") ?? "**付かない**");

                    r.Step("(2) 出来合いでない（偽の）トークンで叩く");

                    JsonResponse bad = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, "not-a-token", DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)bad.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_token",
                        "invalid_token", bad.String("error") ?? "（無い）");

                    r.Step("(3) 専用 scope を持たないトークンで叩く");

                    //  **同じクライアントで、専用 scope を要求せずに取る。**
                    //    **登録には `client_registration` だけを許しているので、**
                    //    **他の scope を頼むと scope が 1 つも付かないトークンになる。**
                    JsonResponse other = await DynamicClientRegistration.TokenAsync(
                        client, ctx.ApiClientId, ctx.ApiClientSecret,
                        ctx.OwnerName, ctx.Password, "openid email");

                    string otherToken = other.String("access_token");

                    Assert.False(string.IsNullOrEmpty(otherToken),
                        "前提: scope 違いのトークンが取れること");

                    JsonResponse insufficient = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, otherToken, DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 403", "403",
                        ((int)insufficient.StatusCode).ToString());

                    r.VerifyEqual("error は insufficient_scope",
                        "insufficient_scope", insufficient.String("error") ?? "（無い）");

                    r.Note("**`client_registration` は、登録に明記していなければ出さない。** "
                        + "**「登録が無ければ制限しない」を当てはめると、"
                        + "`scope` を登録していない既存のクライアントが全て、"
                        + "ROPC で登録を作れることになる。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.3

        /// <summary>RT-307.3 2 件目以降も登録でき、別々に使える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30703_2件目以降も登録でき別々に使える(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.3",
                    "**1 利用者 n クライアント** — 2 件目以降も登録でき、**別々に使え、別々に消せる**",
                    "**段階 1 では 2 件目を `403` ＋ `access_denied` で断っていた。** "
                    + "**絞っていたのは仕様の要求ではなく、器の都合である** — "
                    + "**所有者が `Users.ClientID`（1 枠・NOT NULL・一意索引）だった。** "
                    + "**段階 5-a で `Saml2OAuth2Data.OwnerUserId`（行ごと）へ移したので、縛りが外れた。** "
                    + "**201 が 2 回返るだけでは足りない** — "
                    + "**2 つが本当に別の登録として生きていること**（**資格情報が違い、"
                    + "片方を消してももう片方が動くこと**）**まで測る。**",
                    "RFC 7591 §3.1 / §3.2.1 / RFC 7592 §2.3 / #307 の段階 5-a");

                r.Target("POST registration_endpoint（同じ利用者で 2 回）→ 両方で認可 → 片方を DELETE");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 1 件目を登録する");

                    JsonResponse first = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token, DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)first.StatusCode).ToString());

                    r.Step("(2) 同じトークンで 2 件目も登録できる");

                    JsonResponse second = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token, DynamicClientRegistration.Metadata(UriB));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)second.StatusCode).ToString());

                    r.Step("(3) 2 つは別の登録である（資格情報が違う）");

                    string firstId = first.String("client_id");
                    string secondId = second.String("client_id");

                    r.Verify("client_id が違う",
                        !string.IsNullOrEmpty(firstId) && firstId != secondId,
                        "違う", (firstId == secondId) ? "**同じ**" : "違った（値は伏せる）");

                    r.Verify("client_secret が違う",
                        first.String("client_secret") != second.String("client_secret"),
                        "違う", "違った（値は伏せる）");

                    r.Verify("registration_access_token が違う",
                        first.String("registration_access_token")
                            != second.String("registration_access_token"),
                        "違う", "違った（値は伏せる）");

                    r.Step("(4) どちらでも認可コードが取れる（それぞれの折り返し先で）");

                    ClientRegistration one = new ClientRegistration()
                    {
                        ClientId = firstId,
                        ClientSecret = first.String("client_secret"),
                        RedirectUri = UriA
                    };

                    ClientRegistration two = new ClientRegistration()
                    {
                        ClientId = secondId,
                        ClientSecret = second.String("client_secret"),
                        RedirectUri = UriB
                    };

                    AuthZResponse authzOne = await Flows.AuthorizeCodeAsync(
                        client, one, "openid email", "state-n1", "nonce-n1", UriA);

                    r.Verify("1 件目で code が取れる", !string.IsNullOrEmpty(authzOne.Code),
                        "取れる", string.IsNullOrEmpty(authzOne.Code)
                            ? "**取れない**（error=" + (authzOne.Error ?? "なし") + "）" : "取れた");

                    AuthZResponse authzTwo = await Flows.AuthorizeCodeAsync(
                        client, two, "openid email", "state-n2", "nonce-n2", UriB);

                    r.Verify("2 件目で code が取れる", !string.IsNullOrEmpty(authzTwo.Code),
                        "取れる", string.IsNullOrEmpty(authzTwo.Code)
                            ? "**取れない**（error=" + (authzTwo.Error ?? "なし") + "）" : "取れた");

                    r.Step("(5) 1 件目を DELETE しても、2 件目は生きている");

                    JsonResponse deleted = await DynamicClientRegistration.DeleteAsync(
                        client, first.String("registration_client_uri"),
                        first.String("registration_access_token"));

                    r.VerifyEqual("DELETE は 204", "204", ((int)deleted.StatusCode).ToString());

                    JsonResponse readTwo = await DynamicClientRegistration.ReadAsync(
                        client, second.String("registration_client_uri"),
                        second.String("registration_access_token"));

                    r.VerifyEqual("2 件目は GET で読める（200）", "200",
                        ((int)readTwo.StatusCode).ToString());

                    AuthZResponse authzTwoAgain = await Flows.AuthorizeCodeAsync(
                        client, two, "openid email", "state-n3", "nonce-n3", UriB);

                    r.Verify("2 件目で、まだ code が取れる", !string.IsNullOrEmpty(authzTwoAgain.Code),
                        "取れる", string.IsNullOrEmpty(authzTwoAgain.Code)
                            ? "**取れない（1 件目の DELETE で壊れた）**" : "取れた");

                    r.Note("**`POST` を upsert にはしていない。** "
                        + "**2 回 `POST` すれば、2 件の別の登録になる**（それが n 件である）。"
                        + "**特定の登録を直すのは RFC 7592 の `PUT`**（段階 2）。");

                    r.Note("**上限は設けていない**（設定キーも増やしていない）。"
                        + "**洪水はレート制限で受ける**（#305 の段階 3。口の名前 `register`）。");

                    r.Note("**管理画面は、まだ 1 件だけを扱う**（段階 5-a-1）。"
                        + "**API から 2 件作った利用者が画面で保存すると、画面が扱う 1 件に寄る** — "
                        + "**一覧にするのは段階 5-a-2。**");

                    r.Step("(6) 所有者を消すと、その人の登録は全部消える");

                    //  **新しい外部キー**（`OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`）
                    //    **と、`Register` が所有者を書いていることを、同時に押さえる。**
                    //
                    //  **以前は `Saml2OAuth2Data.ClientID` → `Users.ClientID` の外部キー**で、
                    //    **同じ効き方だった**（1 件だけ消えた）。
                    //    **n 件になったので、「全部消える」ことを測る必要がある。**
                    //
                    //  **`WithDcrAsync` の後始末でも同じ利用者を消す**（二重になるが、無害）。
                    await UsersAdmin.DeleteByUserNameAsync(admin, ctx.OwnerName);

                    JsonResponse goneOne = await DynamicClientRegistration.ReadAsync(
                        client, first.String("registration_client_uri"),
                        first.String("registration_access_token"));

                    r.VerifyEqual("1 件目は、もう読めない（401）", "401",
                        ((int)goneOne.StatusCode).ToString());

                    JsonResponse goneTwo = await DynamicClientRegistration.ReadAsync(
                        client, second.String("registration_client_uri"),
                        second.String("registration_access_token"));

                    r.VerifyEqual("2 件目も、もう読めない（401）", "401",
                        ((int)goneTwo.StatusCode).ToString());

                    r.Note("**行が無くなるので `401`**（`404` ではない。RFC 7592 §2.1 の MUST）。"
                        + "**撃ち分けると「在るが触れない」ことが外から分かる**ためである。");

                    r.Note("**所有者を書いていなければ、ここで落ちる** — "
                        + "**`OwnerUserId` が空の登録は、利用者を消しても残る**"
                        + "（**種データが、わざとその立場に在る**）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.4

        /// <summary>RT-307.4 メタデータの誤りは 400</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30704_メタデータの誤りは400になる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.4",
                    "メタデータの誤りは `400`（`invalid_redirect_uri` / `invalid_client_metadata`）",
                    "**知らないメタデータは無視してよい**（RFC 7591 §3.2.1）が、"
                    + "**無視すると黙って弱くなるものは断る。**"
                    + "**`jwks_uri` は受け付けるようになった**（#309 の段階 1）が、"
                    + "**読めない URL は、登録のその場で断る** — "
                    + "**受け取って無視すると、`private_key_jwt`（#239）や "
                    + "Request Object（JAR）の検証が、登録したつもりの鍵で通らなくなる。**",
                    "RFC 7591 §3.2.1 / §3.2.2 / RFC 6749 §3.1.2 / #307");

                r.Target("POST registration_endpoint（誤ったメタデータ）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) redirect_uris が無い");

                    JsonResponse noUri = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token, "{}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)noUri.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_redirect_uri",
                        "invalid_redirect_uri", noUri.String("error") ?? "（無い）");

                    r.Step("(2) redirect_uri にフラグメントが付いている");

                    JsonResponse fragment = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriA + "#x"));

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)fragment.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_redirect_uri",
                        "invalid_redirect_uri", fragment.String("error") ?? "（無い）");

                    r.Step("(3) 相対 URI は通らない");

                    JsonResponse relative = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata("/e2e/rt307/relative"));

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)relative.StatusCode).ToString());

                    r.Step("(4) 読めない jwks_uri は受け付けない（#309 の段階 1）");

                    JsonResponse jwksUri = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"jwks_uri\":\"https://localhost:44300/e2e/rt307/jwks\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)jwksUri.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata",
                        "invalid_client_metadata", jwksUri.String("error") ?? "（無い）");

                    r.Note("**この URL には JWK Set が無い**（この配備自身の、存在しないパス）。"
                        + "**登録の口は取りに行って、読めなければ断る**（#309 の決め (B)）。"
                        + "**読める `jwks_uri` を登録して使うところは `RT-309.*`** で測る。");

                    r.Step("(5) 壊れた software_statement は受け付けない（段階 4）");

                    JsonResponse statement = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"software_statement\":\"eyJ.eyJ.sig\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)statement.StatusCode).ToString());

                    //  **期待するコードは、配備に依る**（#307 の段階 4）。
                    //    **信頼する発行者を設定していれば「壊れている」**
                    //    （`invalid_software_statement`。この値は JWT として読めない）。
                    //    **1 件も設定していなければ「信頼していない」**
                    //    （`unapproved_software_statement`。**従来どおり**）。
                    //  **どちらでも `400` で、登録は作られない** — それがこのケースの観点である。
                    string expectedStatementError =
                        string.IsNullOrEmpty(ClientRegistrationTests.SoftwareStatementIssuer())
                            ? "unapproved_software_statement" : "invalid_software_statement";

                    r.VerifyEqual("error は " + expectedStatementError,
                        expectedStatementError, statement.String("error") ?? "（無い）");

                    r.Step("(6) response_types と grant_types が噛み合っていない");

                    JsonResponse mismatch = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"response_types\":[\"code\"],"
                        + "\"grant_types\":[\"refresh_token\"]}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)mismatch.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata",
                        "invalid_client_metadata", mismatch.String("error") ?? "（無い）");

                    r.Step("(7) 専用 scope は、動的登録では付けられない");

                    JsonResponse escalate = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"" + DynamicClientRegistration.Scope + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)escalate.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata",
                        "invalid_client_metadata", escalate.String("error") ?? "（無い）");

                    r.Note("**自分と同じ強さの scope を、自分で配らせない。** "
                        + "**`client_registration` を動的登録で付けられるようにすると、"
                        + "権限を際限なく増やせる。** "
                        + "**配るのは、管理画面か構成ファイルからだけ**にしてある。");

                    r.Step("(8) auth（同意画面を出さない）も、動的登録では付けられない");

                    JsonResponse skipConsent = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid auth\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)skipConsent.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata",
                        "invalid_client_metadata", skipConsent.String("error") ?? "（無い）");

                    r.Note("**同意画面を飛ばすかは、登録を管理する人が決める**（#294）。"
                        + "**自分で `auth` を登録できると、クライアントが決めることになる。**");

                    r.Step("(9) どの誤りでも、登録は作られていない");

                    JsonResponse ok = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token, DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("この後で、正しい要求は 201 になる",
                        "201", ((int)ok.StatusCode).ToString());
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.5

        /// <summary>RT-307.5 専用トークンは scope も有効期限も絞られている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30705_専用トークンはscopeも有効期限も絞られている(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.5",
                    "管理 API 専用のアクセス トークンは、scope も有効期限も絞られている",
                    "**配備ぜんたいの `OAuth2AccessTokenExpireTimeSpanFromMinutes`（既定 360 分）では長すぎる** — "
                    + "**この口は、人の操作より CI から叩く想定**で、長く持たせる理由が無い。"
                    + "**scope も混ぜない** — **登録を作れる権限を持ったトークンが、"
                    + "利用者の属性を読む用途でも使い回されると、寿命を短くした意味が薄れる。**",
                    "RFC 6749 §3.3 / #307");

                r.Target("POST /token（grant_type=password、scope=client_registration）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 専用 scope を、他の scope と一緒に要求する");

                    JsonResponse res = await DynamicClientRegistration.TokenAsync(
                        client, ctx.ApiClientId, ctx.ApiClientSecret,
                        ctx.OwnerName, ctx.Password,
                        "openid email " + DynamicClientRegistration.Scope);

                    string accessToken = res.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: アクセス トークンが取れること");

                    JsonElement payload = Jwt.Payload(accessToken);
                    List<string> scopes = Jwt.Strings(payload, "scopes");

                    r.VerifyEqual("scope は専用の 1 本だけ",
                        DynamicClientRegistration.Scope, string.Join(" ", scopes));

                    r.Step("(2) 有効期限が、配備ぜんたいの値より短い");

                    long iat = long.Parse(Jwt.String(payload, "iat"));
                    long exp = long.Parse(Jwt.String(payload, "exp"));
                    long lifetime = exp - iat;

                    r.Observe("exp - iat（秒）", lifetime.ToString());

                    r.Verify("1 時間より短い", lifetime < 3600,
                        "短い", lifetime.ToString() + " 秒");

                    r.Note("**既定は 300 秒**（`DcrAccessTokenExpireTimeSpanFromSeconds`。"
                        + "**未設定・0 以下なら既定値に倒す**）。"
                        + "**ここで値そのものを突き合わせないのは、配備で変えられる設定だから**である。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.6

        /// <summary>RT-307.6 登録した response_types が効く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30706_登録したresponse_typesが効く(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.6",
                    "登録した `response_types` が、認可エンドポイントで効く",
                    "**保存して返すだけにはしない。**"
                    + "**登録が「`code` だけ」と言っているのに認可サーバが `token` も通すのでは、"
                    + "登録の意味が無い。**"
                    + "**絞りは認可エンドポイントで効く** — **利用者を操作させる前に断る**ため。"
                    + "**`ClientModePolicy`（登録種別で、その経路を許すか）の手前に 1 段置いてある。**",
                    "RFC 7591 §2（response_types）/ RFC 6749 §4.1.2.1（unauthorized_client）/ #307");

                r.Target("GET /authorize（登録に無い response_type）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    //  **管理画面で登録したクライアントで測る。**
                    //    **`redirect_uri` の照合が先に効く**（#187。誤りを RP へ返せるようにするため）ので、
                    //    **`redirect_uri_token` の列が空のクライアントでは `invalid_request` になり、**
                    //    **`response_types` の絞りまで届かない。**
                    //    **`WithDcrAsync` が、両方の列を登録し、`response_types` を `code` だけにしてある。**

                    r.Step("(1) 登録した response_type（code）は通る");

                    AuthZResponse code = await client.AuthorizeAndGrantAsync(
                        new Dictionary<string, string>()
                        {
                            { "response_type", "code" },
                            { "client_id", ctx.ApiClientId },
                            { "scope", "openid" },
                            { "state", "state-ok" },
                            { "nonce", "nonce-ok" },
                            { "redirect_uri", UriA }
                        });

                    r.Verify("code が返る", !string.IsNullOrEmpty(code.Code),
                        "返る", string.IsNullOrEmpty(code.Code)
                            ? "**返らない（error=" + (code.Error ?? "なし") + "）**" : "返った");

                    r.Step("(2) 登録に無い response_type（token）は断られる");

                    AuthZResponse implicitFlow = await client.AuthorizeAsync(
                        new Dictionary<string, string>()
                        {
                            { "response_type", "token" },
                            { "client_id", ctx.ApiClientId },
                            { "scope", "openid" },
                            { "state", "state-ng" },
                            { "nonce", "nonce-ng" },
                            { "redirect_uri", UriB }
                        });

                    r.VerifyEqual("error は unauthorized_client",
                        "unauthorized_client", implicitFlow.Get("error") ?? "（無い）");

                    r.Observe("error_description",
                        implicitFlow.Get("error_description") ?? "（無い）");

                    r.Note("**列が空なら絞らない**（#198 と同じ倒し方）。"
                        + "**既存の登録はこの列を持たないので、"
                        + "RFC 7591 §2 の既定（`code`）を当てはめてはならない** — "
                        + "**当てはめると「`code` 以外が通らなくなる」破壊になる。** "
                        + "**既定を書き込むのは、動的登録で作るときだけ。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.7

        /// <summary>RT-307.7 登録した grant_types が効く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30707_登録したgrant_typesが効く(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.7",
                    "登録した `grant_types` が、トークン エンドポイントで効く",
                    "**`grant_types` と `response_types` は別物である。**"
                    + "**認可エンドポイントは `response_types` を見る**が、"
                    + "**どのグラントでトークンを出すかは `grant_types` で決まる。**"
                    + "**`ClientModePolicy`（登録種別 × 証明）の手前に 1 段置いてある** — "
                    + "**`ClientModePolicy` は AS の方針、`grant_types` は RP の申告**であり、"
                    + "**役割が違う。**",
                    "RFC 7591 §2（grant_types）/ RFC 6749 §5.2（unauthorized_client）/ #307");

                r.Target("POST /token（登録に無い grant_type）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    //  **`WithDcrAsync` の管理 API 用クライアントは、`grant_types` に
                    //    `password` だけを登録してある**（ROPC で使うため）。
                    //    **`authorization_code` は登録していない。**

                    r.Step("(1) 認可コードは取れる（認可エンドポイントは grant_types を見ない）");

                    AuthZResponse code = await client.AuthorizeAndGrantAsync(
                        new Dictionary<string, string>()
                        {
                            { "response_type", "code" },
                            { "client_id", ctx.ApiClientId },
                            { "scope", "openid" },
                            { "state", "state-gt" },
                            { "nonce", "nonce-gt" },
                            { "redirect_uri", UriA }
                        });

                    r.Verify("code が返る", !string.IsNullOrEmpty(code.Code),
                        "返る", string.IsNullOrEmpty(code.Code)
                            ? "**返らない（error=" + (code.Error ?? "なし") + "）**" : "返った");

                    r.Step("(2) その code の交換は、unauthorized_client で断られる");

                    JsonResponse exchanged = await client.TokenAsync(
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", code.Code },
                            { "client_id", ctx.ApiClientId },
                            { "client_secret", ctx.ApiClientSecret },
                            { "redirect_uri", UriA }
                        });

                    r.Verify("access_token を返さない",
                        string.IsNullOrEmpty(exchanged.String("access_token")),
                        "返さない", string.IsNullOrEmpty(exchanged.String("access_token"))
                            ? "返さなかった" : "**返してしまった**");

                    r.VerifyEqual("error は unauthorized_client",
                        "unauthorized_client", exchanged.String("error") ?? "（無い）");

                    r.Observe("error_description", exchanged.String("error_description") ?? "（無い）");

                    r.Step("(3) 登録した grant_type（password）は通る");

                    JsonResponse ropc = await DynamicClientRegistration.TokenAsync(
                        client, ctx.ApiClientId, ctx.ApiClientSecret,
                        ctx.OwnerName, ctx.Password);

                    r.Verify("access_token が返る",
                        !string.IsNullOrEmpty(ropc.String("access_token")),
                        "返る", string.IsNullOrEmpty(ropc.String("access_token"))
                            ? "**返らない（error=" + (ropc.String("error") ?? "なし") + "）**" : "返った");

                    r.Note("**列が空なら絞らない。** "
                        + "**通しの大半が、この経路（列を持たない既存の登録）で回っている。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.8

        /// <summary>RT-307.8 登録した scope が効く（DB に登録したクライアントでも）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30708_登録したscopeが効く(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.8",
                    "登録した `scope` が、DB に登録したクライアントでも効く",
                    "**これまで、クライアントごとの `scope` の絞りは"
                    + "構成ファイルのクライアントにしか効いていなかった** — "
                    + "**`Helper.GetClientScopes` が構成ファイル（`OAuth2ClientsInformation`）"
                    + "だけを見ていたため、DB に登録したクライアントは「登録が無い」扱いになり、"
                    + "#198 の後半（クライアントごとの絞り）が一切効かなかった**"
                    + "（`scopes_supported` の絞りだけが効いていた）。"
                    + "**#307 の段階 1 で `Scopes` の列を足し、DB も見るようにした。**",
                    "RFC 7591 §2（scope）/ RFC 6749 §3.3 / #198 / #307");

                r.Target("POST /token（登録に無い scope を要求する）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) scope を openid だけにして登録する");

                    JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"response_types\":[\"code\"],"
                        + "\"grant_types\":[\"authorization_code\"],"
                        + "\"scope\":\"openid\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)res.StatusCode).ToString());

                    r.VerifyEqual("応答の scope は openid", "openid", res.String("scope") ?? "（無い）");

                    ClientRegistration registered = new ClientRegistration()
                    {
                        ClientId = res.String("client_id"),
                        ClientSecret = res.String("client_secret"),
                        RedirectUri = UriA
                    };

                    r.Step("(2) 登録に無い scope（email）も一緒に要求する");

                    AuthZResponse withEmail = await Flows.AuthorizeCodeAsync(
                        client, registered, "openid email", "state-sc", "nonce-sc", UriA);

                    Assert.False(string.IsNullOrEmpty(withEmail.Code),
                        "前提: openid email を要求しても認可コードが取れること");

                    JsonResponse tokenWithEmail = await Flows.ExchangeCodeAsync(
                        client, registered, withEmail.Code, UriA);

                    string accessToken = tokenWithEmail.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: アクセス トークンが取れること"
                        + "（error=" + (tokenWithEmail.String("error") ?? "なし") + "）");

                    List<string> scopes = Jwt.Strings(Jwt.Payload(accessToken), "scopes");

                    r.Observe("トークンに載った scope", string.Join(" ", scopes));

                    r.VerifyEqual("登録した openid は載る", "True",
                        scopes.Contains("openid").ToString());

                    r.VerifyEqual("登録に無い email は載らない", "False",
                        scopes.Contains("email").ToString());

                    r.Note("**断る（`invalid_scope`）のではなく、外す** — "
                        + "**RFC 6749 §3.3 : 認可サーバは、要求されたスコープの"
                        + "一部または全部を無視してよい**（#198 と同じ倒し方）。 "
                        + "**列が空なら絞らない。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.9

        /// <summary>RT-307.9 登録を読める（RFC 7592 §2.1）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30709_登録を読める(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.9",
                    "`registration_client_uri` を `GET` すると、登録の全体が返る",
                    "**登録の応答は 1 回しか返らない** — "
                    + "**RP が自分の登録を確かめる口が無いと、"
                    + "「登録したつもりの値」と「実際に登録された値」の食い違いに気付けない**"
                    + "（**RFC 7591 §3.2.1 は、サーバが値を拒否・置換してよい**としている）。"
                    + "**`client_secret` は返さない** — **トークンが漏れても、秘密は漏らさない。**",
                    "RFC 7592 §2.1 / §3 / #307 の段階 2");

                r.Target("GET registration_client_uri（registration_access_token を Bearer に付ける）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 登録する（応答に管理の口と、その鍵が入る）");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid email\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)created.StatusCode).ToString());

                    string clientId = created.String("client_id");
                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Verify("registration_access_token が返る（§3 で REQUIRED）",
                        !string.IsNullOrEmpty(registrationAccessToken),
                        "返る", string.IsNullOrEmpty(registrationAccessToken)
                            ? "**返らない**" : "返った（値は出さない）");

                    r.Verify("registration_client_uri が返る（§3 で REQUIRED）",
                        !string.IsNullOrEmpty(registrationClientUri),
                        "返る", registrationClientUri ?? "**返らない**");

                    r.Verify("registration_client_uri は client_id で終わる（絶対 URI）",
                        registrationClientUri != null
                            && registrationClientUri.EndsWith("/" + clientId),
                        "終わる", (registrationClientUri == null)
                            ? "**返らない**"
                            : (registrationClientUri.EndsWith("/" + clientId)
                                ? "終わっている" : "**終わっていない**"));

                    r.Step("(2) その口を読む");

                    JsonResponse read = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)read.StatusCode).ToString());

                    r.VerifyEqual("client_id は変わらない（§2.1 の MUST）",
                        clientId, read.String("client_id") ?? "（無い）");

                    r.VerifyEqual("redirect_uris が返る", "True",
                        read.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("scope が返る", "openid email",
                        read.String("scope") ?? "（無い）");

                    r.VerifyEqual("grant_types が返る", "True",
                        read.ArrayContains("grant_types", "authorization_code").ToString());

                    r.VerifyEqual("registration_client_uri が返る（§3 で REQUIRED）",
                        registrationClientUri, read.String("registration_client_uri") ?? "（無い）");

                    r.VerifyEqual("registration_access_token が返る（§3 で REQUIRED）",
                        "True",
                        (read.String("registration_access_token")
                            == registrationAccessToken).ToString());

                    r.Verify("client_secret は返らない",
                        string.IsNullOrEmpty(read.String("client_secret")),
                        "返らない", string.IsNullOrEmpty(read.String("client_secret"))
                            ? "返らない" : "**返った**");

                    r.Note("**提示されたトークンを、そのまま返している** — "
                        + "**保管しているのはハッシュ**なので、**こうでなければ §3 の "
                        + "REQUIRED を満たせない。** **トークンは回さない**（§5 / A.1 は MAY）— "
                        + "**回すと、どちらが有効か取り違えた RP が、管理できなくなる。**");

                    r.Note("**`client_id_issued_at` は `GET` では返さない** — "
                        + "**保管していない**（§3.2.1 で任意）。**発行時の `201` だけが返す。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.10

        /// <summary>RT-307.10 PUT で全置換でき、置換が実際に効く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30710_PUTで全置換でき置換が実際に効く(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.10",
                    "`PUT` で登録を置き換えられ、**新しい値が実際に効く**",
                    "**`200` と新しい値が返るだけでは、効いたことにならない** — "
                    + "**古い `redirect_uri` が通り続けたら、置換できていない。**"
                    + "**全置換である**（§2.2 : 省いた項目は消える）ことも、ここで測る。",
                    "RFC 7592 §2.2 / RFC 6749 §3.1.2.3 / #307 の段階 2");

                r.Target("PUT registration_client_uri（全置換）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) redirect_uris = A、scope = openid email で登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid email\"}");

                    Assert.Equal(201, (int)created.StatusCode);

                    string clientId = created.String("client_id");
                    string clientSecret = created.String("client_secret");
                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Step("(2) redirect_uris = B、scope = openid に置き換える");

                    JsonResponse updated = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        DynamicClientRegistration.UpdateMetadata(clientId, "openid", UriB));

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)updated.StatusCode).ToString());

                    r.VerifyEqual("redirect_uris が B になる", "True",
                        updated.ArrayContains("redirect_uris", UriB).ToString());

                    r.VerifyEqual("redirect_uris から A が消える", "False",
                        updated.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("scope が openid になる", "openid",
                        updated.String("scope") ?? "（無い）");

                    r.Step("(3) 新しい redirect_uri（B）で認可コードが取れる");

                    ClientRegistration withB = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUri = UriB
                    };

                    AuthZResponse authzB = await Flows.AuthorizeCodeAsync(
                        client, withB, "openid email", "state-put", "nonce-put", UriB);

                    r.Verify("code が返る", !string.IsNullOrEmpty(authzB.Code),
                        "返る", string.IsNullOrEmpty(authzB.Code)
                            ? "**返らない（error=" + (authzB.Error ?? "なし") + "）**" : "返った");

                    r.Step("(4) 古い redirect_uri（A）は、もう通らない");

                    ClientRegistration withA = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUri = UriA
                    };

                    AuthZResponse authzA = await Flows.AuthorizeCodeAsync(
                        client, withA, "openid", "state-old", "nonce-old", UriA);

                    r.Observe("error", authzA.Error ?? "（無い）");

                    r.Verify("code は返らない", string.IsNullOrEmpty(authzA.Code),
                        "返らない", string.IsNullOrEmpty(authzA.Code)
                            ? "返らない" : "**返った**");

                    r.Step("(5) 置換で外した scope（email）は、トークンに載らない");

                    JsonResponse exchanged = await Flows.ExchangeCodeAsync(
                        client, withB, authzB.Code, UriB);

                    string accessToken = exchanged.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: アクセス トークンが取れること"
                        + "（error=" + (exchanged.String("error") ?? "なし") + "）");

                    List<string> scopes = Jwt.Strings(Jwt.Payload(accessToken), "scopes");

                    r.Observe("トークンに載った scope", string.Join(" ", scopes));

                    r.VerifyEqual("置換で残した openid は載る", "True",
                        scopes.Contains("openid").ToString());

                    r.VerifyEqual("置換で外した email は載らない", "False",
                        scopes.Contains("email").ToString());

                    r.Note("**`scope` を省くと、絞りが消える**（**列が空 ＝ 絞らない**。段階 1 の決め）— "
                        + "**§2.2 の「省略は削除要求」に従うと、そうなる。**"
                        + "**`client_registration` だけは、明記しても断る**（自己昇格の禁止）。");

                    r.Note("**`redirect_uris` は省けない**（OIDC DCR 1.0 §2 で必須）ので、"
                        + "**うっかり全消しにはならない**（`RT-307.13` の (4) が、それを測る）。"
                        + "**`grant_types` / `response_types` を省くと、"
                        + "RFC 7591 §2 の既定（`authorization_code` / `code`）に戻る** ＝ **狭まる。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.11

        /// <summary>RT-307.11 DELETE できて、同じ利用者が登録し直せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30711_DELETEできて登録し直せる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.11",
                    "`DELETE` で登録が消え、**既に出ているアクセス トークンも通らなくなり**、"
                    + "**同じ利用者が登録し直せる**",
                    "**消えたクライアントのトークンが期限まで通ると、払い下げの意味が無い**"
                    + "（RFC 7592 §2.3 : 削除したら、そのクライアントのトークンを無効にすべき）。"
                    + "**`VerifyAccessToken` の「クライアントがまだ在るか」の確認は、"
                    + "効いていなかった** — **`GetClientSecret` は未登録でも `\"\"` を返す**ので、"
                    + "**`!= null` が常に真**だった（**#307 の段階 2 で `Helper.HasClient` にした**）。"
                    + "**段階 1 〜 4 は 1 利用者 1 クライアントだった**ので、"
                    + "**消せないと登録し直せなかった** — **その確認も、ここで一緒に測る**"
                    + "（**段階 5-a-1 で上限は無くなった**）。",
                    "RFC 7592 §2.3 / §5 / #307 の段階 2");

                r.Target("DELETE registration_client_uri");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 登録して、そのクライアントのアクセス トークンを取る");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriA));

                    Assert.Equal(201, (int)created.StatusCode);

                    ClientRegistration registered = new ClientRegistration()
                    {
                        ClientId = created.String("client_id"),
                        ClientSecret = created.String("client_secret"),
                        RedirectUri = UriA
                    };

                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, registered, "openid email", "state-del", "nonce-del", UriA);

                    Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが取れること");

                    JsonResponse exchanged = await Flows.ExchangeCodeAsync(
                        client, registered, authz.Code, UriA);

                    string accessToken = exchanged.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: アクセス トークンが取れること");

                    JsonResponse before = await client.UserInfoWithAuthorizationAsync(
                        "Bearer " + accessToken);

                    r.VerifyEqual("消す前は /userinfo が 200", "200",
                        ((int)before.StatusCode).ToString());

                    r.Step("(2) 消す");

                    JsonResponse deleted = await DynamicClientRegistration.DeleteAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 204（§2.3 の MUST）", "204",
                        ((int)deleted.StatusCode).ToString());

                    r.Verify("本体は空", string.IsNullOrEmpty(deleted.Body),
                        "空", string.IsNullOrEmpty(deleted.Body) ? "空" : "**空でない**");

                    r.Step("(3) 既に出ていたアクセス トークンが、もう通らない");

                    JsonResponse after = await client.UserInfoWithAuthorizationAsync(
                        "Bearer " + accessToken);

                    r.VerifyEqual("/userinfo は 401", "401", ((int)after.StatusCode).ToString());

                    r.Step("(4) 2 回目の GET は 401（払い下げたトークンは無効。§5）");

                    JsonResponse readAgain = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)readAgain.StatusCode).ToString());

                    r.Step("(5) 消えたクライアントでは、認可コードも取れない");

                    AuthZResponse authzAfter = await Flows.AuthorizeCodeAsync(
                        client, registered, "openid", "state-gone", "nonce-gone", UriA);

                    r.Verify("code は返らない", string.IsNullOrEmpty(authzAfter.Code),
                        "返らない", string.IsNullOrEmpty(authzAfter.Code)
                            ? "返らない（error=" + (authzAfter.Error ?? "なし") + "）" : "**返った**");

                    r.Step("(6) 同じ利用者が、登録し直せる");

                    JsonResponse again = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriB));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)again.StatusCode).ToString());

                    r.Note("**消すのは登録の行だけ** — **所有者（`Users`）の行は触らない。** "
                        + "**所有者は `Saml2OAuth2Data.OwnerUserId`（登録の行ごと）**なので、"
                        + "**行が消えれば結び付きも一緒に消える**"
                        + "（**管理画面の削除も同じ**）。 "
                        + "**同じ利用者が、何件でも登録できる**"
                        + "（**#307 の段階 5-a-1 で上限が無くなった**）。"
                        + "**同意は落とす**（`ConsentProvider.Revoke`）。");

                    r.Note("**段階 1 〜 4 は、所有者が `Users.ClientID`（利用者の行の 1 枠）だった** — "
                        + "**`DELETE` でそこを空にしようとして、`sql` で `500` になった**"
                        + "（**NOT NULL ＋ 一意索引 ＋ 外部キー。`mem` には制約が無く、出なかった**。"
                        + "**この (6) と `RT-307.12` の (6) が捕まえた**）。"
                        + "**段階 5-a-1 で、その列ごと落とした。**");

                    r.Note("**外部のリソース サーバが、自前で JWT を検証する場合は止まらない** — "
                        + "**鍵と `exp` だけで通るため**（`/revoke` と同じ限界）。"
                        + "**この IdP の検証を通る口（`/userinfo` ほか）では止まる。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.12

        /// <summary>RT-307.12 管理 API の守り（トークンが違えば 401）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30712_管理APIの守り(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.12",
                    "管理 API は、**`registration_access_token` 以外では叩けない**",
                    "**作る権限と、直す権限は別物である**（§2 : クライアントは "
                    + "`registration_access_token` を使うこと）。"
                    + "**段階 1 の専用 scope のアクセス トークンで管理まで出来てしまうと、"
                    + "「作った人」が「他の誰かの登録」を触れる形に近づく。**"
                    + "**知らない `client_id` も `401` にする** — "
                    + "**`404` と撃ち分けると、「在るが触れない」ことが外から分かる。**",
                    "RFC 7592 §2.1 / §5 / RFC 6750 §3.1 / #307 の段階 2");

                r.Target("GET registration_client_uri（トークンを変えて叩く）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriA));

                    Assert.Equal(201, (int)created.StatusCode);

                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Step("(2) トークンを付けずに読む");

                    JsonResponse none = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, null);

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)none.StatusCode).ToString());

                    r.VerifyEqual("WWW-Authenticate が付く（RFC 6750 §3）", "True",
                        (none.Header("WWW-Authenticate") != null).ToString());

                    r.Step("(3) 偽のトークンで読む");

                    JsonResponse fake = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, "not-a-registration-access-token");

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)fake.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_token", "invalid_token",
                        fake.String("error") ?? "（無い）");

                    r.Step("(4) 段階 1 の専用 scope のアクセス トークンでは読めない");

                    JsonResponse withScopeToken = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, token);

                    r.VerifyEqual("HTTP の状態は 401", "401",
                        ((int)withScopeToken.StatusCode).ToString());

                    r.Step("(5) 知らない client_id は 401（404 ではない）");

                    string unknownUri = registrationClientUri.Substring(
                        0, registrationClientUri.LastIndexOf('/') + 1)
                        + Guid.NewGuid().ToString("N");

                    JsonResponse unknown = await DynamicClientRegistration.ReadAsync(
                        client, unknownUri, registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)unknown.StatusCode).ToString());

                    r.Step("(6) 別の登録のトークンでは触れない");

                    //  **2 つ目は、そのまま作ってもよい**（**段階 5-a-1 で上限が無くなった**）。
                    //    **消してから作り直す形のままにしてある** —
                    //    **「消した後に作り直せる」ことも、この経路で一緒に通る。**
                    Assert.Equal(204, (int)(await DynamicClientRegistration.DeleteAsync(
                        client, registrationClientUri, registrationAccessToken)).StatusCode);

                    JsonResponse other = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriB));

                    Assert.Equal(201, (int)other.StatusCode);

                    JsonResponse crossed = await DynamicClientRegistration.ReadAsync(
                        client, other.String("registration_client_uri"), registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)crossed.StatusCode).ToString());

                    r.Note("**管理画面で作った登録・段階 1 で作った登録には、"
                        + "`registration_access_token` が無い** — "
                        + "**それらは、この口では触れない**（`401`）。"
                        + "**所有者は、管理画面で自分の 1 件を編集・削除できる。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.13

        /// <summary>RT-307.13 PUT の誤りは 400 で、登録は変わらない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30713_PUTの誤りは400で登録は変わらない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.13",
                    "`PUT` のメタデータの誤りは `400` で、**登録は変わらない**",
                    "**全置換の口である**ことが、そのまま危うさになる — "
                    + "**誤った要求が中途まで適用されると、動いていた登録が壊れる。**"
                    + "**`client_id` の一致**（§2.2 の MUST）と"
                    + "**`client_secret` を自分で決めさせない**（同）ことも、ここで測る。",
                    "RFC 7592 §2.2 / RFC 7591 §3.2.2 / #307 の段階 2");

                r.Target("PUT registration_client_uri（誤ったメタデータ）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) redirect_uris = A、scope = openid で登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],\"scope\":\"openid\"}");

                    Assert.Equal(201, (int)created.StatusCode);

                    string clientId = created.String("client_id");
                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Step("(2) client_id を入れない");

                    JsonResponse noClientId = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        "{\"redirect_uris\":[\"" + UriB + "\"]}");

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)noClientId.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                        noClientId.String("error") ?? "（無い）");

                    r.Step("(3) 別の client_id を入れる");

                    JsonResponse wrongClientId = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        DynamicClientRegistration.UpdateMetadata(
                            Guid.NewGuid().ToString("N"), "openid", UriB));

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)wrongClientId.StatusCode).ToString());

                    r.Step("(4) redirect_uris を入れない（§2.2 の「省略は削除」でも、必須は必須）");

                    JsonResponse noRedirectUris = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        "{\"client_id\":\"" + clientId + "\",\"scope\":\"openid\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)noRedirectUris.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_redirect_uri", "invalid_redirect_uri",
                        noRedirectUris.String("error") ?? "（無い）");

                    r.Step("(5) 違う client_secret を入れる");

                    JsonResponse wrongSecret = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        "{\"client_id\":\"" + clientId + "\","
                        + "\"client_secret\":\"not-the-current-secret\","
                        + "\"redirect_uris\":[\"" + UriB + "\"]}");

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)wrongSecret.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                        wrongSecret.String("error") ?? "（無い）");

                    r.Step("(6) 専用 scope を、自分に付けようとする");

                    JsonResponse selfGrant = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        DynamicClientRegistration.UpdateMetadata(
                            clientId, "openid " + DynamicClientRegistration.Scope, UriA));

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)selfGrant.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_client_metadata", "invalid_client_metadata",
                        selfGrant.String("error") ?? "（無い）");

                    r.Step("(7) どの誤りでも、登録は変わっていない");

                    JsonResponse read = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)read.StatusCode).ToString());

                    r.VerifyEqual("redirect_uris は A のまま", "True",
                        read.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("redirect_uris に B は入っていない", "False",
                        read.ArrayContains("redirect_uris", UriB).ToString());

                    r.VerifyEqual("scope は openid のまま", "openid",
                        read.String("scope") ?? "（無い）");

                    r.Note("**読み取り専用の 4 つ**（`registration_access_token` / "
                        + "`registration_client_uri` / `client_id_issued_at` / "
                        + "`client_secret_expires_at`）**は、入っていても無視する** — "
                        + "**§2.2 は「入れるな」と書くが、断ると "
                        + "「`GET` して直して返す」が成り立たない。**");
                });

                r.Done();
            }
        }

        #endregion


        #region RT-307.14

        /// <summary>RT-307.14 private_key_jwt で登録すると、その鍵で認証できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30714_private_key_jwtで登録するとその鍵で認証できる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.14",
                    "token_endpoint_auth_method=private_key_jwt と jwks を登録すると、"
                    + "その鍵の client_assertion で認証でき、client_secret では認証できない",
                    "**段階 1・2 は、秘密ベースの 2 つしか登録できなかった**"
                    + "（`jwks` は断っていた）。**強い認証方法を使う配備では、"
                    + "API で作ったクライアントを、管理画面で直す手作業が残っていた。**"
                    + "**検証する側は #239 / #129 の段階 2 で実装済み**なので、"
                    + "**段階 3 で足したのは「登録を受けて列に入れる」ところだけ**である。"
                    + "**登録された方法は、認証でも効く** — "
                    + "**鍵を登録したクライアントは、秘密では通らない。**",
                    "RFC 7591 §2 / RFC 7523 §2.2 / RFC 7592 §3 / #307 の段階 3");

                r.Target("POST /register（jwks ＋ token_endpoint_auth_method）→ POST /token");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) jwks（RSA 1 本）と token_endpoint_auth_method=private_key_jwt で登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid email\","
                        + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                        + "\"jwks\":{\"keys\":[" + JwsSigner.PublicRsaJwk(client) + "]}}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)created.StatusCode).ToString());

                    string clientId = created.String("client_id");
                    string clientSecret = created.String("client_secret");

                    Assert.False(string.IsNullOrEmpty(clientId), "前提: client_id が返ること");

                    r.VerifyEqual("応答の token_endpoint_auth_method は private_key_jwt",
                        "private_key_jwt", created.String("token_endpoint_auth_method") ?? "（無い）");

                    r.VerifyEqual("応答に jwks が返る（登録した鍵）", "True",
                        (created.IsJson && created.Json.TryGetProperty("jwks", out JsonElement _))
                            .ToString());

                    //  **一律発行である**（段階 3 の決定）。**秘密しか使えない口が在る**ため
                    //    （RFC 8628 のデバイス フローは `client_assertion` を読まない）。
                    r.VerifyEqual("client_secret も返る（方法に関わらず発行する）", "True",
                        (!string.IsNullOrEmpty(clientSecret)).ToString());

                    ClientRegistration reg = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUri = UriA
                    };

                    r.Step("(2) 登録した鍵の client_assertion で、認可コードを交換する");

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid email", "state-pkj", "nonce-pkj", UriA);

                    Assert.False(string.IsNullOrEmpty(authz.Code),
                        "前提: 認可コードが取れること（error=" + (authz.Error ?? "なし") + "）");

                    JsonResponse byAssertion = await client.TokenAsync(
                        ClientRegistrationTests.WithClientAssertion(client, clientId,
                            new Dictionary<string, string>()
                            {
                                { "grant_type", "authorization_code" },
                                { "code", authz.Code },
                                { "redirect_uri", UriA }
                            }));

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)byAssertion.StatusCode).ToString());

                    r.Verify("access_token が返る", !string.IsNullOrEmpty(byAssertion.AccessToken),
                        "返る", string.IsNullOrEmpty(byAssertion.AccessToken)
                            ? "**返らない**（" + byAssertion.ToString() + "）" : "返った（値は伏せる）");

                    r.Step("(3)（対照）同じクライアントを client_secret で交換すると、通らない");

                    AuthZResponse again = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid email", "state-sec", "nonce-sec", UriA);

                    Assert.False(string.IsNullOrEmpty(again.Code),
                        "前提: 2 本目の認可コードが取れること");

                    JsonResponse bySecret = await Flows.ExchangeCodeAsync(
                        client, reg, again.Code, UriA);

                    r.VerifyEqual("HTTP の状態は 401", "401", ((int)bySecret.StatusCode).ToString());

                    r.VerifyEqual("エラーは invalid_client", "invalid_client",
                        bySecret.String("error") ?? "（無い）");

                    r.Note("**登録された方法でなければ通さない**（段階 3）。"
                        + "**以前は「登録されている資格のどれかで通る」**作りだったので、"
                        + "**鍵を登録しても、秘密でも入れた** ＝ **登録で求めた強さが効かなかった。**");

                    r.Note("**`client_secret_basic` と `client_secret_post` は区別しない** — "
                        + "**どちらで来たかを、この層は知らない**（口が同じ形に正規化して渡す）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.15

        /// <summary>RT-307.15 tls_client_auth で登録すると、その証明書で認証できる</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **既定では net10.0 版だけを測る**（`MtlsTests` と同じ前提）。
        /// **net48 版（IIS Express）は、テスト用 CA の手当てが要る**ので、
        /// **`-NetFxMtls` を付けたときだけケースを作る。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT30715_tls_client_authで登録するとその証明書で認証できる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(admin.Target);

                TestReport r = this.Report("RT-307.15",
                    "token_endpoint_auth_method=tls_client_auth と "
                    + "tls_client_auth_subject_dn を登録すると、その証明書で認証できる",
                    "**照合は `x509.Subject` との完全一致**である（RFC 8705 §2.1）。"
                    + "**検証する側は #226 で実装済み**で、**#305 の段階 4 で"
                    + "「登録が空なら通さない」まで入っている。**"
                    + "**段階 3 で足したのは、動的登録から DN を登録できるようにしたところだけ。**",
                    "RFC 8705 §2.1 / §2.1.2 / RFC 7591 §2 / #307 の段階 3");

                r.Target("POST /register（tls_client_auth_subject_dn）→ POST /token（証明書つき）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    string dn = "CN=mpas-e2e-rt307-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                    r.Step("(1) tls_client_auth と Subject DN を登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"token_endpoint_auth_method\":\"tls_client_auth\","
                        + "\"tls_client_auth_subject_dn\":\"" + dn + "\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)created.StatusCode).ToString());

                    string clientId = created.String("client_id");

                    Assert.False(string.IsNullOrEmpty(clientId), "前提: client_id が返ること");

                    r.VerifyEqual("応答の token_endpoint_auth_method は tls_client_auth",
                        "tls_client_auth", created.String("token_endpoint_auth_method") ?? "（無い）");

                    r.VerifyEqual("応答に tls_client_auth_subject_dn が返る",
                        dn, created.String("tls_client_auth_subject_dn") ?? "（無い）");

                    ClientRegistration reg = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = created.String("client_secret"),
                        RedirectUri = UriA
                    };

                    r.Step("(2) Subject が一致する証明書を添えて交換する（client_secret は送らない）");

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid", "state-mtls", "nonce-mtls", UriA);

                    Assert.False(string.IsNullOrEmpty(authz.Code),
                        "前提: 認可コードが取れること（error=" + (authz.Error ?? "なし") + "）");

                    JsonResponse matched;

                    using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, dn))
                    {
                        matched = await client.TokenWithCertificateAsync(
                            new Dictionary<string, string>()
                            {
                                { "grant_type", "authorization_code" },
                                { "code", authz.Code },
                                { "client_id", clientId },
                                { "redirect_uri", UriA }
                            }, cert);
                    }

                    r.Verify("access_token が返る", !string.IsNullOrEmpty(matched.AccessToken),
                        "返る", string.IsNullOrEmpty(matched.AccessToken)
                            ? "**返らない**（" + matched.ToString() + "）" : "返った（値は伏せる）");

                    r.Step("(3)（対照）Subject が違う証明書では、通らない");

                    AuthZResponse again = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid", "state-other", "nonce-other", UriA);

                    Assert.False(string.IsNullOrEmpty(again.Code),
                        "前提: 2 本目の認可コードが取れること");

                    JsonResponse other;

                    using (X509Certificate2 cert = TestCertificate.ForTarget(
                        client.Target, MtlsTests.OtherSubjectDn))
                    {
                        other = await client.TokenWithCertificateAsync(
                            new Dictionary<string, string>()
                            {
                                { "grant_type", "authorization_code" },
                                { "code", again.Code },
                                { "client_id", clientId },
                                { "redirect_uri", UriA }
                            }, cert);
                    }

                    r.Verify("access_token は返らない", string.IsNullOrEmpty(other.AccessToken),
                        "返らない", string.IsNullOrEmpty(other.AccessToken)
                            ? "返らない（HTTP " + (int)other.StatusCode
                                + " / error=" + (other.String("error") ?? "なし") + "）"
                            : "**返った**");

                    r.Note("**DN は 1 文字も違ってはならない**（`#263` の `redirect_uri` と同じ厳しさ）。"
                        + "**`tls_client_auth` を登録すると、RFC 8705 §3 の"
                        + "「証明書に縛られたアクセス トークン」も効く**（既存の振る舞い）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.16

        /// <summary>RT-307.16 方法と鍵の誤りは、登録の時点で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30716_方法と鍵の誤りは登録の時点で断る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.16",
                    "認証できない登録は作らせない（材料が無い・鍵が多い・知らない方法・jwks_uri）",
                    "**黙って作ると、クライアントは「登録した方法で認証できる」と考えるが、"
                    + "永久に通らない。** **どれも「無視すると黙って弱くなる／壊れる」もの**なので、"
                    + "**登録の時点で断る**（RFC 7591 §3.2.2 : `invalid_client_metadata`）。",
                    "RFC 7591 §2 / §3.2.2 / RFC 7517 §5 / RFC 8705 §2.1.2 / #307 の段階 3");

                r.Target("POST /register（誤ったメタデータ）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    string head = "{\"redirect_uris\":[\"" + UriA + "\"],";
                    string rsaJwk = JwsSigner.PublicRsaJwk(client);

                    r.Step("(1) private_key_jwt なのに jwks が無い");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"token_endpoint_auth_method\":\"private_key_jwt\"}",
                        "鍵が無ければ、その方法では認証できない");

                    r.Step("(2) tls_client_auth なのに tls_client_auth_subject_dn が無い");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"token_endpoint_auth_method\":\"tls_client_auth\"}",
                        "DN が無ければ、照合する相手が無い");

                    r.Step("(3) 知らない token_endpoint_auth_method");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"token_endpoint_auth_method\":\"client_secret_jwt\"}",
                        "広告していない方法（既知でない値は拒否する。#224 の段階 2 と同じ方針）");

                    r.Step("(4) jwks に RSA が 2 本");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"jwks\":{\"keys\":[" + rsaJwk + "," + rsaJwk + "]}}",
                        "列は RSA 1 本しか持てない。先頭を採ると、もう一方の鍵で署名したときに失敗する");

                    r.Step("(5) jwks_uri（鍵を URL から引く）は、受け付けない");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"jwks_uri\":\"https://rp.example/jwks.json\"}",
                        "クライアント認証の経路が同期なので、取得を差し込めない（別 Issue）");

                    r.Step("(6) device_code グラント × private_key_jwt");

                    await this.VerifyRegistrationErrorAsync(r, client, endpoint, token,
                        head + "\"grant_types\":[\"urn:ietf:params:oauth:grant-type:device_code\"],"
                        + "\"response_types\":[],"
                        + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                        + "\"jwks\":{\"keys\":[" + rsaJwk + "]}}",
                        "RFC 8628 の口は client_assertion を読まないので、永久に認証できない");

                    r.Note("**`jwks` と `jwks_uri` を同時に送ることも断る**"
                        + "（RFC 7591 §2 は、どちらか一方としている）。"
                        + "**ここでは `jwks_uri` を単独で送って断られることだけを測った。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.17

        /// <summary>RT-307.17 PUT で方法を省くと秘密に戻るが、鍵は消えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30717_PUTで方法を省くと秘密に戻るが鍵は消えない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.17",
                    "PUT で token_endpoint_auth_method を省くと秘密ベースに戻り、jwks は持ち越される",
                    "**`PUT` は全置換**（§2.2 : 省いた項目は「消す要求」）。"
                    + "**方法は、その規則どおり省略で消える** ＝ **秘密ベースに戻る。**"
                    + "**鍵と DN だけは持ち越す** — **管理画面から入れた鍵を、"
                    + "`PUT` で消してはならない**（段階 2 の「動的登録で設定できない列」と同じ考え方）。"
                    + "**方法を明記するなら、材料も毎回送ること**（材料が無ければ `400`）。",
                    "RFC 7592 §2.2 / §3 / #307 の段階 3");

                r.Target("POST /register → PUT（方法と jwks を省く）→ GET");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) private_key_jwt ＋ jwks で登録する");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"token_endpoint_auth_method\":\"private_key_jwt\","
                        + "\"jwks\":{\"keys\":[" + JwsSigner.PublicRsaJwk(client) + "]}}");

                    Assert.Equal(201, (int)created.StatusCode);

                    string clientId = created.String("client_id");
                    string clientSecret = created.String("client_secret");
                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Step("(2) 方法と jwks を省いて PUT する（redirect_uris と client_id だけ）");

                    JsonResponse updated = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        DynamicClientRegistration.UpdateMetadata(clientId, "openid", UriA));

                    r.VerifyEqual("HTTP の状態は 200", "200", ((int)updated.StatusCode).ToString());

                    r.VerifyEqual("token_endpoint_auth_method は client_secret_basic に戻る",
                        "client_secret_basic",
                        updated.String("token_endpoint_auth_method") ?? "（無い）");

                    r.VerifyEqual("jwks は残っている（省いても消さない）", "True",
                        (updated.IsJson && updated.Json.TryGetProperty("jwks", out JsonElement _))
                            .ToString());

                    r.Step("(3) GET で読み直しても、同じである");

                    JsonResponse read = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("GET も client_secret_basic", "client_secret_basic",
                        read.String("token_endpoint_auth_method") ?? "（無い）");

                    r.VerifyEqual("GET でも jwks が返る", "True",
                        (read.IsJson && read.Json.TryGetProperty("jwks", out JsonElement _))
                            .ToString());

                    r.Step("(4) 秘密ベースに戻ったので、client_secret で交換できる");

                    ClientRegistration reg = new ClientRegistration()
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUri = UriA
                    };

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid", "state-back", "nonce-back", UriA);

                    Assert.False(string.IsNullOrEmpty(authz.Code),
                        "前提: 認可コードが取れること（error=" + (authz.Error ?? "なし") + "）");

                    JsonResponse exchanged = await Flows.ExchangeCodeAsync(
                        client, reg, authz.Code, UriA);

                    r.Verify("access_token が返る", !string.IsNullOrEmpty(exchanged.AccessToken),
                        "返る", string.IsNullOrEmpty(exchanged.AccessToken)
                            ? "**返らない**（" + exchanged.ToString() + "）" : "返った（値は伏せる）");

                    r.Note("**省略で方法が戻るのは、§2.2 のとおり**である。"
                        + "**ただし「方法だけ戻って、鍵が残る」状態になる** — "
                        + "**鍵は使われなくなるだけで、害は無い**"
                        + "（**認証に使えるのは、登録された方法だけ**）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.18

        /// <summary>RT-307.18 software_statement で登録でき、主張が本文に勝つ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30718_software_statementで登録でき主張が本文に勝つ(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.18",
                    "署名付きの `software_statement` で登録でき、**主張した値が本文（plain JSON）に勝つ**",
                    "**これが機能の要点である。** **ベンダは security に効く項目を statement で固定し**、"
                    + "**配置ごとに変わる項目は本文に書かせる。** "
                    + "**配置側が折り返し先を勝手な所に書き換えても、statement が上書きして効かない。** "
                    + "**201 が返るだけでは足りない** — **どちらの値で登録されたかを、"
                    + "実際の認可要求で確かめる。**",
                    "RFC 7591 §2.3（MUST take precedence）/ §3.1.1 / #307 の段階 4");

                r.Target("POST /register（本文は B、statement は A を主張する）");

                ClientRegistrationTests.SkipIfNoSoftwareStatement();

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 本文は redirect_uris = B、statement は A を主張する");

                    Dictionary<string, object> claims =
                        ClientRegistrationTests.StatementClaims();

                    claims.Add("redirect_uris", new string[] { UriA });

                    string statement = JwsSigner.SignRS256(client, claims);

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriB + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"software_statement\":\"" + statement + "\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)created.StatusCode).ToString());

                    r.VerifyEqual("redirect_uris は A（statement が勝つ）", "True",
                        created.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("redirect_uris に B は入らない", "False",
                        created.ArrayContains("redirect_uris", UriB).ToString());

                    r.Step("(2) statement だけに在る項目は、そのまま使われる");

                    r.VerifyEqual("software_id が入る",
                        ClientRegistrationTests.SoftwareId,
                        created.String("software_id") ?? "（無い）");

                    r.Step("(3) 本文だけに在る項目も、そのまま使われる");

                    r.VerifyEqual("scope は本文の値", "openid",
                        created.String("scope") ?? "（無い）");

                    r.Step("(4) software_statement 自身は、応答に出ない（保管しない）");

                    r.VerifyEqual("software_statement は返らない", "False",
                        (created.IsJson
                            && created.Json.TryGetProperty("software_statement", out JsonElement _))
                                .ToString());

                    r.Step("(5) 主張された折り返し先（A）で、実際に認可コードが取れる");

                    ClientRegistration reg = new ClientRegistration()
                    {
                        ClientId = created.String("client_id"),
                        ClientSecret = created.String("client_secret"),
                        RedirectUri = UriA
                    };

                    AuthZResponse allowed = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid", "state-ss", "nonce-ss", UriA);

                    r.Verify("A では認可コードが返る", !string.IsNullOrEmpty(allowed.Code),
                        "返る", string.IsNullOrEmpty(allowed.Code)
                            ? "**返らない**（error=" + (allowed.Error ?? "なし") + "）" : "返った");

                    r.Step("(6) 本文に書いた折り返し先（B）では、通らない");

                    AuthZResponse refused = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid", "state-ss2", "nonce-ss2", UriB);

                    r.Verify("B では認可コードが返らない", string.IsNullOrEmpty(refused.Code),
                        "返らない", string.IsNullOrEmpty(refused.Code)
                            ? "返らなかった（error=" + (refused.Error ?? "なし") + "）"
                            : "**返ってしまった**");

                    r.Note("**食い違っても断らない。** **statement を採り、オペレーション ログに残す**"
                        + "（§2.3 が優先順位を MUST で定めているため）。"
                        + "**上書きされた項目の名前だけを残し、値は書かない。**");

                    r.Note("**statement は認可ではない。** "
                        + "**この登録でも、専用 scope のアクセス トークンは要る**"
                        + "（**statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.19

        /// <summary>RT-307.19 壊れた software_statement は 400 ＋ invalid_software_statement</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30719_壊れたsoftware_statementは400(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.19",
                    "壊れた `software_statement` は `400` ＋ `invalid_software_statement`",
                    "**「読めたが信頼していない」のと「壊れている」のを分ける**（§3.2.2 の 2 つのコード）。"
                    + "**黙って無視してはならない** — "
                    + "**クライアントは「主張した内容で登録された」と考える。**",
                    "RFC 7591 §2.3 / §3.2.2（invalid_software_statement）/ #307 の段階 4");

                r.Target("POST /register（statement を 5 通りに壊す）");

                ClientRegistrationTests.SkipIfNoSoftwareStatement();

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) JWT ではない値");

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        "eyJ.eyJ.sig", "invalid_software_statement",
                        "3 つに分かれていても、Base64URL の JSON でなければ読めない");

                    r.Step("(2) 署名が合わない（最後の 1 文字を変える）");

                    string signed = JwsSigner.SignRS256(
                        client, ClientRegistrationTests.StatementClaims());

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        ClientRegistrationTests.Tamper(signed), "invalid_software_statement",
                        "発行者の証明書で検証して落ちる");

                    r.Step("(3) iss が無い（§2.3 は必須）");

                    Dictionary<string, object> noIss =
                        ClientRegistrationTests.StatementClaims();

                    noIss.Remove("iss");

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        JwsSigner.SignRS256(client, noIss), "invalid_software_statement",
                        "iss が無いと、どの発行者の鍵で検証するかが決まらない");

                    r.Step("(4) exp が切れている");

                    Dictionary<string, object> expired =
                        ClientRegistrationTests.StatementClaims();

                    expired.Add("exp", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 60);

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        JwsSigner.SignRS256(client, expired), "invalid_software_statement",
                        "exp は任意だが、在るなら効かせる（切れた保証を使わせない）");

                    r.Step("(5) aud が、この認可サーバではない");

                    Dictionary<string, object> otherAud =
                        ClientRegistrationTests.StatementClaims();

                    otherAud.Add("aud", "https://other-as.example.com");

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        JwsSigner.SignRS256(client, otherAud), "invalid_software_statement",
                        "他の認可サーバ向けの statement を、ここで使い回させない");

                    r.Note("**`aud` の扱いは、仕様が定めていない。** "
                        + "**在るときだけ `IssuerId` と照合する**（無い statement は通る）。"
                        + "**在るのに見ないと、他の AS へ出した保証がそのまま通る。**");

                    r.Note("**`iat` / `nbf` は見ない**（段階 4 の決定）。"
                        + "**`exp` が在れば、それで足りる。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.20

        /// <summary>RT-307.20 知らない発行者は 400 ＋ unapproved_software_statement</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30720_知らない発行者は400(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.20",
                    "**知らない発行者**の `software_statement` は `400` ＋ `unapproved_software_statement`",
                    "**署名が正しいことと、信頼していることは別である。** "
                    + "**鍵は「発行者ごと」に設定で登録する** — "
                    + "**設定に無い `iss` は、署名が通る鍵で作られていても受けない。**",
                    "RFC 7591 §3.2.2（unapproved_software_statement）/ #307 の段階 4");

                r.Target("POST /register（iss だけを、設定に無い値にする）");

                ClientRegistrationTests.SkipIfNoSoftwareStatement();

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 同じ鍵で署名し、iss だけを設定に無い値にする");

                    Dictionary<string, object> claims =
                        ClientRegistrationTests.StatementClaims();

                    claims["iss"] = "https://unknown-vendor.example.com";

                    await this.VerifyStatementErrorAsync(r, client, endpoint, token,
                        JwsSigner.SignRS256(client, claims), "unapproved_software_statement",
                        "署名は通る鍵だが、その iss を信頼していない");

                    r.Note("**信頼する発行者を 1 件も設定していない配備では、"
                        + "どの statement もこれになる**（**従来どおり**）。"
                        + "**段階 4 の設定を書いていない配備の振る舞いは、変わっていない。**");

                    r.Note("**認可の判定（401 / 403）が先である。** "
                        + "**認可されていない相手には、自分の statement が信頼されているかを教えない** — "
                        + "**信頼一覧の中身を、外から探らせないため。**");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.21

        /// <summary>RT-307.21 PUT でも software_statement が効く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30721_PUTでもsoftware_statementが効く(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-307.21",
                    "`PUT`（RFC 7592）でも `software_statement` が効き、**省くと本文が通る**",
                    "**検査は `Validate` の 1 か所**なので、**`POST` と `PUT` で同じ判定になる。**"
                    + "**省いたときの振る舞いまで測る** — "
                    + "**statement を保管しない**決めの帰結であり、"
                    + "**`RequireSoftwareStatement` で閉じる穴**だからである。",
                    "RFC 7592 §2.2（全置換）/ RFC 7591 §2.3 / #307 の段階 4");

                r.Target("POST /register → PUT（statement 付き）→ PUT（statement なし）");

                ClientRegistrationTests.SkipIfNoSoftwareStatement();

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) statement（A を主張）で登録する");

                    Dictionary<string, object> claims =
                        ClientRegistrationTests.StatementClaims();

                    claims.Add("redirect_uris", new string[] { UriA });

                    string statement = JwsSigner.SignRS256(client, claims);

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"software_statement\":\"" + statement + "\"}");

                    Assert.Equal(201, (int)created.StatusCode);

                    string clientId = created.String("client_id");
                    string registrationAccessToken = created.String("registration_access_token");
                    string registrationClientUri = created.String("registration_client_uri");

                    r.Step("(2) PUT の本文は B、statement は A を主張する → A のまま");

                    JsonResponse withStatement = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        "{\"client_id\":\"" + clientId + "\","
                        + "\"redirect_uris\":[\"" + UriB + "\"],"
                        + "\"scope\":\"openid\","
                        + "\"software_statement\":\"" + statement + "\"}");

                    r.VerifyEqual("HTTP の状態は 200", "200",
                        ((int)withStatement.StatusCode).ToString());

                    r.VerifyEqual("redirect_uris は A のまま（statement が勝つ）", "True",
                        withStatement.ArrayContains("redirect_uris", UriA).ToString());

                    r.VerifyEqual("B にはならない", "False",
                        withStatement.ArrayContains("redirect_uris", UriB).ToString());

                    r.Step("(3) 壊れた statement を添えた PUT は 400（登録は変わらない）");

                    JsonResponse broken = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        "{\"client_id\":\"" + clientId + "\","
                        + "\"redirect_uris\":[\"" + UriB + "\"],"
                        + "\"software_statement\":\"" + ClientRegistrationTests.Tamper(statement)
                        + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)broken.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_software_statement",
                        "invalid_software_statement", broken.String("error") ?? "（無い）");

                    JsonResponse unchanged = await DynamicClientRegistration.ReadAsync(
                        client, registrationClientUri, registrationAccessToken);

                    r.VerifyEqual("登録は変わっていない（A のまま）", "True",
                        unchanged.ArrayContains("redirect_uris", UriA).ToString());

                    r.Step("(4) statement を省いた PUT は、本文が通る（全置換）");

                    JsonResponse withoutStatement = await DynamicClientRegistration.UpdateAsync(
                        client, registrationClientUri, registrationAccessToken,
                        DynamicClientRegistration.UpdateMetadata(clientId, "openid", UriB));

                    r.VerifyEqual("HTTP の状態は 200", "200",
                        ((int)withoutStatement.StatusCode).ToString());

                    r.VerifyEqual("redirect_uris は B になる", "True",
                        withoutStatement.ArrayContains("redirect_uris", UriB).ToString());

                    r.Note("**(4) は仕様どおりである**（RFC 7592 §2.2 は全置換で、"
                        + "**`software_statement` を省いた要求は「statement 無しの登録」**）。"
                        + "**statement を保管しない**決め（§3.2.1 で任意）の帰結でもある。");

                    r.Note("**閉じたい配備は `RequireSoftwareStatement` を true にする** — "
                        + "**`PUT` にも効く**ので、**statement を毎回添えないと `400`** になる。"
                        + "**この E2E は false の配備で測っている**"
                        + "（**true にすると既存の `RT-307.*` が全部落ちる**ため）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.22

        /// <summary>RT-307.22 client_credentials で登録でき、所有者はそのクライアントの所有者</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **利用者のパスワードを使わずに登録する**（#307 の段階 5-b）。
        ///
        /// **段階 1 〜 5-a は、所有者を AT の `sub` からしか引けなかった** —
        /// **ROPC（利用者のパスワード）を開けないと、動的登録が使えなかった。**
        ///
        /// **ここで測るのは「登録の表のクライアント」の側**である
        /// （**所有者は `OwnerUserId`**）。
        /// **構成ファイルの `owner` の側は `RT-307.23`。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30722_client_credentialsで登録でき所有者はクライアントの所有者(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                //  **動的登録と client_credentials の両方が開いている配備でしか測れない。**
                await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "client_credentials");
                string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

                TestReport r = this.Report("RT-307.22",
                    "**`client_credentials` のトークンで登録でき**、"
                    + "**所有者は「認証したクライアントの所有者」になる**",
                    "**段階 1 〜 5-a は、所有者をトークンの `sub` からしか引けなかった** — "
                    + "**ROPC を開けないと動的登録が使えなかった**（利用者のパスワードが要る）。"
                    + "**CI / IaC から叩くのに、利用者のパスワードを置きたくない。**"
                    + "**段階 5-b で、利用者の居ないトークンも受ける** — "
                    + "**作る登録の所有者は、認証したクライアントの所有者**である。",
                    "RFC 6749 §4.4 / #307 の段階 5-b");

                r.Target("POST /token（client_credentials）→ POST /register");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                //  **使い捨ての利用者**（**ロールは `Admin`** — 管理画面を開くため）。
                string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                string name = "e2e_rt30722_" + suffix;
                string renamedTo = "e2e_rt30722_r_" + suffix;

                await UsersAdmin.CreateAsync(admin, name, name + "@example.com", "Admin");

                try
                {
                    string apiClientId = null;
                    string apiClientSecret = null;

                    using (IdPClient owner = this.Client(targetKey))
                    {
                        Assert.True(
                            await owner.TrySignInAsync(name, admin.Config.Get("TestUserPWD")),
                            "前提: 使い捨ての利用者でサインインできること");

                        r.Step("(1) 画面から、専用 scope を持つクライアントを登録する");

                        //  **動的登録では `client_registration` を配れない**
                        //    （`RT-307.4` の (7) が測っている）ので、**画面から**作る。
                        (string ClientId, string ClientSecret) registered =
                            await ManageClientRegistration.RegisterWithSecretAsync(owner,
                                new Dictionary<string, string>()
                                {
                                    { "Scopes", DynamicClientRegistration.Scope }
                                });

                        apiClientId = registered.ClientId;
                        apiClientSecret = registered.ClientSecret;

                        r.Verify("登録できる", !string.IsNullOrEmpty(apiClientId),
                            "登録できる", string.IsNullOrEmpty(apiClientId)
                                ? "**登録できない**" : apiClientId);

                        Assert.False(string.IsNullOrEmpty(apiClientId),
                            "前提: 画面からクライアントを登録できること");

                        r.VerifyEqual("この時点の一覧は 1 件", "1",
                            (await ManageClientRegistration.ListAsync(owner)).Count.ToString());

                        r.Step("(2) 所有者の利用者名を変える");

                        //  **これを挟まないと、新しい道を測れない**（実測で踏んだ）。
                        //    **登録の `ClientName` には所有者の利用者名が入る**（段階 5-a）ので、
                        //    **`client_credentials` の `sub`（＝ `ClientName`）から
                        //      利用者が引けてしまう** —
                        //    **「クライアントの所有者から引く」道を通らずに通ってしまう。**
                        //
                        //  **名前を変えると `ClientName` は古い名前のまま残る**
                        //    （**ラベルだから**。段階 5-a の決め）ので、
                        //    **`sub` では引けなくなり、`OwnerUserId` から引く道だけが残る。**
                        //
                        //  **「利用者名を変えても切れない」こと**（段階 5-a-1 の主張）
                        //    **を、正面から測ることにもなる。**
                        bool renamed = await ClientRegistrationTests.RenameUserAsync(
                            owner, renamedTo, admin.Config.Get("TestUserPWD"));

                        r.Verify("利用者名を変えられる", renamed,
                            "変えられる", renamed ? "変えた" : "**変えられない**");

                        Assert.True(renamed, "前提: 所有者の利用者名を変えられること");

                        r.Note("**この時点で、登録の `ClientName` は古い名前のまま**である"
                            + "（**ラベルだから**。段階 5-a）。"
                            + "**所有者の鍵は `OwnerUserId`**（`Users.Id`）なので、**切れない。**");
                    }

                    r.Step("(3) client_credentials で、専用 scope のトークンを取る");

                    JsonResponse token = await DynamicClientRegistration.ClientCredentialsTokenAsync(
                        admin, apiClientId, apiClientSecret);

                    string accessToken = token.String("access_token");

                    r.Verify("access_token が返る", !string.IsNullOrEmpty(accessToken),
                        "返る", string.IsNullOrEmpty(accessToken)
                            ? "**返らない**（error=" + (token.String("error") ?? "なし") + "）"
                            : "返った（値は出さない）");

                    r.VerifyEqual("scope は専用 scope 1 本",
                        DynamicClientRegistration.Scope, token.String("scope") ?? "（無い）");

                    r.Note("**他の scope と混ぜない** — **ROPC の経路と同じ規則**である"
                        + "（段階 1）。**期限も `DcrAccessTokenExpireTimeSpanFromSeconds`** に絞る。");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: client_credentials でトークンが取れること");

                    r.Step("(4) そのトークンで登録できる");

                    JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                        admin, endpoint, accessToken,
                        DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)res.StatusCode).ToString());

                    string newClientId = res.String("client_id");

                    r.Verify("client_id が返る", !string.IsNullOrEmpty(newClientId),
                        "返る", string.IsNullOrEmpty(newClientId) ? "**返らない**" : newClientId);

                    r.Step("(5) 所有者は、認証したクライアントの所有者である");

                    using (IdPClient owner = this.Client(targetKey))
                    {
                        //  **新しい名前で入る**（**名前を変えた後**である）。
                        Assert.True(
                            await owner.TrySignInAsync(
                                renamedTo, admin.Config.Get("TestUserPWD")),
                            "前提: 名前を変えた利用者でサインインできること");

                        List<string> listed = await ManageClientRegistration.ListAsync(owner);

                        r.VerifyEqual("その人の一覧は 2 件になる", "2", listed.Count.ToString());

                        r.Verify("動的登録で作った 1 件が、その人の一覧に出る",
                            listed.Contains(newClientId),
                            "出る", listed.Contains(newClientId) ? "出た" : "**出ない**");
                    }

                    r.Note("**所有者が決まるのは、認証したクライアントが所有者を持っているから**である。"
                        + "**構成ファイル発のクライアントは `owner` 属性**で持つ（`RT-307.23`）。"
                        + "**所有者を持たないクライアントでは断る**（`RT-307.24`）。");

                    r.Done();
                }
                finally
                {
                    //  **利用者を消すと、その人の登録は全部消える**
                    //    （`OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`。段階 5-a-1）。
                    //  **名前を変えているので、両方を試す**（**落ちた回の後始末**）。
                    await UsersAdmin.DeleteByUserNameAsync(admin, renamedTo);
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }
            }
        }

        #endregion

        #region RT-307.23

        /// <summary>RT-307.23 構成ファイルの owner から、所有者が決まる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **構成ファイル発のクライアントは、`owner` 属性（利用者名）で所有者を持つ**
        /// （#307 の段階 5-b）。
        ///
        /// **`test.ps1` が渡すのは net10.0 版にだけ**である —
        /// **net10.0 は設定を「節」として読む**のでクライアントを 1 件ずつ足せるが、
        /// **net48 は 1 本の JSON 文字列**で、**足すと雛形のクライアントを全て置き換えてしまう。**
        /// **net48 では Skip する**（`RT-307.15` と同じ作法）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30723_構成ファイルのownerから所有者が決まる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                //  **動的登録と client_credentials の両方が開いている配備でしか測れない。**
                await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "client_credentials");
                string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

                string clientId = ClientRegistrationTests.DcrCcClientId(targetKey);
                string clientSecret = ClientRegistrationTests.DcrCcClientSecret(targetKey);
                string ownerName = ClientRegistrationTests.DcrCcOwner(targetKey);

                Skip.If(string.IsNullOrEmpty(clientId)
                    || string.IsNullOrEmpty(clientSecret)
                    || string.IsNullOrEmpty(ownerName),
                    "この対象には、構成ファイル発の動的登録クライアントを渡していません"
                    + "（test.ps1 は net10.0 版にだけ渡す。#307 の段階 5-b）。");

                TestReport r = this.Report("RT-307.23",
                    "**構成ファイルの `owner`（利用者名）から、登録の所有者が決まる**",
                    "**構成ファイル発のクライアントは、利用者の行と結び付いていない** — "
                    + "**配備全体のもの**である。**`owner` を 1 属性足して、持ち主を書けるようにした**"
                    + "（#307 の段階 5-b）。**`client_credentials` で叩いたときの所有者**になる。"
                    + "**名前で持つ**のは**設定ファイルは人が書く物**だからで、"
                    + "**利用者名を変えたら設定も直す**必要がある"
                    + "（**登録の表の側は `Users.Id` なので切れない**）。",
                    "#307 の段階 5-b / Helper.GetOwnerUserId");

                r.Target("POST /token（client_credentials。構成ファイル発）→ POST /register");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                r.Step("(1) `owner` に書かれた利用者を作る");

                //  **設定に書いた名前の利用者を、ここで作る**
                //    （**種データの利用者を使わない** — **他のケースと登録を奪い合わないため**）。
                //    **ロールは `Admin`**（所有者の一覧を画面で見るため）。
                await UsersAdmin.DeleteByUserNameAsync(admin, ownerName);
                await UsersAdmin.CreateAsync(admin, ownerName, ownerName + "@example.com", "Admin");

                try
                {
                    r.Step("(2) client_credentials で、専用 scope のトークンを取る");

                    JsonResponse token = await DynamicClientRegistration.ClientCredentialsTokenAsync(
                        admin, clientId, clientSecret);

                    string accessToken = token.String("access_token");

                    r.Verify("access_token が返る", !string.IsNullOrEmpty(accessToken),
                        "返る", string.IsNullOrEmpty(accessToken)
                            ? "**返らない**（error=" + (token.String("error") ?? "なし") + "）"
                            : "返った（値は出さない）");

                    r.VerifyEqual("scope は専用 scope 1 本",
                        DynamicClientRegistration.Scope, token.String("scope") ?? "（無い）");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: client_credentials でトークンが取れること");

                    r.Step("(3) 登録できる");

                    JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                        admin, endpoint, accessToken,
                        DynamicClientRegistration.Metadata(UriA));

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)res.StatusCode).ToString());

                    string newClientId = res.String("client_id");

                    r.Step("(4) 所有者は、`owner` に書かれた利用者である");

                    using (IdPClient owner = this.Client(targetKey))
                    {
                        Assert.True(
                            await owner.TrySignInAsync(ownerName, admin.Config.Get("TestUserPWD")),
                            "前提: owner の利用者でサインインできること");

                        List<string> listed = await ManageClientRegistration.ListAsync(owner);

                        r.Verify("その人の一覧に出る", listed.Contains(newClientId),
                            "出る", listed.Contains(newClientId)
                                ? "出た（" + listed.Count + " 件）" : "**出ない**");
                    }

                    r.Note("**`ClientName` は所有者の利用者名**である（従来どおり）。"
                        + "**`client_name` を要求に書いても無視する**（RFC 7591 §3.2.1 が認めている）。");

                    r.Done();
                }
                finally
                {
                    //  **利用者を消すと、その人の登録も消える**（cascade）。
                    await UsersAdmin.DeleteByUserNameAsync(admin, ownerName);
                }
            }
        }

        #endregion

        #region RT-307.24

        /// <summary>RT-307.24 所有者の決まらないクライアントでは断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`owner` を書いていない構成ファイルのクライアント**は、
        /// **配備全体のもの**であって、**1 人の持ち物ではない**（#307 の段階 5-b）。
        /// **その登録を誰のものにもできない**ので、**断る。**
        ///
        /// **`403` である**（**トークンは正しい**）。
        /// **`401` にすると「取り直せ」と読めて誤誘導**になる。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30724_所有者の決まらないクライアントでは断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                //  **動的登録と client_credentials の両方が開いている配備でしか測れない。**
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "client_credentials");
                string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(client);

                string clientId = ClientRegistrationTests.DcrCcNoOwnerClientId(targetKey);
                string clientSecret = ClientRegistrationTests.DcrCcNoOwnerSecret(targetKey);

                Skip.If(string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret),
                    "この対象には、所有者の無い動的登録クライアントを渡していません"
                    + "（test.ps1 は net10.0 版にだけ渡す。#307 の段階 5-b）。");

                TestReport r = this.Report("RT-307.24",
                    "**所有者の決まらないクライアントでは、登録を断る**（`403` ＋ `access_denied`）",
                    "**`client_credentials` のトークンには利用者が居ない**ので、"
                    + "**所有者は認証したクライアントから引く**（#307 の段階 5-b）。"
                    + "**引けないことがある** — **`owner` を書いていない構成ファイルのクライアント**"
                    + "（配備全体のもの）、**`owner` の利用者が居ない**（設定の誤り）、"
                    + "**所有者の無い登録**（種データ）。"
                    + "**そのときは断る** — **誰のものでもない登録を作らない。**",
                    "#307 の段階 5-b / ClientRegistrationProvider.Register");

                r.Target("POST /register（所有者の無いクライアントのトークン）");

                r.Step("(1) client_credentials で、専用 scope のトークンを取る");

                JsonResponse token = await DynamicClientRegistration.ClientCredentialsTokenAsync(
                    client, clientId, clientSecret);

                string accessToken = token.String("access_token");

                r.Verify("トークンそのものは取れる", !string.IsNullOrEmpty(accessToken),
                    "取れる", string.IsNullOrEmpty(accessToken)
                        ? "**取れない**（error=" + (token.String("error") ?? "なし") + "）"
                        : "取れた（値は出さない）");

                r.Note("**トークンの発行は通る** — **`scope` は登録に明記してある。**"
                    + "**止まるのは `/register` の側**で、**所有者が決まらないため**である。");

                Assert.False(string.IsNullOrEmpty(accessToken),
                    "前提: client_credentials でトークンが取れること");

                r.Step("(2) 登録は断られる");

                JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                    client, endpoint, accessToken,
                    DynamicClientRegistration.Metadata(UriA));

                r.VerifyEqual("HTTP の状態は 403", "403", ((int)res.StatusCode).ToString());

                r.VerifyEqual("error は access_denied",
                    "access_denied", res.String("error") ?? "（無い）");

                r.Verify("client_id は返らない",
                    string.IsNullOrEmpty(res.String("client_id")),
                    "返らない", string.IsNullOrEmpty(res.String("client_id"))
                        ? "返らない" : "**返った**");

                r.Note("**`401` ではない** — **トークンは正しい。**"
                    + "**`401` にすると「取り直せ」と読めて、同じ失敗を繰り返させる。**");

                r.Done();
            }
        }

        #endregion

        #region RT-307.25

        /// <summary>RT-307.25 発行者に許した範囲の外は、断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **発行者ごとの上限**（`allowed_scope` / `allowed_grant_types`。#307 の段階 6）。
        ///
        /// **絞るのは「受け入れる側」の決め**である。
        /// **ベンダが自分で絞る分は statement の中身に書けば済む**（段階 4）ので、
        /// **実際に登録に入るのは 2 つの積**になる。
        ///
        /// **本文（plain JSON）由来の値も上限に収める** —
        /// **statement に書かれていなければ本文の値が登録の値になる**ためである。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30725_発行者に許した範囲の外は断る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                ClientRegistrationTests.SkipIfNoSoftwareStatement();
                ClientRegistrationTests.SkipIfNoAllowedScope();

                TestReport r = this.Report("RT-307.25",
                    "**発行者に許した範囲の外**を主張した `software_statement` は、"
                    + "**`unapproved_software_statement` で断る**",
                    "**段階 4 では「信じるか、信じないか」の 2 択**だった — "
                    + "**信頼した発行者は、何でも主張できた。**"
                    + "**提携の範囲を技術的な上限として持てないと、無人の自動登録を許せない**"
                    + "（**人が審査しない道**である）。"
                    + "**発行者の鍵が漏れたときの被害を囲む**意味もある。",
                    "RFC 7591 §3.2.2 / #307 の段階 6");

                r.Target("POST registration_endpoint（上限の外を主張する statement）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 範囲内の scope は通る");

                    Dictionary<string, object> inside =
                        ClientRegistrationTests.StatementClaims();

                    inside["scope"] = "openid email";
                    inside["redirect_uris"] = new string[] { UriA };

                    JsonResponse ok = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"software_statement\":\""
                        + JwsSigner.SignRS256(client, inside) + "\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)ok.StatusCode).ToString());

                    r.VerifyEqual("登録された scope は、主張したもの",
                        "openid email", ok.String("scope") ?? "（無い）");

                    r.Step("(2) 範囲の外の scope を主張すると、断られる");

                    //  **この配備が許していない scope**（`test.ps1` の `allowed_scope` の外）。
                    //    **`scopes_supported` には在る値**を使う — **「知らない scope」ではなく、
                    //    「この発行者には許していない scope」であることを測る。**
                    string outsideScope = ClientRegistrationTests.ScopeOutsideAllowed();

                    Dictionary<string, object> outside =
                        ClientRegistrationTests.StatementClaims();

                    outside["scope"] = "openid " + outsideScope;
                    outside["redirect_uris"] = new string[] { UriA };

                    JsonResponse denied = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"software_statement\":\""
                        + JwsSigner.SignRS256(client, outside) + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)denied.StatusCode).ToString());

                    r.VerifyEqual("error は unapproved_software_statement",
                        "unapproved_software_statement", denied.String("error") ?? "（無い）");

                    r.Observe("error_description", denied.String("error_description") ?? "（無い）");

                    r.Note("**黙って狭めない。** **断る** — "
                        + "**主張が通ったのか削られたのかが、要求した側に分からなくなる**ためである。");

                    r.Step("(3) 本文（plain JSON）に書いても、同じく断られる");

                    //  **statement に scope が無ければ、本文の値が登録の値になる**（段階 4）。
                    //    **だから本文由来の値も上限に収める** —
                    //    **その発行者の保証で作られる登録、全体の上限**である。
                    Dictionary<string, object> silent =
                        ClientRegistrationTests.StatementClaims();

                    silent["redirect_uris"] = new string[] { UriA };

                    JsonResponse body = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"scope\":\"openid " + outsideScope + "\","
                        + "\"software_statement\":\""
                        + JwsSigner.SignRS256(client, silent) + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400",
                        ((int)body.StatusCode).ToString());

                    r.VerifyEqual("error は unapproved_software_statement",
                        "unapproved_software_statement", body.String("error") ?? "（無い）");

                    r.Note("**statement を付けない要求には、この上限は効かない** — "
                        + "**発行者が決まらない**ためである（**`RequireSoftwareStatement` で"
                        + "statement を必須にすれば、その穴も閉じる**。段階 4）。");

                    r.Step("(4) PUT（RFC 7592）でも効く");

                    JsonResponse created = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        DynamicClientRegistration.Metadata(UriA));

                    Assert.Equal(201, (int)created.StatusCode);

                    Dictionary<string, object> forPut =
                        ClientRegistrationTests.StatementClaims();

                    forPut["scope"] = "openid " + outsideScope;
                    forPut["redirect_uris"] = new string[] { UriA };

                    JsonResponse put = await DynamicClientRegistration.UpdateAsync(
                        client, created.String("registration_client_uri"),
                        created.String("registration_access_token"),
                        "{\"client_id\":\"" + created.String("client_id") + "\","
                        + "\"redirect_uris\":[\"" + UriA + "\"],"
                        + "\"software_statement\":\""
                        + JwsSigner.SignRS256(client, forPut) + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)put.StatusCode).ToString());

                    r.VerifyEqual("error は unapproved_software_statement",
                        "unapproved_software_statement", put.String("error") ?? "（無い）");

                    r.Note("**検査は `Validate` の 1 か所**なので、"
                        + "**`POST` と `PUT` で同じ判定**になる（段階 4 と同じ作り）。");
                });

                r.Done();
            }
        }

        #endregion

        #region RT-307.26

        /// <summary>RT-307.26 発行者の鍵を入れ替える間、新旧のどちらでも通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **発行者の証明書を n 本持てる**（`cer_file_path` を空白区切り。#307 の段階 6）。
        ///
        /// **段階 4 では 1 本だけ**だった — **発行者が鍵を替えると、
        /// 替えた瞬間に古い statement が通らなくなる**（**出荷済みのソフトが登録できない**）。
        ///
        /// **`test.ps1` は 2 本渡す**（`SpRp_RsaPfxFilePath` の対 ＋ `RsaPfxFilePath` の対）。
        /// **どちらで署名しても通り、どちらでもない鍵では通らない**ことを測る。
        ///
        /// **鍵はテスト用の寄せ集め**である（**「発行者の鍵」として作った物ではない**） —
        /// **要るのは「RSA 2048 の鍵が 2 つ」と「登録されていない 3 つ目」**だけで、
        /// **配備側（`C:/root/files/resource/X509`）に配られているものから選んである。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30726_発行者の鍵を入れ替える間は新旧どちらでも通る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                ClientRegistrationTests.SkipIfNoSoftwareStatement();
                ClientRegistrationTests.SkipIfNoRollover();

                TestReport r = this.Report("RT-307.26",
                    "**発行者の鍵を入れ替える間、新旧のどちらで署名された "
                    + "`software_statement` でも登録できる**",
                    "**段階 4 は証明書を 1 本しか持てなかった** — "
                    + "**発行者が鍵を替えると、出荷済みのソフトが一斉に登録できなくなる。**"
                    + "**入れ替えには、新旧が並ぶ期間が要る**（**鍵のロールオーバー**）。"
                    + "**どちらでもない鍵は通らない**ことも、併せて測る。",
                    "#307 の段階 6 / SoftwareStatementIssuer.CerFilePaths");

                r.Target("POST registration_endpoint（1 本目 / 2 本目 / どちらでもない鍵で署名）");

                await this.WithDcrAsync(admin, targetKey, async (client, endpoint, token, ctx) =>
                {
                    r.Step("(1) 1 本目の鍵で署名した statement は通る");

                    JsonResponse first = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"software_statement\":\""
                        + JwsSigner.SignRS256(client,
                            ClientRegistrationTests.StatementClaims(UriA)) + "\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)first.StatusCode).ToString());

                    r.Step("(2) 2 本目の鍵で署名した statement も通る");

                    //  **入れ替えの間**（新旧が並んでいる状態）**を作っている。**
                    JsonResponse second = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"software_statement\":\""
                        + JwsSigner.SignRS256(client,
                            ClientRegistrationTests.StatementClaims(UriB),
                            "RsaPfxFilePath", "RsaPfxPassword") + "\"}");

                    r.VerifyEqual("HTTP の状態は 201", "201", ((int)second.StatusCode).ToString());

                    r.VerifyEqual("主張した折り返し先が入る", "True",
                        second.ArrayContains("redirect_uris", UriB).ToString());

                    r.Note("**試す順は、書いた順**である。"
                        + "**1 本目以外で通ったときは、ログに残す** — "
                        + "**運用者が「古い鍵をいつ消せるか」を判断する材料**になる。");

                    r.Step("(3) どちらでもない鍵で署名した statement は通らない");

                    //  **発行者として登録されていない鍵**で署名する
                    //    （`SpRp_ClientCertPfxFilePath`。**mTLS のクライアント証明書の鍵**）。
                    //    **その `.cer` は発行者の一覧に無い**ので、**どの鍵でも検証できない。**
                    JsonResponse other = await DynamicClientRegistration.RegisterAsync(
                        client, endpoint, token,
                        "{\"software_statement\":\""
                        + JwsSigner.SignRS256(client,
                            ClientRegistrationTests.StatementClaims(UriA),
                            "SpRp_ClientCertPfxFilePath", "SpRp_ClientCertPfxPassword") + "\"}");

                    r.VerifyEqual("HTTP の状態は 400", "400", ((int)other.StatusCode).ToString());

                    r.VerifyEqual("error は invalid_software_statement",
                        "invalid_software_statement", other.String("error") ?? "（無い）");

                    r.Note("**`iss` は合っていて、署名だけが合わない**ので "
                        + "**`invalid_software_statement`** である"
                        + "（**知らない発行者なら `unapproved_software_statement`**。`RT-307.20`）。");
                });

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>
        /// 発行者に許した `scope` の上限（`test.ps1` が渡す。無ければ空）（#307 の段階 6）
        /// </summary>
        /// <returns>空白区切りの scope</returns>
        private static string AllowedScope()
        {
            return Environment.GetEnvironmentVariable(
                "MPAS_SOFTWARE_STATEMENT_ALLOWED_SCOPE") ?? "";
        }

        /// <summary>上限を渡していない配備では Skip する（#307 の段階 6）</summary>
        private static void SkipIfNoAllowedScope()
        {
            Skip.If(string.IsNullOrEmpty(ClientRegistrationTests.AllowedScope()),
                "この配備は発行者の上限（allowed_scope）を設定していません"
                + "（test.ps1 -Launch が渡す。#307 の段階 6）。");
        }

        /// <summary>上限の外に在る scope を 1 つ返す（#307 の段階 6）</summary>
        /// <returns>scope</returns>
        /// <remarks>
        /// **`scopes_supported` に在って、上限には無い値**を選ぶ —
        /// **「知らない scope」ではなく「この発行者には許していない scope」**を測るためである。
        /// **`test.ps1` の上限は `openid` 系を広く含む**ので、**ここは `address` を避けて
        /// 固定の候補から選ぶ**（**上限に全部入っていたら Skip**）。
        /// </remarks>
        private static string ScopeOutsideAllowed()
        {
            List<string> allowed = new List<string>(
                ClientRegistrationTests.AllowedScope().Split(
                    new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));

            foreach (string candidate in new string[] { "address", "phone", "roles" })
            {
                if (!allowed.Contains(candidate))
                {
                    return candidate;
                }
            }

            Skip.If(true, "上限（allowed_scope）が、候補の scope を全て含んでいます"
                + "（test.ps1 の SoftwareStatementAllowedScope を狭めてください。#307 の段階 6）。");

            return "";
        }

        /// <summary>statement のクレーム（折り返し先も主張する）（#307 の段階 6）</summary>
        /// <param name="redirectUri">主張する折り返し先</param>
        /// <returns>クレーム</returns>
        private static Dictionary<string, object> StatementClaims(string redirectUri)
        {
            Dictionary<string, object> claims = ClientRegistrationTests.StatementClaims();

            claims["redirect_uris"] = new string[] { redirectUri };

            return claims;
        }

        /// <summary>2 本目の鍵を渡していない配備では Skip する（#307 の段階 6）</summary>
        private static void SkipIfNoRollover()
        {
            Skip.IfNot(
                Environment.GetEnvironmentVariable("MPAS_SOFTWARE_STATEMENT_ROLLOVER") == "true",
                "この配備は発行者の証明書を 1 本しか設定していません"
                + "（test.ps1 -Launch が 2 本渡す。#307 の段階 6）。");
        }

        /// <summary>
        /// 構成ファイル発の動的登録クライアント（`test.ps1` が渡す。無ければ空）（#307 の段階 5-b）
        /// </summary>
        /// <summary>サインイン中の利用者の名前を変える（#307 の段階 5-b）</summary>
        /// <param name="client">IdPClient（その利用者でサインイン済み）</param>
        /// <param name="newName">新しい利用者名</param>
        /// <param name="password">その利用者のパスワード（出力しないこと）</param>
        /// <returns>変えられたら true</returns>
        /// <remarks>
        /// **`/Manage/ChangeUserName` を送る**（`RT-277.4` と同じ経路）。
        ///
        /// **`Password` も送る** — **`[Required(AllowEmptyStrings = true)]`** なので、
        /// **項目ごと無いと検証に落ちて、画面が出し直されるだけ**になる
        /// （`RequirePasswordInEditingUserNameAndEmail` が true の配備でも通るよう、実際の値を送る）。
        /// </remarks>
        private static async Task<bool> RenameUserAsync(
            IdPClient client, string newName, string password)
        {
            string html = await client.GetStringAsync("/Manage/ChangeUserName");
            string token = Html.Antiforgery(html);

            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            System.Net.Http.HttpResponseMessage res = await client.PostFormAsync(
                "/Manage/ChangeUserName",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", token },
                    { "UserNameForEdit", newName },
                    { "Password", password }
                });

            return ClientRegistrationTests.IsRedirect(res);
        }

        /// <summary>対象ごとのしるしを読む（#307 の段階 5-b）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="name">しるしの名前（接尾）</param>
        /// <returns>値（無ければ空）</returns>
        /// <remarks>
        /// **`MPAS_CORE_*` / `MPAS_NETFX_*` の作法**（`MPAS_CORE_MTLS` と同じ）。
        ///
        /// **対象ごとに分けないと、net48 のケースが「渡された」と見なして落ちる** —
        /// **しるしは process 全体に置かれる**ので、**net48 のケースも読んでしまう**
        /// （実測で踏んだ）。
        /// </remarks>
        private static string DcrCcEnv(string targetKey, string name)
        {
            string prefix = (targetKey == TestEnv.NetFxKey) ? "MPAS_NETFX_" : "MPAS_CORE_";

            return Environment.GetEnvironmentVariable(prefix + name) ?? "";
        }

        /// <summary>
        /// 構成ファイル発の動的登録クライアント（`test.ps1` が渡す。無ければ空）（#307 の段階 5-b）
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>client_id</returns>
        /// <remarks>**net10.0 版にだけ渡される**（net48 は 1 本の JSON 文字列のため）。</remarks>
        private static string DcrCcClientId(string targetKey)
        {
            return ClientRegistrationTests.DcrCcEnv(targetKey, "DCR_CC_CLIENT_ID");
        }

        /// <summary>その client_secret（値は出力しないこと）（#307 の段階 5-b）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>client_secret</returns>
        private static string DcrCcClientSecret(string targetKey)
        {
            return ClientRegistrationTests.DcrCcEnv(targetKey, "DCR_CC_CLIENT_SECRET");
        }

        /// <summary>そのクライアントの `owner`（利用者名）（#307 の段階 5-b）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>利用者名</returns>
        private static string DcrCcOwner(string targetKey)
        {
            return ClientRegistrationTests.DcrCcEnv(targetKey, "DCR_CC_OWNER");
        }

        /// <summary>所有者を書いていない方の client_id（#307 の段階 5-b）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>client_id</returns>
        private static string DcrCcNoOwnerClientId(string targetKey)
        {
            return ClientRegistrationTests.DcrCcEnv(targetKey, "DCR_CC_NOOWNER_CLIENT_ID");
        }

        /// <summary>その client_secret（値は出力しないこと）（#307 の段階 5-b）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>client_secret</returns>
        private static string DcrCcNoOwnerSecret(string targetKey)
        {
            return ClientRegistrationTests.DcrCcEnv(targetKey, "DCR_CC_NOOWNER_CLIENT_SECRET");
        }

        /// <summary>管理 API を叩くための前提（使い捨ての利用者 2 人ぶん）</summary>
        private sealed class DcrContext
        {
            /// <summary>管理 API を叩くクライアントの client_id（利用者 A が持つ）</summary>
            public string ApiClientId { get; set; }

            /// <summary>その client_secret（出力しないこと）</summary>
            public string ApiClientSecret { get; set; }

            /// <summary>登録の所有者になる利用者（B）の名前</summary>
            public string OwnerName { get; set; }

            /// <summary>その パスワード（出力しないこと）</summary>
            public string Password { get; set; }
        }

        /// <summary>
        /// 使い捨ての利用者 2 人で、動的登録を叩ける状態を作って渡す
        /// </summary>
        /// <param name="admin">管理者のクライアント</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="body">測る本体（client / endpoint / access_token / 前提）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **利用者を 2 人使う。**
        ///
        /// | | 役 |
        /// |---|---|
        /// | **A** | **管理 API を叩くクライアントの持ち主。** 画面から、`scope` に専用 scope だけを登録する |
        /// | **B** | **登録の所有者。** ROPC の `username` / `password` で本人になる |
        ///
        /// **分けないと、A の管理クライアントと B の登録が、同じ利用者に混ざる** —
        /// **`Helper.GetClientIdByName` と管理画面が返すのは「所有者の先頭 1 件」**なので、
        /// **どちらを引くかが決まらない。**
        ///
        /// **#307 の段階 5-a-1 より前は、もっと硬く効いていた** —
        /// **B の登録が「2 件目」になって断られた**（**1 人 1 件だった**ため）。
        ///
        /// **A のクライアントは画面から登録する** — **動的登録では専用 scope を付けられない**
        /// （`RT-307.4` の (7)）。**配るのは、管理画面か構成ファイルからだけ**である。
        ///
        /// **終わったら両方の利用者を消す**（登録も一緒に消える）。
        /// </remarks>
        private async Task WithDcrAsync(
            IdPClient admin, string targetKey,
            Func<IdPClient, string, string, DcrContext, Task> body)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            //  **ROPC と動的登録の両方が開いている配備でしか測れない。**
            await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "password");
            string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

            string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
            string apiOwner = "e2e_rt307_api_" + suffix;
            string owner = "e2e_rt307_own_" + suffix;
            string password = admin.Config.Get("TestUserPWD");

            Assert.True(ClientRegistrationTests.IsRedirect(await UsersAdmin.CreateAsync(
                admin, apiOwner, apiOwner + "@example.com", "Admin")),
                "前提: 管理 API 用の利用者を作れること");

            try
            {
                Assert.True(ClientRegistrationTests.IsRedirect(await UsersAdmin.CreateAsync(
                    admin, owner, owner + "@example.com", "User")),
                    "前提: 登録の所有者になる利用者を作れること");

                try
                {
                    DcrContext ctx = new DcrContext()
                    {
                        OwnerName = owner,
                        Password = password
                    };

                    //  **A で、管理 API を叩くクライアントを登録する**（専用 scope 付き）。
                    using (IdPClient apiClient = this.Client(targetKey))
                    {
                        Assert.True(await apiClient.TrySignInAsync(apiOwner, password),
                            "前提: 管理 API 用の利用者でサインインできること");

                        (string ClientId, string ClientSecret) registered =
                            await ManageClientRegistration.RegisterWithSecretAsync(apiClient,
                                new Dictionary<string, string>()
                                {
                                    { "Scopes", DynamicClientRegistration.Scope },

                                    //  **`RT-307.6` が、`response_types` の絞りをここで測る。**
                                    //    **`redirect_uri` の照合が先に効く**ので、
                                    //    **両方の列に登録しておく必要がある。**
                                    { "RedirectUriCode", UriA },
                                    { "RedirectUriToken", UriB },
                                    { "ResponseTypes", "code" },

                                    //  **`RT-307.7` が、`grant_types` の絞りをここで測る。**
                                    //    **`password` だけを登録する**（ROPC で使う）。
                                    //    **`authorization_code` は登録しない。**
                                    { "GrantTypes", "password" }
                                });

                        Assert.False(string.IsNullOrEmpty(registered.ClientId),
                            "前提: 管理 API 用のクライアントを登録できること");

                        ctx.ApiClientId = registered.ClientId;
                        ctx.ApiClientSecret = registered.ClientSecret;
                    }

                    //  **B の資格で、専用 scope のアクセス トークンを取る。**
                    using (IdPClient client = this.Client(targetKey))
                    {
                        JsonResponse token = await DynamicClientRegistration.TokenAsync(
                            client, ctx.ApiClientId, ctx.ApiClientSecret, owner, password);

                        string accessToken = token.String("access_token");

                        Assert.False(string.IsNullOrEmpty(accessToken),
                            "前提: 専用 scope のアクセス トークンが取れること"
                            + "（error=" + (token.String("error") ?? "なし") + "）");

                        //  **B でサインインしておく**（認可エンドポイントを通るテストがある）。
                        Assert.True(await client.TrySignInAsync(owner, password),
                            "前提: 所有者の利用者でサインインできること");

                        await body(client, endpoint, accessToken, ctx);
                    }
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, owner);
                }
            }
            finally
            {
                await UsersAdmin.DeleteByUserNameAsync(admin, apiOwner);
            }
        }

        /// <summary>client_assertion だけを添えたフォームを作る（#307 の段階 3）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="items">フォームの中身</param>
        /// <returns>フォーム</returns>
        /// <remarks>
        /// **署名鍵は、登録した `jwks` と対になる構成ファイルの鍵**
        /// （`SpRp_RsaPfxFilePath`）。**`aud` は、この実装が求めるトークン エンドポイント。**
        /// </remarks>
        private static Dictionary<string, string> WithClientAssertion(
            IdPClient client, string clientId, IDictionary<string, string> items)
        {
            long now = System.DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", System.Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            };

            return new Dictionary<string, string>(items)
            {
                { "client_assertion", JwsSigner.SignRS256(client, payload) },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
            };
        }

        /// <summary>登録が `400` ＋ `invalid_client_metadata` で断られることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="endpoint">registration_endpoint</param>
        /// <param name="token">専用 scope のアクセス トークン</param>
        /// <param name="metadata">送るメタデータ</param>
        /// <param name="why">読み手向けの理由</param>
        /// <returns>Task</returns>
        private async Task VerifyRegistrationErrorAsync(
            TestReport r, IdPClient client, string endpoint, string token,
            string metadata, string why)
        {
            JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                client, endpoint, token, metadata);

            r.VerifyEqual("HTTP の状態は 400（" + why + "）",
                "400", ((int)res.StatusCode).ToString());

            r.VerifyEqual("error は invalid_client_metadata",
                "invalid_client_metadata", res.String("error") ?? "（無い）");

            r.Observe("error_description", res.String("error_description") ?? "（無い）");
        }

        /// <summary>statement の `software_id`（#307 の段階 4）</summary>
        private const string SoftwareId = "e2e-rt307-software";

        /// <summary>
        /// `software_statement` の発行者（`test.ps1` が渡す。無ければ空）（#307 の段階 4）
        /// </summary>
        /// <returns>iss</returns>
        /// <remarks>
        /// **サイトへ渡した値と、必ず同じ値を使う** —
        /// **テスト側で別に持つと、設定を替えたときに食い違う。**
        /// **`MtlsTests.SkipIfNoMtls` と同じ作法**（しるしの環境変数で判定する）。
        /// </remarks>
        private static string SoftwareStatementIssuer()
        {
            return Environment.GetEnvironmentVariable("MPAS_SOFTWARE_STATEMENT_ISS") ?? "";
        }

        /// <summary>発行者が設定されていない配備では Skip する（#307 の段階 4）</summary>
        private static void SkipIfNoSoftwareStatement()
        {
            Skip.If(string.IsNullOrEmpty(ClientRegistrationTests.SoftwareStatementIssuer()),
                "この配備は software_statement の発行者を設定していません"
                + "（test.ps1 -Launch が、SpRp_RsaPfxFilePath と対の .cer を渡す。#307 の段階 4）。");
        }

        /// <summary>statement の最小のクレーム（#307 の段階 4）</summary>
        /// <returns>クレーム</returns>
        /// <remarks>
        /// **`iss` は必須**（RFC 7591 §2.3）。**`exp` / `aud` は入れない**
        /// （**任意**であり、**入れないときに通ること**も測る）。
        /// **`software_id` / `software_version` は、statement だけが主張する項目**として使う。
        /// </remarks>
        private static Dictionary<string, object> StatementClaims()
        {
            return new Dictionary<string, object>()
            {
                { "iss", ClientRegistrationTests.SoftwareStatementIssuer() },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                { "software_id", ClientRegistrationTests.SoftwareId },
                { "software_version", "1.0.0" }
            };
        }

        /// <summary>署名を 1 文字だけ変える（#307 の段階 4）</summary>
        /// <param name="jws">JWS（コンパクト形式）</param>
        /// <returns>署名が合わなくなった JWS</returns>
        /// <remarks>
        /// **形は壊さない**（3 つに分かれたまま、Base64URL のまま）。
        /// **「読めるが、署名が合わない」**ことだけを作る。
        ///
        /// > **変えるのは、署名の 1 文字目である。**
        /// > **末尾では壊れない** — **RS256 の署名は 256 バイト ＝ Base64URL で 342 文字**で、
        /// > **2048 ビットを 6 ビットずつに切ると 341 文字 ＋ 2 ビット**になる。
        /// > **最後の 1 文字が持つ実データは 2 ビットだけ**で、**残り 4 ビットは詰め物**なので、
        /// > **そこを変えても、復号したバイト列は同じ**になる（最初はそれで取り逃していた）。
        /// </remarks>
        private static string Tamper(string jws)
        {
            int at = jws.LastIndexOf('.');
            char first = jws[at + 1];

            return jws.Substring(0, at + 1)
                + ((first == 'A') ? 'B' : 'A')
                + jws.Substring(at + 2);
        }

        /// <summary>statement の誤りで、登録が断られることを確かめる（#307 の段階 4）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="endpoint">registration_endpoint</param>
        /// <param name="token">専用 scope のアクセス トークン</param>
        /// <param name="statement">送る software_statement</param>
        /// <param name="expectedError">期待する error</param>
        /// <param name="why">読み手向けの理由</param>
        /// <returns>Task</returns>
        private async Task VerifyStatementErrorAsync(
            TestReport r, IdPClient client, string endpoint, string token,
            string statement, string expectedError, string why)
        {
            JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                client, endpoint, token,
                "{\"redirect_uris\":[\"" + UriA + "\"],"
                + "\"software_statement\":\"" + statement + "\"}");

            r.VerifyEqual("HTTP の状態は 400（" + why + "）",
                "400", ((int)res.StatusCode).ToString());

            r.VerifyEqual("error は " + expectedError,
                expectedError, res.String("error") ?? "（無い）");

            r.Observe("error_description", res.String("error_description") ?? "（無い）");
        }

        /// <summary>リダイレクトか（UsersAdmin の作成が成功したか）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(System.Net.Http.HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        #endregion
    }
}
