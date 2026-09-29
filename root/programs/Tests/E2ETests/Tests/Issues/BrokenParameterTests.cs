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
//* クラス名        ：BrokenParameterTests
//* クラス日本語名  ：RT-245 パラメタを 1 つ壊したら、認証・認可されない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/29  玄人 幸道         新規（#245 の段階 2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-245. **パラメタを 1 つ壊したら、認証・認可されない。**
    /// </summary>
    /// <remarks>
    /// **#245 の段階 2。** 異常系は Issue ごとに足してきたため、
    /// 「**このパラメタを壊したら通らない**」が経路ごとに揃っていなかった。
    /// **既にあるものは数え、無いものだけをここに足す**（Issue の方針）。
    ///
    /// | 壊すもの | 既にあるもの | ここで足すもの |
    /// |---|---|---|
    /// | `client_id` / `client_secret` | `TC-2.3`（誤り・存在しない）／`FA-6.2`（証明書）／`EX-4.6` | — |
    /// | `redirect_uri` | `TC-1.3`（未登録）／`RT-186.2` `.3`（認可時と違う・省略） | **大文字小文字違い**（`RT-245.4`。**C-10 が未修正なので Skip**） |
    /// | `code` | `TC-2.2` `RT-186.4`（使用済み）／`RT-188.1`（期限切れ） | **改竄・他クライアント**（`RT-245.2`） |
    /// | `refresh_token` | `EX-1.2` `.3` `.4`／`RT-188.2` | — |
    /// | `device_code` | `EX-4.5` `.7` | — |
    /// | `code_verifier` | `TC-2.4`（不一致）／`RT-197.6` | **欠落**（`RT-245.3`。**#245 で修正**） |
    /// | `client_assertion` | `RT-239.4`（署名）／`RT-241.2` `.3`（JWT でない・`iss`） | **`aud` 違い・`exp` 切れ**（`RT-245.5`） |
    /// | Request Object / CIBA の `request` | `RT-233` `RT-234`（`aud`・`jti`）／`RT-241.1` | — |
    /// | `scope` | `RT-198.1`〜`.4`／`TC-1.4` | — |
    /// | **`request_uri` を口をまたいで渡す** | **無い** | **`RT-245.1`** |
    /// </remarks>
    public class BrokenParameterTests : TargetTestBase
    {
        /// <summary>PKCE の検証子（RFC 7636 付録 B の例。既存テストと同じ値）</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>上の検証子の S256 チャレンジ</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public BrokenParameterTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-245.1 request_uri は、預けた口でしか使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24501_request_uriは預けた口でしか使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);
                ClientRegistration ciba = Flows.Registration(client, KnownClients.TestClient4);

                TestReport r = this.Report("RT-245.1",
                    "`/par` に預けた request_uri は `/ciba_authz` では使えず、CIBA の request は `/par` に預けられない",
                    "**`/ros` と `/par` は、保存先（`RequestObjectProvider`）と `urn:` の名前空間を共有している**"
                    + "（どちらも GUID キーで `urn:…` を返す）。"
                    + "**口をまたいで参照を持ち込めないことを、テストで固定する**（#245 の段階 2）。"
                    + "いまは `/par` が**認可リクエストとして検証する**ので CIBA の要求は預けられないが、"
                    + "**それは検証の副作用で、設計上の分離ではない。**",
                    "RFC 9126 / CIBA Core §7.1.1 / #245 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + "（/par）と "
                    + KnownClients.TestClient4 + "（/ciba_authz）");

                r.Step("(1) /par に認可要求を預けて request_uri を得る");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync("/par",
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", normal.ClientId },
                        { "redirect_uri", normal.RedirectUri },
                        { "scope", "openid email" },
                        { "state", "state-rt2451" },
                        { "nonce", "nonce-rt2451" }
                    }, normal.ClientId, normal.ClientSecret);

                string requestUri = par.String("request_uri");

                r.Verify("request_uri が返る", !string.IsNullOrEmpty(requestUri),
                    "urn:… が返る",
                    string.IsNullOrEmpty(requestUri) ? "**返らない**（" + par.ToString() + "）" : "返った");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: /par に預けられること");

                r.Step("(2) その request_uri を /ciba_authz に渡す");

                JsonResponse crossed = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>() { { "request_uri", requestUri } },
                    ciba.ClientId, ciba.ClientSecret);

                string authReqId = crossed.String("auth_req_id");

                r.Verify("auth_req_id を返さない（利用者へ通知しない）",
                    string.IsNullOrEmpty(authReqId),
                    "返さない",
                    string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

                r.Observe("/ciba_authz の応答",
                    "HTTP " + (int)crossed.StatusCode + " / error=" + (crossed.Error ?? "-"),
                    "**認可リクエストの参照は、CIBA の認証要求として成立しない。**"
                    + "エラー コードは実装の都合で決まるため、観察として残す。");

                r.Step("(3) 逆向き : CIBA の request（ES256）を /par に預ける");

                string cibaRequest = await RequestObjectBuilder.CreateCibaAsync(
                    client, ciba.ClientId, new Dictionary<string, object>());

                JsonResponse pushed = await client.PostJsonWithBasicAuthAsync("/par",
                    new Dictionary<string, string>() { { "request", cibaRequest } },
                    ciba.ClientId, ciba.ClientSecret);

                r.Verify("request_uri を返さない",
                    string.IsNullOrEmpty(pushed.String("request_uri")),
                    "返さない",
                    string.IsNullOrEmpty(pushed.String("request_uri")) ? "返さなかった" : "**返した**");

                r.Observe("/par の応答",
                    "HTTP " + (int)pushed.StatusCode + " / error=" + (pushed.Error ?? "-"),
                    "**CIBA の認証要求は、認可リクエストの検証を通らない**"
                    + "（`response_type` などが無い）。");

                r.Note("**保存先が同じでも、口をまたいだ参照は成立しない**ことを、"
                    + "この 2 方向で押さえた（#245 の段階 2）。");

                r.Done();
            }
        }

        /// <summary>RT-245.2 改竄した code・他クライアントの code は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24502_改竄した認可コードと他クライアントの認可コードは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **TestClient_2 は構成ファイルに無い**（test.ps1 -Launch が差し込む）。
                //   InjectedRegistration が、差し込まれていなければ Skip する（#224）。
                ClientRegistration a = Flows.Registration(client, KnownClients.TestClient);
                ClientRegistration b = Flows.InjectedRegistration(client, KnownClients.TestClient_2);

                TestReport r = this.Report("RT-245.2",
                    "改竄した認可コードと、他クライアントに発行された認可コードは、トークンに交換できない",
                    "**使用済み（`TC-2.2` / `RT-186.4`）と期限切れ（`RT-188.1`）は測っていたが、"
                    + "改竄と「他人のコード」は測っていなかった**（#245 の段階 2）。"
                    + "コードは**発行先のクライアントに紐づく**（RFC 6749 §4.1.3 : "
                    + "認証したクライアントに発行されたものであることを確かめる）。",
                    "RFC 6749 §4.1.3 / §5.2（invalid_grant）/ #245 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + " と "
                    + KnownClients.TestClient_2 + "（どちらも normal）");

                // **コードは 1 回提示されたら消える**（AuthorizationCodeProvider.Receive が、
                //   client_id / redirect_uri を照合する**前に**ストアから削除する）。
                //   **したがって、壊す試行ごとに新しいコードを取る。**
                //   同じコードを使い回すと、2 つ目以降は「使用済み」で落ちるため、
                //   **何を測ったのか分からなくなる**（TC-2.2 / RT-186.4 が測っているのはその「使用済み」）。

                r.Step("(1) 1 文字だけ書き換えたコードは交換できない");

                AuthZResponse first = await Flows.AuthorizeCodeAsync(
                    client, a, redirectUri: a.RedirectUri, state: "state-rt2452a");

                Assert.False(string.IsNullOrEmpty(first.Code), "前提: 認可コードが返ること");

                JsonResponse broken = await Flows.ExchangeCodeAsync(
                    client, a, BrokenParameterTests.Tamper(first.Code), redirectUri: a.RedirectUri);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(broken.AccessToken),
                    "発行しない", string.IsNullOrEmpty(broken.AccessToken) ? "発行しない" : "**発行した**");

                r.VerifyEqual("エラーは invalid_grant", "invalid_grant", broken.Error ?? "（無し）");

                r.Step("(2) 別のクライアントの資格情報では交換できない");

                AuthZResponse second = await Flows.AuthorizeCodeAsync(
                    client, a, redirectUri: a.RedirectUri, state: "state-rt2452b");

                Assert.False(string.IsNullOrEmpty(second.Code), "前提: 2 つ目の認可コードが返ること");

                JsonResponse otherClient = await Flows.ExchangeCodeAsync(
                    client, b, second.Code, redirectUri: a.RedirectUri);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(otherClient.AccessToken),
                    "発行しない", string.IsNullOrEmpty(otherClient.AccessToken) ? "発行しない" : "**発行した**");

                r.VerifyEqual("エラーは invalid_grant", "invalid_grant", otherClient.Error ?? "（無し）");

                r.Step("(3) その試行で、コードは失効している");

                JsonResponse afterMisuse = await Flows.ExchangeCodeAsync(
                    client, a, second.Code, redirectUri: a.RedirectUri);

                r.Observe("本来のクライアントが同じコードを出したときの応答",
                    "HTTP " + (int)afterMisuse.StatusCode + " / error=" + (afterMisuse.Error ?? "-"),
                    "**他のクライアントが提示した時点で、コードは消えている。**"
                    + "`Receive` が照合の**前に**削除するため。**これは安全側の振る舞いで、"
                    + "RFC 6819 §5.2.1.1 / OAuth 2.1 §4.1.3 が求める「誤用されたコードの失効」に当たる**"
                    + "（コードを提示できるのは、既にコードを握っている者だけなので、"
                    + "これで正当な利用者が害を受ける経路は無い）。"
                    + "利用者は認可をやり直せばよい。");

                r.Step("(4)（対照）本来のクライアントが、自分のコードを 1 度出せば交換できる");

                AuthZResponse third = await Flows.AuthorizeCodeAsync(
                    client, a, redirectUri: a.RedirectUri, state: "state-rt2452c");

                Assert.False(string.IsNullOrEmpty(third.Code), "前提: 3 つ目の認可コードが返ること");

                JsonResponse ok = await Flows.ExchangeCodeAsync(
                    client, a, third.Code, redirectUri: a.RedirectUri);

                r.Verify("トークンが返る", !string.IsNullOrEmpty(ok.AccessToken),
                    "返る", string.IsNullOrEmpty(ok.AccessToken) ? "**返らない**（" + ok.ToString() + "）" : "返った");

                r.Note("**「壊したら通らない」だけでは足りない。**"
                    + "(4) の対照が無いと、**壊し方に関係なく全部落ちている**状態と区別できない。");

                r.Done();
            }
        }


        /// <summary>RT-245.3 code_challenge を送ったのに code_verifier を送らないと通らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24503_code_verifierの欠落は拒否される(string targetKey)        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-245.3",
                    "code_challenge を送った認可の code は、code_verifier が無ければトークンに交換できない",
                    "**不一致（`TC-2.4`）は測っていたが、欠落は測っていなかった**（#245 の段階 2）。"
                    + "**欠落を通してしまうと、PKCE を付けた意味が無くなる**"
                    + "（横取りしたコードは、検証子を知らなくても使えてしまう）。",
                    "RFC 7636 §4.6 / RFC 6749 §5.2（invalid_grant）/ #245 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + " / PKCE(S256)");

                r.Step("(1) code_challenge（S256）を付けて認可コードを取る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, state: "state-rt2453",
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", BrokenParameterTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                r.Step("(2) code_verifier を送らずに交換する");

                JsonResponse missing = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, redirectUri: reg.RedirectUri);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(missing.AccessToken),
                    "発行しない", string.IsNullOrEmpty(missing.AccessToken) ? "発行しない" : "**発行した**");

                r.VerifyEqual("エラーは invalid_grant", "invalid_grant", missing.Error ?? "（無し）");

                r.Step("(3)（対照）正しい code_verifier なら交換できる");

                AuthZResponse again = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, state: "state-rt2453b",
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", BrokenParameterTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(again.Code), "前提: 2 回目の認可コードが返ること");

                JsonResponse ok = await Flows.ExchangeCodeAsync(
                    client, reg, again.Code, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_verifier", BrokenParameterTests.Verifier }
                    });

                r.Verify("トークンが返る", !string.IsNullOrEmpty(ok.AccessToken),
                    "返る", string.IsNullOrEmpty(ok.AccessToken) ? "**返らない**（" + ok.ToString() + "）" : "返った");

                r.Step("(4) パブリック クライアント（client_secret 無し）では、そもそも認証が通らない");

                ClientRegistration pub = Flows.Registration(client, KnownClients.TestClient3);

                AuthZResponse publicAuthZ = await Flows.AuthorizeCodeAsync(
                    client, pub, redirectUri: pub.RedirectUri, state: "state-rt2453c",
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", BrokenParameterTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(publicAuthZ.Code), "前提: 認可コードが返ること");

                JsonResponse publicNoVerifier = await client.TokenAsync(
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "authorization_code" },
                        { "code", publicAuthZ.Code },
                        { "client_id", pub.ClientId },
                        { "redirect_uri", pub.RedirectUri }
                    });

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(publicNoVerifier.AccessToken),
                    "発行しない",
                    string.IsNullOrEmpty(publicNoVerifier.AccessToken) ? "発行しない" : "**発行した**");

                r.Observe("パブリック クライアントの応答",
                    "HTTP " + (int)publicNoVerifier.StatusCode
                    + " / error=" + (publicNoVerifier.Error ?? "-"),
                    "**`client_secret` も証明書も無いので、クライアント認証そのものが通らない**"
                    + "（`invalid_client`）。つまり**パブリック クライアントは、PKCE 以外に交換の手段が無い。**"
                    + "**この項の影響は、秘密や鍵・証明書を持つクライアントに限られる**"
                    + "（C-22 の「影響」の根拠。実測で押さえておく）。");

                r.Done();
            }
        }

        /// <summary>RT-245.4 redirect_uri は、大文字小文字まで一致しなければ通らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24504_redirect_uriは大文字小文字まで一致しなければ通らない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-245.4",
                    "登録値とパスの大文字小文字が違う redirect_uri は、認可応答を返さない",
                    "**未登録（`TC-1.3`）は測っていたが、「似ているが違う」は測っていなかった**（#245 の段階 2）。"
                    + "RFC 6749 §3.1.2 は**単純な文字列比較**を求めている"
                    + "（スキームとホストは大文字小文字を区別しないが、**パスは区別する**）。"
                    + "**緩い比較は、別のパスへコードを送る余地になる。**",
                    "RFC 6749 §3.1.2 / RFC 3986 §6.2.2.1 / #245 の段階 2");

                // **パスだけを変える。** ホストは RFC 3986 で大文字小文字を区別しないため、
                //   そこを変えて「拒否されること」を期待するのは、仕様上正しくない。
                string lowered = BrokenParameterTests.LowerPath(reg.RedirectUri);

                r.Target("client_name=" + KnownClients.TestClient + " / redirect_uri=" + lowered);

                r.Verify("登録値とは違う値になっている（パスだけを変えた）",
                    lowered != reg.RedirectUri,
                    "違う", lowered == reg.RedirectUri ? "**同じ**（テストの前提が崩れている）" : "違う");

                Assert.NotEqual(reg.RedirectUri, lowered);

                r.Step("パスの大文字小文字を変えた redirect_uri で認可を要求する");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: lowered, state: "state-rt2454");

                r.Observe("応答", res.ToString(),
                    "**redirect_uri が照合できないときは、その URI へエラーも返さない**"
                    + "（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。");

                // **未修正と分かっている項目なので、その挙動のときだけ Skip する**
                //   （TESTING.md 10 節。直れば、この下の検証がそのまま成立して緑になる）。
                Skip.If(!string.IsNullOrEmpty(res.Code),
                    "未修正: ANALYSIS-IdP.md の C-10（`redirect_uri` の比較が大文字小文字を無視）。"
                    + "`CheckRedirectUri` が `ToLower()` 同士で比べているため、"
                    + "パスの大文字小文字だけが違う値でも照合が通る。"
                    + "実測 2026/09/29（" + client.Target.DisplayName + "）: **認可コードが発行された。**"
                    + "期待する動作 = 単純文字列比較（RFC 6749 §3.1.2）で照合し、認可コードを発行しない。"
                    + "ロードマップのフェーズ 2（C-10）で直す。");

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(res.Code),
                    "発行しない", string.IsNullOrEmpty(res.Code) ? "発行しない" : "**発行した**");

                r.Verify("その URI へリダイレクトしない",
                    !(res.Redirected && (res.Location ?? "").StartsWith(lowered)),
                    "送らない",
                    (res.Redirected && (res.Location ?? "").StartsWith(lowered))
                        ? "**送ってしまった**" : "送らない");

                r.Done();
            }
        }

        /// <summary>RT-245.5 client_assertion の aud 違い・exp 切れは invalid_client</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24505_client_assertionのaud違いとexp切れは通らない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-245.5",
                    "client_assertion の aud が違う・exp が切れていれば、クライアント認証を通さない",
                    "**署名の壊れ（`RT-239.4`）と JWT でない値（`RT-241.2`）、"
                    + "`iss` の不備（`RT-241.3`）は測っていたが、`aud` と `exp` は測っていなかった**"
                    + "（#245 の段階 2）。"
                    + "**`aud` を見ないと、他のサーバへ送ったアサーションを転用できる**"
                    + "（RFC 7523 §3 は `aud` の検証を求めている）。",
                    "RFC 7523 §3 / RFC 6749 §5.2（invalid_client）/ #245 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + "（private_key_jwt）");

                r.Step("(1) aud が別のサーバを指すアサーションで client_credentials を要求する");

                JsonResponse wrongAud = await BrokenParameterTests.ClientCredentialsAsync(
                    client, reg, BrokenParameterTests.Assertion(
                        client, reg.ClientId, "https://another.example.invalid/token", 300));

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(wrongAud.AccessToken),
                    "発行しない", string.IsNullOrEmpty(wrongAud.AccessToken) ? "発行しない" : "**発行した**");

                r.VerifyEqual("エラーは invalid_client", "invalid_client", wrongAud.Error ?? "（無し）");
                r.VerifyEqual("HTTP 401", "401", ((int)wrongAud.StatusCode).ToString());

                r.Step("(2) exp が切れたアサーションで要求する");

                JsonResponse expired = await BrokenParameterTests.ClientCredentialsAsync(
                    client, reg, BrokenParameterTests.Assertion(
                        client, reg.ClientId, client.Target.BaseUrl + "/token", -60));

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(expired.AccessToken),
                    "発行しない", string.IsNullOrEmpty(expired.AccessToken) ? "発行しない" : "**発行した**");

                r.VerifyEqual("エラーは invalid_client", "invalid_client", expired.Error ?? "（無し）");

                r.Step("(3)（対照）aud と exp が正しいアサーションなら通る");

                JsonResponse ok = await BrokenParameterTests.ClientCredentialsAsync(
                    client, reg, BrokenParameterTests.Assertion(
                        client, reg.ClientId, client.Target.BaseUrl + "/token", 300));

                r.Verify("トークンが返る", !string.IsNullOrEmpty(ok.AccessToken),
                    "返る", string.IsNullOrEmpty(ok.AccessToken) ? "**返らない**（" + ok.ToString() + "）" : "返った");

                r.Done();
            }
        }

        /// <summary>RT-245.6 FAPI1 PKCE の自己テストは、宣言と値が噛み合っている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24506_FAPI1のPKCEボタンはS256を宣言する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-245.6",
                    "自己テストの「FAPI1 PC, PKCE」は、S256 で計算した値を S256 と宣言する",
                    "**壊れたパラメタを数えていて、自己テスト側の取り違えが 1 件出た**（#245 の段階 2）。"
                    + "**S256 で計算した `code_challenge` を `code_challenge_method=plain` と宣言していた**ため、"
                    + "トークン要求では `challenge == verifier` の比較になり、**このボタンは必ず失敗していた。**"
                    + "**FAPI 1.0 Advanced は S256 を求める**ので、plain は宣言としても誤りである。"
                    + "**E2E が押していなかったボタン**なので、ここで固定する。",
                    "RFC 7636 §4.2 / FAPI 1.0 Advanced §5.2.2 / #245 の段階 2");

                r.Target("submit.AuthorizationCodeFAPI1_PKCE（自己テストの起点）");

                r.Step("ボタンを押して、認可エンドポイントへのリダイレクト先を見る");

                using (HttpResponseMessage res = await client.StartSelfTestAsync(
                    "AuthorizationCodeFAPI1_PKCE"))
                {
                    string location = (res.Headers.Location != null)
                        ? res.Headers.Location.ToString() : "";

                    r.Observe("リダイレクト先", "HTTP " + (int)res.StatusCode
                        + " / " + (location.Length > 120 ? location.Substring(0, 120) + "…" : location));

                    r.Verify("認可エンドポイントへ送る",
                        location.Contains("code_challenge"),
                        "code_challenge を含む URL",
                        location.Contains("code_challenge")
                            ? "含む" : "**含まない**");

                    Assert.Contains("code_challenge", location);

                    r.VerifyEqual("code_challenge_method は S256",
                        "S256",
                        BrokenParameterTests.QueryValue(location, "code_challenge_method"));

                    string challenge = BrokenParameterTests.QueryValue(location, "code_challenge");

                    r.Verify("code_challenge は S256 の長さ（43 文字の BASE64URL）",
                        challenge.Length == 43,
                        "43 文字", challenge.Length + " 文字");

                    r.Note("**値そのものは照合できない**（`code_verifier` はサイトのセッションにある）。"
                        + "**宣言と長さが噛み合っていることまでを見る。**"
                        + "実際に交換できるかは、同意まで通す目視の経路で確かめる。");
                }

                r.Done();
            }
        }

        #region 補助

        /// <summary>client_assertion（RS256）を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="audience">aud</param>
        /// <param name="expiresInSeconds">exp までの秒数（負なら期限切れ）</param>
        /// <returns>JWS</returns>
        private static string Assertion(
            IdPClient client, string clientId, string audience, int expiresInSeconds)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", audience },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + expiresInSeconds }
            });
        }

        /// <summary>client_assertion で client_credentials を要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="assertion">client_assertion</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> ClientCredentialsAsync(
            IdPClient client, ClientRegistration reg, string assertion)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "client_credentials" },
                { "scope", "profile" },
                { "client_id", reg.ClientId },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", assertion }
            });
        }

        /// <summary>URL のクエリ文字列から 1 つ引く</summary>
        /// <param name="url">URL</param>
        /// <param name="key">キー</param>
        /// <returns>値（無ければ「（無し）」）</returns>
        private static string QueryValue(string url, string key)
        {
            int q = url.IndexOf('?');

            if (q < 0)
            {
                return "（無し）";
            }

            foreach (string pair in url.Substring(q + 1).Split('&'))
            {
                int eq = pair.IndexOf('=');

                if (eq > 0 && pair.Substring(0, eq) == key)
                {
                    return Uri.UnescapeDataString(pair.Substring(eq + 1));
                }
            }

            return "（無し）";
        }

        /// <summary>文字列の 1 文字を書き換える（値は出さない）</summary>
        /// <param name="value">元の値</param>
        /// <returns>書き換えた値</returns>
        private static string Tamper(string value)
        {
            char[] chars = value.ToCharArray();
            int last = chars.Length - 1;

            chars[last] = (chars[last] == 'a') ? 'b' : 'a';

            return new string(chars);
        }

        /// <summary>URI のパスだけを小文字にする（スキームとホストは変えない）</summary>
        /// <param name="uri">URI</param>
        /// <returns>パスを小文字にした URI</returns>
        private static string LowerPath(string uri)
        {
            Uri parsed = new Uri(uri);

            return parsed.GetLeftPart(UriPartial.Authority)
                + parsed.AbsolutePath.ToLowerInvariant() + parsed.Query;
        }

        #endregion
    }
}
