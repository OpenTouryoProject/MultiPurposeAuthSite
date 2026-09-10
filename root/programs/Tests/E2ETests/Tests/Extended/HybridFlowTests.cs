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
//* クラス名        ：HybridFlowTests
//* クラス日本語名  ：EX-5 OIDC Hybrid フロー
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-5. OIDC Hybrid フロー（response_type に code と id_token / token を組み合わせる）。
    ///
    /// 認可エンドポイントで一部のトークンを先に受け取り、code は後でトークンに交換する。
    /// **先に受け取った id_token と、code / access_token との結び付け（c_hash / at_hash）**が要になる。
    ///
    /// redirect_uri は、登録の redirect_uri_token を使う（サーバは Hybrid を
    /// Implicit と同じ側に振り分ける）。
    /// </summary>
    public class HybridFlowTests : TargetTestBase
    {
        /// <summary>送る state</summary>
        private const string State = "state-hybrid";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HybridFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Hybrid の認可リクエストを送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseType">response_type</param>
        /// <param name="nonce">nonce</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(
            IdPClient client, ClientRegistration reg, string responseType, string nonce)
        {
            return client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", responseType },
                { "client_id", reg.ClientId },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUriToken },
                { "state", State },
                { "nonce", nonce },
                { "prompt", "none" }
            });
        }

        /// <summary>c_hash / at_hash を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="claim">c_hash / at_hash</param>
        /// <param name="payload">id_token のペイロード</param>
        /// <param name="value">元の値（code / access_token）</param>
        /// <param name="source">元の値の名前</param>
        private static void VerifyHash(
            TestReport r, string claim, JsonElement payload, string value, string source)
        {
            string actual = Jwt.String(payload, claim);
            string expected = Jwt.HalfHash(value);

            r.Verify(claim + " が、" + source + " から計算した値と一致する",
                actual == expected,
                "一致する",
                actual == null
                    ? "**" + claim + " が無い**"
                    : (actual == expected
                        ? "一致した"
                        : "**一致しない**（" + claim + "=" + actual + " / 計算値=" + expected + "）"));
        }

        /// <summary>
        /// s_hash を state から計算した値と突き合わせ、観測として残す。
        ///
        /// **c_hash / at_hash が合わなかったときの切り分けに使う。**
        /// state はこちらが送った既知の値なので、s_hash が合えば、
        /// ハッシュの計算方法（SHA-256 の左半分を BASE64URL）はサーバと一致している。
        /// その場合、合わない原因は「サーバが何をハッシュしたか」の側にある。
        /// </summary>
        /// <param name="r">TestReport</param>
        /// <param name="payload">id_token のペイロード</param>
        /// <param name="state">送った state</param>
        private static void ObserveStateHash(TestReport r, JsonElement payload, string state)
        {
            string actual = Jwt.String(payload, "s_hash");

            string expected = Jwt.HalfHash(state);

            // 値も残す。state は既知の固定値なので、s_hash も毎回同じ値になり、
            // 報告書だけから計算方法の違いを追える（ハッシュ値は秘密ではない）。
            r.Observe("s_hash と、state から計算した値（計算方法の対照）",
                actual == null
                    ? "s_hash なし"
                    : (actual == expected
                        ? "一致（計算方法はサーバと同じ）"
                        : "**一致しない**（s_hash=" + actual + " / 計算値=" + expected
                          + " / state=" + state + "）"),
                "s_hash は FAPI の拡張で、OIDC Core では任意。");
        }

        /// <summary>EX-5.1 code id_token</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（OpenTouryo#584）。実測（2026/09/10, net10.0 / net48）では、"
            + "c_hash が code から計算した値と一致しない。"
            + "Open棟梁 の IdToken.CreateHash が、SHA-256 の左半分ではなく、"
            + "左右を XOR で畳んだ値を使っている（ArrayOperator.ShortenByteArray）。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0501_code_id_tokenでc_hashがcodeと一致する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-5.1",
                    "response_type=code id_token : フラグメントで返り、id_token の c_hash が code と一致する",
                    "id_token を認可エンドポイントで先に受け取り、code は後でトークンに交換する形。"
                    + "**c_hash は「この id_token とこの code は同じ応答のものだ」という結び付け。**"
                    + "合わなければ、code だけを差し替えられても RP は気付けない。",
                    "OIDC Core §3.3.2.5（フラグメントで返す）/ §3.3.2.10（c_hash による code の検証）"
                    + " / §3.3.2.11（この形では c_hash は REQUIRED）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string nonce = "nonce-" + Guid.NewGuid().ToString("N");

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code id_token / scope=openid");
                r.Step("GET /authorize に response_type=code id_token と nonce を付けて送る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "code id_token", nonce);

                r.Verify("フラグメント（#）で返る", res.Where == ParameterLocation.Fragment,
                    "フラグメント", res.ToString());

                r.Verify("code が返る", !string.IsNullOrEmpty(res.Code),
                    "code あり", res.Code == null ? "なし" : "あり（値は伏せる）");

                string idToken = res.Get("id_token");

                r.Verify("id_token が返る", !string.IsNullOrEmpty(idToken),
                    "id_token あり", idToken == null ? "なし" : "あり（値は伏せる）");

                r.Verify("access_token は返さない（response_type に token が無い）",
                    string.IsNullOrEmpty(res.Get("access_token")),
                    "返さない", res.Get("access_token") == null ? "返さなかった" : "**返してしまった**");

                if (!string.IsNullOrEmpty(idToken) && !string.IsNullOrEmpty(res.Code))
                {
                    Jwks.Result sig = Jwks.Verify(idToken, await Flows.JwkSetAsync(client));

                    r.Verify("id_token の署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);

                    JsonElement payload = Jwt.Payload(idToken);

                    r.VerifyEqual("nonce が送った値と一致する", nonce, Jwt.String(payload, "nonce"));

                    ObserveStateHash(r, payload, State);

                    r.Observe("at_hash",
                        Jwt.Has(payload, "at_hash") ? "あり" : "なし",
                        "この形では access_token を返さないので、at_hash は任意（§3.3.2.11）。");

                    VerifyHash(r, "c_hash", payload, res.Code, "code");
                }

                r.Done();
            }
        }

        /// <summary>EX-5.2 code token</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0502_code_tokenでcodeとaccess_tokenが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-5.2",
                    "response_type=code token : code と access_token がフラグメントで返る",
                    "access_token を返すなら、**token_type も添える**（Implicit と同じ規則）。"
                    + "id_token は要求していないので返さない。",
                    "OIDC Core §3.3.2.5 / RFC 6749 §4.2.2（token_type は REQUIRED、"
                    + "大小文字を区別しない。expires_in は RECOMMENDED）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code token / scope=openid");
                r.Step("GET /authorize に response_type=code token を付けて送る");

                AuthZResponse res = await AuthorizeAsync(
                    client, reg, "code token", "nonce-" + Guid.NewGuid().ToString("N"));

                r.Verify("フラグメント（#）で返る", res.Where == ParameterLocation.Fragment,
                    "フラグメント", res.ToString());

                r.Verify("code が返る", !string.IsNullOrEmpty(res.Code),
                    "code あり", res.Code == null ? "なし" : "あり（値は伏せる）");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(res.Get("access_token")),
                    "access_token あり", res.Get("access_token") == null ? "なし" : "あり（値は伏せる）");

                r.Verify("token_type が Bearer",
                    string.Equals(res.Get("token_type"), "Bearer", StringComparison.OrdinalIgnoreCase),
                    "Bearer（大小文字は問わない）", res.Get("token_type") ?? "なし");

                r.Verify("id_token は返さない（response_type に id_token が無い）",
                    string.IsNullOrEmpty(res.Get("id_token")),
                    "返さない", res.Get("id_token") == null ? "返さなかった" : "**返してしまった**");

                r.Observe("expires_in", res.Get("expires_in") ?? "なし", "RECOMMENDED。");

                r.Done();
            }
        }

        /// <summary>EX-5.3 code id_token token</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（OpenTouryo#584）。実測（2026/09/10, net10.0 / net48）では、"
            + "at_hash / c_hash が一致しない。"
            + "Open棟梁 の IdToken.CreateHash が、SHA-256 の左半分ではなく、"
            + "左右を XOR で畳んだ値を使っている（ArrayOperator.ShortenByteArray）。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0503_code_id_token_tokenでat_hashとc_hashが一致する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-5.3",
                    "response_type=code id_token token : at_hash と c_hash の両方が一致する",
                    "3 つを同時に返す形。**id_token が code と access_token の両方に結び付いている**ことを確かめる。"
                    + "片方でも合わなければ、その値だけを差し替えられる。",
                    "OIDC Core §3.3.2.11（この形では at_hash も c_hash も REQUIRED）/ §3.3.2.9 / §3.3.2.10");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string nonce = "nonce-" + Guid.NewGuid().ToString("N");

                r.Target("client_name=" + KnownClients.TestClient
                    + " / response_type=code id_token token / scope=openid");
                r.Step("GET /authorize に response_type=code id_token token と nonce を付けて送る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "code id_token token", nonce);

                string idToken = res.Get("id_token");
                string accessToken = res.Get("access_token");

                r.Verify("フラグメント（#）で返る", res.Where == ParameterLocation.Fragment,
                    "フラグメント", res.ToString());

                r.Verify("code / id_token / access_token がすべて返る",
                    !string.IsNullOrEmpty(res.Code) && !string.IsNullOrEmpty(idToken)
                    && !string.IsNullOrEmpty(accessToken),
                    "3 つともあり",
                    "code=" + (res.Code == null ? "なし" : "あり")
                    + " / id_token=" + (idToken == null ? "なし" : "あり")
                    + " / access_token=" + (accessToken == null ? "なし" : "あり"));

                if (!string.IsNullOrEmpty(idToken) && !string.IsNullOrEmpty(res.Code)
                    && !string.IsNullOrEmpty(accessToken))
                {
                    Jwks.Result sig = Jwks.Verify(idToken, await Flows.JwkSetAsync(client));

                    r.Verify("id_token の署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);

                    JsonElement payload = Jwt.Payload(idToken);

                    r.VerifyEqual("nonce が送った値と一致する", nonce, Jwt.String(payload, "nonce"));

                    ObserveStateHash(r, payload, State);

                    // at_hash を先に確かめる（c_hash で止まると、at_hash の結果が残らないため）。
                    VerifyHash(r, "at_hash", payload, accessToken, "access_token");
                    VerifyHash(r, "c_hash", payload, res.Code, "code");
                }

                r.Done();
            }
        }

        /// <summary>EX-5.4 code の交換</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0504_Hybridのcodeを交換でき両方のid_tokenが同じユーザを指す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-5.4",
                    "Hybrid で受け取った code をトークンに交換でき、両方の id_token が同じユーザを指す",
                    "code の交換で得る id_token は、認可エンドポイントで受け取ったものと"
                    + "**同じ発行者・同じユーザ**でなければならない。"
                    + "違えば、RP はどちらを信じればよいか分からない。",
                    "OIDC Core §3.3.3.6（iss と sub は、認可エンドポイントの id_token と同一。MUST）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                Assert.False(string.IsNullOrEmpty(reg.ClientSecret),
                    "前提: " + KnownClients.TestClient + " に client_secret が登録されていること");

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code id_token");
                r.Step("(1) response_type=code id_token で code と id_token を受け取る");

                AuthZResponse res = await AuthorizeAsync(
                    client, reg, "code id_token", "nonce-" + Guid.NewGuid().ToString("N"));

                string idToken1 = res.Get("id_token");

                Assert.False(string.IsNullOrEmpty(res.Code) || string.IsNullOrEmpty(idToken1),
                    "前提: code と id_token が返ること（" + res.ToString() + "）");

                r.Step("(2) その code を、同じ redirect_uri でトークンに交換する");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, res.Code, reg.RedirectUriToken);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Verify("id_token が返る", !string.IsNullOrEmpty(token.IdToken),
                    "id_token あり", token.IdToken == null ? "なし" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(token.IdToken))
                {
                    JsonElement p1 = Jwt.Payload(idToken1);
                    JsonElement p2 = Jwt.Payload(token.IdToken);

                    r.VerifyEqual("iss が同じ", Jwt.String(p1, "iss"), Jwt.String(p2, "iss"));
                    r.VerifyEqual("sub が同じ", Jwt.String(p1, "sub"), Jwt.String(p2, "sub"));
                }

                r.Done();
            }
        }
    }
}
