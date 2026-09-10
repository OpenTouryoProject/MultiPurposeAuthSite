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
//* クラス名        ：OidcTests
//* クラス日本語名  ：TC-6 OIDC 固有（id_token と UserInfo）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストケースの追加）
//**********************************************************************************

using System;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-6. OIDC 固有の検証。id_token（JWT）の中身と署名、UserInfo。
    /// </summary>
    public class OidcTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public OidcTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>TC-6.1 openid スコープの必須性</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0601_openidスコープがあるときだけid_tokenが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-6.1",
                    "scope に openid を含めたときだけ id_token が返る",
                    "openid が無ければ、それは OAuth 2.0 の認可であって OIDC の認証ではない。"
                    + "id_token を返してはならない。",
                    "OIDC Core §3.1.2.1（openid は REQUIRED）/ §2");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) scope=\"openid email\" で認可コード フローを通す");

                JsonResponse withOpenid = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Verify("openid あり → id_token が返る",
                    !string.IsNullOrEmpty(withOpenid.IdToken),
                    "id_token あり", withOpenid.IdToken == null ? "なし" : "あり");

                r.Step("(2) scope=\"email\"（openid 無し）で通す");

                JsonResponse withoutOpenid = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "email");

                r.Verify("openid なし → id_token が返らない",
                    string.IsNullOrEmpty(withoutOpenid.IdToken),
                    "id_token なし",
                    string.IsNullOrEmpty(withoutOpenid.IdToken) ? "なし" : "**返ってしまった**");

                r.Verify("openid なしでも access_token は返る",
                    !string.IsNullOrEmpty(withoutOpenid.AccessToken),
                    "access_token あり",
                    withoutOpenid.AccessToken == null ? "なし" : "あり");

                r.Done();
            }
        }

        /// <summary>TC-6.2 id_token の必須クレーム</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0602_id_tokenの必須クレームが妥当(string targetKey)
        {
            const string Nonce = "nonce-tc0602";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-6.2",
                    "id_token の iss / sub / aud / exp / iat / nonce が妥当",
                    "RP は id_token のこれらを検証して初めて、"
                    + "「誰が」「誰のために」「いつまで」認証したのかを信頼できる。",
                    "OIDC Core §2（ID Token）/ §3.1.3.7（ID Token の検証）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("認可コード フローで id_token を取得する（nonce=" + Nonce + "）");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", Nonce);

                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること");

                JsonElement idToken = Jwt.Payload(token.IdToken);

                // --- iss ---
                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string issuer = discovery.String("issuer");

                r.Note("iss の期待値は、Discovery 文書の issuer から取る（決め打ちにしない）。");

                r.VerifyEqual("iss が Discovery の issuer と完全一致する",
                    issuer, Jwt.String(idToken, "iss"));

                // --- sub ---
                r.VerifyEqual("sub が認証したユーザである",
                    TestEnv.TestUserName, Jwt.String(idToken, "sub"));

                // --- aud ---
                r.VerifyEqual("aud が自クライアントの client_id と一致する",
                    reg.ClientId, Jwt.String(idToken, "aud"));

                // --- exp / iat ---
                r.Verify("exp が数値である（NumericDate）",
                    Jwt.KindOf(idToken, "exp") == JsonValueKind.Number,
                    "JSON の数値", "exp の型 = " + Jwt.KindOf(idToken, "exp"));

                r.Verify("iat が数値である（NumericDate）",
                    Jwt.KindOf(idToken, "iat") == JsonValueKind.Number,
                    "JSON の数値", "iat の型 = " + Jwt.KindOf(idToken, "iat"));

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long exp = long.Parse(Jwt.String(idToken, "exp"));
                long iat = long.Parse(Jwt.String(idToken, "iat"));

                r.Verify("exp が現在時刻より未来である", exp > now,
                    "exp > 現在時刻", "残り " + (exp - now) + " 秒");

                r.Verify("iat が未来ではない（時計のずれを 60 秒まで許容）", iat <= now + 60,
                    "iat <= 現在時刻 + 60", "iat - 現在 = " + (iat - now) + " 秒");

                // --- nonce ---
                r.VerifyEqual("認可リクエストの nonce がそのまま入る",
                    Nonce, Jwt.String(idToken, "nonce"));

                r.Done();
            }
        }

        /// <summary>TC-6.3 署名検証</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0603_id_tokenの署名をJWKSで検証できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-6.3",
                    "id_token の署名が JWK Set の公開鍵で検証できる",
                    "RP は、**認可サーバの公開鍵だけで** id_token の真正性を確かめられなければならない。"
                    + "検証できなければ、id_token は誰でも作れる文字列と変わらない。"
                    + "改竄したトークンが検証を通らないことも併せて見る。",
                    "OIDC Core §3.1.3.7 (6)（JWS で検証）/ §10.1（署名鍵は jwks_uri で公開）");

                r.Target(client.Target.DisplayName);
                r.Step("(1) 認可コード フローで id_token を取得する");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること");

                r.Step("(2) Discovery の jwks_uri から JWK Set を取得する");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string jwksUri = discovery.String("jwks_uri");

                JsonResponse jwks = await client.GetJsonAsync(client.ToLocalUrl(jwksUri));

                r.Verify("JWK Set が取得できる",
                    jwks.IsJson && jwks.KindOf("keys") == JsonValueKind.Array,
                    "keys 配列を持つ JSON", "jwks_uri = " + jwksUri + " / " + jwks.ToString());

                r.Step("(3) 公開鍵だけで署名を検証する（実装側の JWS クラスは使わない）");

                JsonElement header = Jwt.Header(token.IdToken);
                r.Note("id_token のヘッダ : alg=" + (Jwt.String(header, "alg") ?? "なし")
                    + " / kid=" + (Jwt.String(header, "kid") ?? "なし"));

                Jwks.Result verify = Jwks.Verify(token.IdToken, jwks.Json);

                r.Verify("正規の id_token の署名が検証できる", verify.Verified,
                    "検証成功", verify.Detail);

                r.Step("(4) ペイロードを書き換えた id_token を検証する（通ってはならない）");

                Jwks.Result tampered = Jwks.Verify(Jwks.Tamper(token.IdToken), jwks.Json);

                r.Verify("改竄した id_token は検証できない", !tampered.Verified,
                    "検証失敗", tampered.Detail);

                r.Done();
            }
        }

        /// <summary>TC-6.4 alg=none の拒否</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0604_alg_noneのトークンが受け付けられない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-6.4",
                    "alg=none に書き換えたトークンを認可サーバが受け付けない",
                    "署名を外した JWT を受理する実装は、**誰でも任意のトークンを作れる。**"
                    + "ここでは RP 側ではなく、**認可サーバの保護資源（/userinfo）が"
                    + "拒否するか**を見る。",
                    "JWT BCP（RFC 8725）§3.1（alg=none を拒否する）/ OIDC Core §3.1.3.7");

                r.Target(client.Target.DisplayName);
                r.Step("(1) 正規の access_token を取得する");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) 対照として、正規のトークンで /userinfo を叩く");

                JsonResponse ok = await client.UserInfoAsync(token.AccessToken);

                r.Verify("正規のトークンでは /userinfo が応答する",
                    ok.IsJson && ok.KindOf("sub") != JsonValueKind.Undefined,
                    "sub を含む JSON", ok.ToString());

                r.Step("(3) 同じトークンを alg=none（署名なし）に書き換えて叩く");

                string algNone = Jwks.ToAlgNone(token.AccessToken);

                JsonResponse none = await client.UserInfoAsync(algNone);

                bool accepted = none.IsJson && none.KindOf("sub") != JsonValueKind.Undefined;

                r.Verify("alg=none のトークンでユーザ情報を返さない", !accepted,
                    "sub を含む応答を返さない",
                    accepted ? "**受理してしまった**" : "拒否した（" + none.ToString() + "）");

                r.Step("(4) ペイロードだけ書き換え、署名はそのままのトークンで叩く");

                JsonResponse tampered = await client.UserInfoAsync(Jwks.Tamper(token.AccessToken));

                bool acceptedTampered =
                    tampered.IsJson && tampered.KindOf("sub") != JsonValueKind.Undefined;

                r.Verify("改竄したトークンでユーザ情報を返さない", !acceptedTampered,
                    "sub を含む応答を返さない",
                    acceptedTampered ? "**受理してしまった**"
                                     : "拒否した（" + tampered.ToString() + "）");

                r.Observe("拒否のしかた",
                    "alg=none : HTTP " + (int)none.StatusCode
                    + " / 改竄 : HTTP " + (int)tampered.StatusCode,
                    "OIDC Core §5.3.3 は 401 と WWW-Authenticate を求める（#196）。");

                r.Done();
            }
        }

        /// <summary>TC-6.5 UserInfo</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0605_UserInfoがスコープに応じた属性を返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-6.5",
                    "UserInfo が、要求したスコープに応じた属性を返す",
                    "Bearer トークンで /userinfo を叩くと、sub と、"
                    + "email / phone などスコープに対応した Claim が返ること。"
                    + "**要求していないスコープの属性が返ってはならない。**",
                    "OIDC Core §5.3（UserInfo Endpoint）/ §5.4（スコープと Claim の対応）");

                r.Target(client.Target.DisplayName);

                r.Step("(1) scope=\"openid email\" で取得したトークンで /userinfo を叩く");

                JsonResponse t1 = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                JsonResponse u1 = await client.UserInfoAsync(t1.AccessToken);

                r.Verify("JSON が返る", u1.IsJson, "JSON", u1.ToString());

                r.VerifyEqual("sub がテスト ユーザである",
                    TestEnv.TestUserName, u1.String("sub"));

                r.Verify("email スコープの属性が返る",
                    u1.KindOf("email") != JsonValueKind.Undefined,
                    "email あり", "email = " + (u1.KindOf("email") == JsonValueKind.Undefined
                        ? "なし" : "あり（値は伏せる）"));

                r.Verify("要求していない phone_number は返らない",
                    u1.KindOf("phone_number") == JsonValueKind.Undefined,
                    "phone_number なし",
                    u1.KindOf("phone_number") == JsonValueKind.Undefined
                        ? "なし" : "**返ってしまった**");

                r.Step("(2) scope=\"openid email phone\" で取得したトークンで叩く");

                JsonResponse t2 = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                JsonResponse u2 = await client.UserInfoAsync(t2.AccessToken);

                r.Verify("phone を要求すれば phone_number が返る",
                    u2.KindOf("phone_number") != JsonValueKind.Undefined,
                    "phone_number あり",
                    u2.KindOf("phone_number") == JsonValueKind.Undefined ? "なし" : "あり");

                r.Verify("email_verified が真偽値である",
                    u2.KindOf("email_verified") == JsonValueKind.True
                    || u2.KindOf("email_verified") == JsonValueKind.False
                    || u2.KindOf("email_verified") == JsonValueKind.Undefined,
                    "boolean（または返さない）",
                    "email_verified の型 = " + u2.KindOf("email_verified"));

                r.Step("(3) トークン無しで叩く");

                JsonResponse u3 = await client.GetJsonAsync("/userinfo");

                bool leaked = u3.IsJson && u3.KindOf("sub") != JsonValueKind.Undefined;

                r.Verify("Bearer トークン無しではユーザ情報を返さない", !leaked,
                    "sub を返さない", leaked ? "**返してしまった**" : "返さなかった");

                r.Done();
            }
        }
    }
}
