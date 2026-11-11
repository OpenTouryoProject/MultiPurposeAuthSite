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
//* クラス名        ：IdTokenOnlyTests
//* クラス日本語名  ：RT-360 access token を返さない応答の id_token（at_hash・クレーム・response_types_supported）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/11  玄人 幸道         新規（#360）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-360 access token を返さない応答の id_token（#360）。
    /// </summary>
    /// <remarks>
    /// **id_token は、認可エンドポイントで作る access token から組み立てる**（`CmnIdToken.ChangeToIdTokenFromAccessToken`）。
    /// **以前は、access token を返さない `id_token`・`code id_token` でも、その access token の at_hash を付けていた**
    /// （RP が確かめられない値。適合性テストの `oidcc-server [id_token]`・`[code id_token]` が落ちた）。
    /// **また `response_type=id_token` では、UserInfo を引く access token が無いのに、scope のクレームを id_token に入れていなかった。**
    /// Discovery の `response_types_supported` にも、受け付ける `id_token` を載せていなかった。
    /// </remarks>
    public class IdTokenOnlyTests : TargetTestBase
    {
        /// <summary>state（固定）</summary>
        private const string State = "state-rt360";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdTokenOnlyTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-360.1 response_type=id_token の id_token に at_hash を付けない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36001_id_tokenの応答のid_tokenにat_hashを付けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-360.1",
                    "response_type=id_token の id_token に、at_hash を付けない（access token を返さないため）",
                    "**at_hash は、id_token と一緒に返した access token との結び付けである。** "
                    + "**access token を返さない応答に at_hash を付けても、RP は確かめられない**（以前は付けていた）。",
                    "OIDC Core 1.0 §3.2.2.10（at_hash は access token を出さないときは使わない）/ #360");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string nonce = "nonce-" + Guid.NewGuid().ToString("N");

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=id_token / scope=openid");
                r.Step("GET /authorize に response_type=id_token と nonce を付けて送る");

                AuthZResponse res = await IdTokenOnlyTests.AuthorizeAsync(client, reg, "id_token", "openid", nonce);
                string idToken = res.Get("id_token");

                Assert.False(string.IsNullOrEmpty(idToken), "前提: id_token が返ること（" + res.ToString() + "）");

                r.Verify("access_token は返さない", string.IsNullOrEmpty(res.Get("access_token")),
                    "返さない", res.Get("access_token") == null ? "返さなかった" : "**返してしまった**");

                Jwks.Result sig = Jwks.Verify(idToken, await Flows.JwkSetAsync(client));
                r.Verify("id_token の署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);

                JsonElement payload = Jwt.Payload(idToken);

                r.VerifyEqual("nonce が送った値と一致する", nonce, Jwt.String(payload, "nonce"));

                r.Verify("**at_hash を付けない**", !Jwt.Has(payload, "at_hash"),
                    "at_hash なし", Jwt.Has(payload, "at_hash") ? "**あり**" : "なし");

                r.Done();
            }
        }

        /// <summary>RT-360.2 response_type=id_token の id_token に、scope のクレームを入れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36002_id_tokenの応答のid_tokenにscopeのクレームを入れる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-360.2",
                    "response_type=id_token で scope=openid email phone を要求すると、email と email_verified が id_token に入る（値の無い phone_number は入らない）",
                    "**access token を返さないので、RP は UserInfo を引けない。** scope のクレームは id_token で返す（以前は入れていなかった）。"
                    + "**値の無いクレームは名前ごと省く**（UserInfo と同じ。種データの利用者は電話番号を持たない）。",
                    "OIDC Core 1.0 §5.4（response_type=id_token ではクレームを ID Token で返す）/ OIDC Core 1.0 §5.3.2 / #360");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=id_token / scope=openid email phone / username="
                    + TestEnv.TestUserName(targetKey) + "（種データの利用者。メール アドレスあり・電話番号なし）");
                r.Step("GET /authorize に response_type=id_token、scope=openid email phone を付けて送る");

                AuthZResponse res = await IdTokenOnlyTests.AuthorizeAsync(
                    client, reg, "id_token", "openid email phone", "nonce-" + Guid.NewGuid().ToString("N"));
                string idToken = res.Get("id_token");

                Assert.False(string.IsNullOrEmpty(idToken), "前提: id_token が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(idToken);

                r.Verify("**email が文字列で入る**",
                    Jwt.KindOf(payload, "email") == JsonValueKind.String && !string.IsNullOrEmpty(Jwt.String(payload, "email")),
                    "値の在る文字列", Jwt.KindOf(payload, "email") == JsonValueKind.Undefined ? "**項目なし**" : "型 = " + Jwt.KindOf(payload, "email"));

                r.Verify("**email_verified が真偽値で入る**",
                    Jwt.KindOf(payload, "email_verified") == JsonValueKind.True || Jwt.KindOf(payload, "email_verified") == JsonValueKind.False,
                    "真偽値", Jwt.KindOf(payload, "email_verified") == JsonValueKind.Undefined ? "**項目なし**" : "型 = " + Jwt.KindOf(payload, "email_verified"));

                r.Verify("値の無い phone_number・phone_number_verified は入らない",
                    !Jwt.Has(payload, "phone_number") && !Jwt.Has(payload, "phone_number_verified"),
                    "どちらも項目なし",
                    "phone_number = " + (Jwt.Has(payload, "phone_number") ? "**あり**" : "なし")
                    + " / phone_number_verified = " + (Jwt.Has(payload, "phone_number_verified") ? "**あり**" : "なし"));

                r.Verify("access token の項目（scopes・jti など）は入らない",
                    !Jwt.Has(payload, "scopes") && !Jwt.Has(payload, "jti"),
                    "どちらも項目なし",
                    "scopes = " + (Jwt.Has(payload, "scopes") ? "**あり**" : "なし")
                    + " / jti = " + (Jwt.Has(payload, "jti") ? "**あり**" : "なし"));

                r.Done();
            }
        }

        /// <summary>RT-360.3 response_type=code id_token の id_token に at_hash を付けない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36003_code_id_tokenの応答のid_tokenにat_hashを付けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-360.3",
                    "response_type=code id_token の id_token に、at_hash を付けない（c_hash は付けて、code と一致する。scope のクレームは入れない）",
                    "**この形は access token を認可エンドポイントから返さない。** 仕様では、この形の at_hash は任意（OPTIONAL）である。"
                    + "**ただし、付けていた値は返さない access token のもの**で、トークン エンドポイントの access token とも別の値なので、"
                    + "**RP はどの access token とも突き合わせられない**（以前は付けていた。適合性テストの `oidcc-server [code id_token]` が落ちた）。"
                    + "**付けないことにした。** scope のクレームは UserInfo で受け取れるので、id_token には入れない（従来どおり）。",
                    "OIDC Core 1.0 §3.3.2.11（at_hash は access token を返すとき REQUIRED、ほかは OPTIONAL。c_hash は REQUIRED）/ #360（付けない）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code id_token / scope=openid email");
                r.Step("GET /authorize に response_type=code id_token、scope=openid email を付けて送る");

                AuthZResponse res = await IdTokenOnlyTests.AuthorizeAsync(
                    client, reg, "code id_token", "openid email", "nonce-" + Guid.NewGuid().ToString("N"));
                string idToken = res.Get("id_token");

                Assert.False(string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(res.Code),
                    "前提: code と id_token が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(idToken);

                r.Verify("**at_hash を付けない**", !Jwt.Has(payload, "at_hash"),
                    "at_hash なし", Jwt.Has(payload, "at_hash") ? "**あり**" : "なし");

                r.VerifyEqual("c_hash が、code から計算した値と一致する",
                    Jwt.HalfHash(res.Code), Jwt.String(payload, "c_hash") ?? "（c_hash なし）");

                r.Verify("scope のクレーム（email）は入れない", !Jwt.Has(payload, "email"),
                    "email なし", Jwt.Has(payload, "email") ? "**あり**" : "なし");

                r.Done();
            }
        }

        /// <summary>RT-360.4 response_type=id_token token の id_token には at_hash を付け、access_token と一致する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36004_id_token_tokenの応答のid_tokenのat_hashはaccess_tokenと一致する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-360.4",
                    "response_type=id_token token の id_token には at_hash を付け、返した access_token から計算した値と一致する（scope のクレームは入れない）",
                    "**at_hash を付けるのを「access token を返すとき」に絞った後も、返すときは付けている**ことを確かめる。"
                    + "**scope のクレームは、返した access token で UserInfo から受け取れるので、id_token には入れない**（従来どおり）。",
                    "OIDC Core 1.0 §3.2.2.10（access token を返すとき at_hash は REQUIRED）/ #360");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=id_token token / scope=openid email");
                r.Step("GET /authorize に response_type=id_token token、scope=openid email を付けて送る");

                AuthZResponse res = await IdTokenOnlyTests.AuthorizeAsync(
                    client, reg, "id_token token", "openid email", "nonce-" + Guid.NewGuid().ToString("N"));
                string idToken = res.Get("id_token");
                string accessToken = res.Get("access_token");

                Assert.False(string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(accessToken),
                    "前提: id_token と access_token が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(idToken);

                r.VerifyEqual("**at_hash が、access_token から計算した値と一致する**",
                    Jwt.HalfHash(accessToken), Jwt.String(payload, "at_hash") ?? "（at_hash なし）");

                r.Verify("scope のクレーム（email）は入れない", !Jwt.Has(payload, "email"),
                    "email なし", Jwt.Has(payload, "email") ? "**あり**" : "なし");

                r.Done();
            }
        }

        /// <summary>RT-360.5 Discovery の response_types_supported に id_token を載せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36005_Discoveryのresponse_types_supportedにid_tokenを載せる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-360.5",
                    "Implicit を開いた配備の Discovery は、response_types_supported に id_token を載せる",
                    "**受け付ける response_type は広告する。** 以前は `id_token` 単独を「受け付けるが広告しない」としていたので、"
                    + "Discovery を見る RP が `id_token` を選べなかった（Implicit を閉じた配備では、受け付けも広告もしない。RT-314.1・.4）。",
                    "OIDC Discovery 1.0 §3（response_types_supported）/ OIDC Core 1.0 §15.2（動的な OP は id_token を MUST）/ #360");

                r.Target("GET /.well-known/openid-configuration（既定の構成。`EnableImplicitGrantType` = true）");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string[] types = discovery.Strings("response_types_supported") ?? new string[0];

                r.Verify("**id_token を載せる**", types.Contains("id_token"),
                    "載せる", types.Contains("id_token") ? "載せる" : "**載せていない**（" + string.Join(" / ", types) + "）");

                r.Done();
            }
        }

        /// <summary>RT-360.6 response_type=id_token でも、要求していない scope のクレームは入れない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36006_id_tokenの応答でも要求していないscopeのクレームは入れない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-360.6",
                    "response_type=id_token で scope=openid だけを要求すると、email・email_verified は id_token に入らない",
                    "**id_token に入れるのは、要求して許された scope のクレームだけ**である（RT-360.2 の対照）。"
                    + "**クレームを残す判定が、scope に関係なく利用者の値を出していないか**を確かめる。",
                    "OIDC Core 1.0 §5.4（scope の値で要求したクレームを返す）/ #360");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=id_token / scope=openid / username="
                    + TestEnv.TestUserName(targetKey) + "（種データの利用者。メール アドレスあり）");
                r.Step("GET /authorize に response_type=id_token、scope=openid を付けて送る");

                AuthZResponse res = await IdTokenOnlyTests.AuthorizeAsync(
                    client, reg, "id_token", "openid", "nonce-" + Guid.NewGuid().ToString("N"));
                string idToken = res.Get("id_token");

                Assert.False(string.IsNullOrEmpty(idToken), "前提: id_token が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(idToken);

                r.Verify("**email・email_verified は入らない**",
                    !Jwt.Has(payload, "email") && !Jwt.Has(payload, "email_verified"),
                    "どちらも項目なし",
                    "email = " + (Jwt.Has(payload, "email") ? "**あり**" : "なし")
                    + " / email_verified = " + (Jwt.Has(payload, "email_verified") ? "**あり**" : "なし"));

                r.Done();
            }
        }

        #region 補助

        /// <summary>認可要求を送る（サインイン済み。同意画面が出たら許可する）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseType">response_type</param>
        /// <param name="scope">scope</param>
        /// <param name="nonce">nonce</param>
        /// <returns>AuthZResponse</returns>
        /// <remarks>
        /// **`prompt=none` は付けない。** 同意していない scope（email・phone）を求めると、
        /// `consent_required` で返るため（それまでに同意したかは、テストの順で変わる）。
        /// </remarks>
        private static async Task<AuthZResponse> AuthorizeAsync(
            IdPClient client, ClientRegistration reg, string responseType, string scope, string nonce)
        {
            AuthZResponse res = await client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", responseType },
                { "client_id", reg.ClientId },
                { "scope", scope },
                { "redirect_uri", reg.RedirectUriToken },
                { "state", IdTokenOnlyTests.State },
                { "nonce", nonce }
            });

            return res.NeedsConsent ? await client.GrantConsentAsync(res) : res;
        }

        #endregion
    }
}
