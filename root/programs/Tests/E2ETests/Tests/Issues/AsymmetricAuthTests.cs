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
//* クラス名        ：AsymmetricAuthTests
//* クラス日本語名  ：RT-239 認可コード以外でも private_key_jwt で認証する（#239）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/26  玄人 幸道         新規（#239 の段階 1・2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-239. `private_key_jwt` を、認可コード グラント以外でも受ける。
    /// </summary>
    /// <remarks>
    /// #238 で `client_assertion` を読むようにしたが、**受ける場所が限られていた。**
    /// `refresh_token` / ROPC / `client_credentials` の各グラントは**引数にアサーションを持たず**、
    /// `/revoke` と `/introspect` は **`client_assertion` を読んでさえいなかった。**
    ///
    /// 仕様は「**トークン エンドポイントと同じクライアント認証**」を求めている
    /// （RFC 6749 §6 / RFC 7009 §2.1 / RFC 7662 §2.1）。
    /// **FAPI 2.0 は、その方式を MTLS と `private_key_jwt` に限っている。**
    ///
    /// **測るのは `TestClient`（normal）。** 秘密と RSA 公開鍵の両方を登録しているので、
    /// 「秘密を持つクライアントが、あえて非対称で認証する」形を確かめられる。
    /// **`fapi1` / `fapi2` の登録は、まだ `refresh_token` を使えない**
    /// （`ClientModePolicy` が認可コード以外を normal に限っている。#239 の段階 3）。
    /// </remarks>
    public class AsymmetricAuthTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AsymmetricAuthTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>client_assertion（RS256）を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <returns>JWS</returns>
        /// <remarks>`aud` は、この実装が求めるトークン エンドポイントの URL。</remarks>
        private static string CreateClientAssertion(IdPClient client, string clientId)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>client_assertion だけを添えたフォームを作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="items">フォームの中身</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> WithClientAssertion(
            IdPClient client, string clientId, IDictionary<string, string> items)
        {
            Dictionary<string, string> form = new Dictionary<string, string>(items)
            {
                { "client_assertion", AsymmetricAuthTests.CreateClientAssertion(client, clientId) },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
            };

            return form;
        }

        /// <summary>RT-239.1 refresh_token を private_key_jwt で更新できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23901_refresh_tokenをprivate_key_jwtで更新できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-239.1",
                    "refresh_token の更新を、private_key_jwt のクライアント認証で行える",
                    "**RFC 6749 §6 は、コンフィデンシャル クライアントの認証を求めている**が、"
                    + "方式は限定していない。**FAPI 2.0 は MTLS と private_key_jwt に限る**ので、"
                    + "ここが通らないと、**アクセス トークンが切れるたびに認可からやり直す**ことになる。"
                    + "`GrantRefreshTokenCredentials` は**引数にアサーションを持っていなかった**（#239）。",
                    "RFC 6749 §6 / RFC 7523 §2.2 / FAPI 2.0 / #239");

                r.Target("client_name=" + KnownClients.TestClient
                    + "（normal。client_secret と jwk_rsa_publickey の両方を登録済み）");

                r.Step("(1) 認可コード フローで refresh_token を得る（client_secret で交換）");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email offline_access");

                string refreshToken = token.String("refresh_token");

                Skip.If(string.IsNullOrEmpty(refreshToken),
                    "refresh_token が返らない（offline_access の扱い。EX-1 を見ること）。");

                r.Step("(2) client_secret を送らず、client_assertion で更新する");

                JsonResponse refreshed = await client.TokenAsync(
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "refresh_token" },
                            { "refresh_token", refreshToken }
                        }));

                r.VerifyEqual("HTTP 200", "200", ((int)refreshed.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(refreshed.AccessToken),
                    "access_token あり",
                    string.IsNullOrEmpty(refreshed.AccessToken) ? refreshed.ToString() : "あり（値は伏せる）");

                r.Note("**client_id も送っていない。** アサーションの `iss` から引く（RFC 7523 §3）。"
                    + "refresh_token と発行先の結び付け（#188）も、その client_id で確かめられる。");

                r.Done();
            }
        }

        /// <summary>RT-239.2 /revoke を private_key_jwt で呼べる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23902_revokeをprivate_key_jwtで呼べる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-239.2",
                    "トークンの失効（/revoke）を、private_key_jwt のクライアント認証で行える",
                    "**RFC 7009 §2.1 は「RFC 6749 §2.3 の資格情報を含める」としている**"
                    + "（＝トークン エンドポイントと同じ方式）。"
                    + "以前は `client_assertion` を読んでおらず、**秘密を持たないクライアントは失効できなかった。**"
                    + "失効できないと、**漏れたトークンを止める手段が無い。**",
                    "RFC 7009 §2.1 / RFC 7523 §2.2 / #239");

                r.Target("client_name=" + KnownClients.TestClient);

                r.Step("(1) トークンを得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) client_assertion で POST /revoke");

                JsonResponse revoked = await client.PostJsonAsync("/revoke",
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "token", token.AccessToken },
                            { "token_type_hint", "access_token" }
                        }));

                r.VerifyEqual("HTTP 200（RFC 7009 §2.2）", "200", ((int)revoked.StatusCode).ToString());

                r.Step("(3) 失効したことを確かめる（/userinfo が 401）");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("失効後は 401", "401", ((int)userInfo.StatusCode).ToString());

                r.Done();
            }
        }

        /// <summary>RT-239.3 /introspect を private_key_jwt で呼べる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23903_introspectをprivate_key_jwtで呼べる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-239.3",
                    "トークンの問い合わせ（/introspect）を、private_key_jwt のクライアント認証で行える",
                    "**RFC 7662 §2.1 は、この口に認証を求めている**（トークン エンドポイントと同じ方式）。"
                    + "以前は `client_assertion` を読んでおらず、**秘密を持たないクライアントは問い合わせできなかった。**",
                    "RFC 7662 §2.1 / RFC 7523 §2.2 / #239");

                r.Target("client_name=" + KnownClients.TestClient);

                r.Step("(1) トークンを得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) client_assertion で POST /introspect");

                JsonResponse res = await client.PostJsonAsync("/introspect",
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "token", token.AccessToken },
                            { "token_type_hint", "access_token" }
                        }));

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                bool active = res.IsJson
                    && res.Json.TryGetProperty("active", out System.Text.Json.JsonElement value)
                    && value.ValueKind == System.Text.Json.JsonValueKind.True;

                r.Verify("active が true", active, "true", active ? "true" : "**true でない**");

                r.Done();
            }
        }

        /// <summary>RT-239.4 誤ったアサーションは断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23904_誤ったアサーションは断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-239.4",
                    "署名が壊れた client_assertion では、/revoke も /introspect も通らない",
                    "**受け口を増やしたら、そこが緩んでいないことも確かめる。**"
                    + "アサーションは署名だけがクライアントの証明なので、"
                    + "**検証せずに通すと、誰でも他人のトークンを失効できる。**",
                    "RFC 7009 §2.1 / RFC 7662 §2.1 / #239");

                r.Target("client_name=" + KnownClients.TestClient + "（署名の先頭 1 文字を書き換える）");

                r.Step("(1) 署名を壊した client_assertion を作る");

                string jws = AsymmetricAuthTests.CreateClientAssertion(client, reg.ClientId);
                string[] parts = jws.Split('.');

                // **先頭の 1 文字を変える**（末尾は余りビットで、変えても同じ署名になり得る。RT-233.3 参照）
                parts[2] = (parts[2].StartsWith("A") ? "B" : "A") + parts[2].Substring(1);

                Dictionary<string, string> broken = new Dictionary<string, string>()
                {
                    { "token", "dummy-token" },
                    { "client_assertion", string.Join(".", parts) },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
                };

                r.Step("(2) POST /revoke");

                JsonResponse revoked = await client.PostJsonAsync("/revoke", broken);

                r.VerifyEqual("/revoke : HTTP 401", "401", ((int)revoked.StatusCode).ToString());

                r.VerifyEqual("/revoke : エラーは invalid_client",
                    "invalid_client", revoked.Error ?? "（無し）");

                r.Step("(3) POST /introspect");

                JsonResponse introspected = await client.PostJsonAsync("/introspect", broken);

                r.VerifyEqual("/introspect : HTTP 401", "401", ((int)introspected.StatusCode).ToString());

                r.VerifyEqual("/introspect : エラーは invalid_client",
                    "invalid_client", introspected.Error ?? "（無し）");

                r.Done();
            }
        }
    }
}
