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
//* クラス名        ：DeviceAuthorizationTests
//* クラス日本語名  ：EX-4 Device Authorization Grant（RFC 8628）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-4. Device Authorization Grant（RFC 8628）。
    ///
    /// 入力手段の乏しい機器（TV など）が、ユーザに**別の端末で**承認してもらってトークンを得る。
    ///
    ///   機器   : POST /device_authz → device_code と user_code を得る
    ///   ユーザ : 別の端末で /device_verify を開き、user_code を入力して許可する
    ///   機器   : POST /token（grant_type=device_code）をポーリングする
    ///
    /// device モードのクライアント（TestClient3、client_secret なし）を使う。
    /// </summary>
    public class DeviceAuthorizationTests : TargetTestBase
    {
        /// <summary>grant_type</summary>
        private const string GrantType = "urn:ietf:params:oauth:grant-type:device_code";

        /// <summary>デバイス認可エンドポイント（DeviceAuthZAuthorizeEndpoint）</summary>
        private const string AuthorizePath = "/device_authz";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DeviceAuthorizationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>機器 : デバイス認可を始める</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> StartAsync(IdPClient client, string clientId)
        {
            return client.PostJsonAsync(AuthorizePath, new Dictionary<string, string>()
            {
                { "client_id", clientId },
                { "scope", "profile email" }
            });
        }

        /// <summary>機器 : トークンを要求する（ポーリングの 1 回分）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="deviceCode">device_code</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> PollAsync(IdPClient client, string clientId, string deviceCode)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", GrantType },
                { "device_code", deviceCode },
                { "client_id", clientId }
            });
        }

        /// <summary>EX-4.1 応答の必須項目</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0401_デバイス認可の応答に必須の項目が揃っている(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-4.1",
                    "デバイス認可の応答に、必須の項目が揃っている",
                    "入力手段の乏しい機器（TV など）が、**別の端末でユーザに承認してもらう**ための起点。"
                    + "機器はこの応答だけを頼りに、ユーザへの案内とポーリングを行う。",
                    "RFC 8628 §3.1 / §3.2（device_code / user_code / verification_uri / expires_in は REQUIRED）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3 + "（device モード、client_secret なし）");
                r.Step("POST " + AuthorizePath + " に client_id と scope を送る");

                JsonResponse res = await StartAsync(client, reg.ClientId);

                foreach (string name in new string[] { "device_code", "user_code", "verification_uri", "expires_in" })
                {
                    bool has = res.KindOf(name) != JsonValueKind.Undefined;

                    r.Verify(name + " がある", has, "あり", has ? "あり" : "なし（" + res.ToString() + "）");
                }

                r.Observe("verification_uri", res.String("verification_uri") ?? "なし",
                    "ユーザが別の端末で開く URL。");

                r.Observe("任意の項目",
                    "verification_uri_complete="
                    + (res.KindOf("verification_uri_complete") != JsonValueKind.Undefined ? "あり" : "なし")
                    + " / interval=" + (res.String("interval") ?? "なし"));

                r.Observe("expires_in / interval の JSON 型",
                    "expires_in=" + res.KindOf("expires_in") + " / interval=" + res.KindOf("interval"),
                    "秒数なので数値（Number）が自然（§3.2 の例も数値）。"
                    + "文字列だと、型に厳しいクライアントは読めない。");

                r.Step("（参考）Discovery に、このエンドポイントが載っているかを見る");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                bool hasEndpoint = discovery.KindOf("device_authorization_endpoint") != JsonValueKind.Undefined;
                bool hasGrant = false;

                JsonElement grants;
                if (discovery.IsJson
                    && discovery.Json.TryGetProperty("grant_types_supported", out grants)
                    && grants.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement g in grants.EnumerateArray())
                    {
                        if (g.ToString() == GrantType)
                        {
                            hasGrant = true;
                        }
                    }
                }

                r.Observe("Discovery での広告",
                    "device_authorization_endpoint=" + (hasEndpoint ? "あり" : "なし")
                    + " / grant_types_supported に device_code=" + (hasGrant ? "あり" : "なし"),
                    "RFC 8628 §4 の認可サーバ メタデータ。Discovery の不備は #189 で扱っている。");

                r.Done();
            }
        }

        /// <summary>EX-4.2 承認前</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0402_承認前のポーリングはauthorization_pending(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-4.2",
                    "ユーザが承認する前のポーリングには、authorization_pending を返す",
                    "機器は、ユーザの操作を待ちながらトークン エンドポイントを繰り返し叩く。"
                    + "**まだ承認されていないこと**を、失敗とは区別できる形で伝える必要がある。",
                    "RFC 8628 §3.4 / §3.5（authorization_pending）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3);
                r.Step("(1) 機器 : POST " + AuthorizePath + " で device_code を得る");

                JsonResponse start = await StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");

                Assert.False(string.IsNullOrEmpty(deviceCode), "前提: device_code が発行されること");

                r.Step("(2) 機器 : ユーザが何もしないうちに、grant_type=device_code でトークンを要求する");

                JsonResponse poll = await PollAsync(client, reg.ClientId, deviceCode);

                r.VerifyEqual("authorization_pending を返す", "authorization_pending", poll.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(poll.AccessToken),
                    "access_token を返さない",
                    poll.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>EX-4.3 承認</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0403_ユーザが承認すると機器はトークンを取得できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-4.3",
                    "ユーザが承認すると、機器はトークンを取得できる",
                    "**フローの骨格。** トークンを受け取る機器（device_code を持つ）と、"
                    + "承認するユーザ（user_code を入力する）は、別の端末である。"
                    + "承認したユーザの権限で、機器にトークンが出ること。",
                    "RFC 8628 §3.3（ユーザの操作）/ §3.4 / §3.5");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3
                    + " / 承認するユーザ = " + TestEnv.TestUserName);
                r.Step("(1) 機器 : POST " + AuthorizePath + " で device_code と user_code を得る");
                r.Step("(2) ユーザ : サインインした端末で /device_verify を開き、user_code を入力して許可する");
                r.Step("(3) 機器 : grant_type=device_code でトークンを要求する");
                r.Note("このテストでは 1 つの HTTP クライアントが両方の役を務める。"
                    + "機器側の要求（" + AuthorizePath + " と /token）は Cookie に依存しないので、"
                    + "役の区別には影響しない。");

                JsonResponse start = await StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること");

                bool accepted = await client.SubmitDeviceUserCodeAsync(userCode, true);

                r.Verify("検証画面が承認を受け付ける", accepted,
                    "受け付ける", accepted ? "受け付けた" : "**受け付けなかった**");

                JsonResponse token = await PollAsync(client, reg.ClientId, deviceCode);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(token.AccessToken))
                {
                    r.VerifyEqual("承認したユーザのトークンである（sub）",
                        TestEnv.TestUserName, Jwt.String(Jwt.Payload(token.AccessToken), "sub"));
                }

                r.Observe("refresh_token / id_token",
                    "refresh_token=" + (string.IsNullOrEmpty(token.RefreshToken) ? "なし" : "あり")
                    + " / id_token=" + (string.IsNullOrEmpty(token.IdToken) ? "なし" : "あり"),
                    "この実装は refresh_token を生成・保存するが、応答には含めていない"
                    + "（CmnEndpoints.GrantDeviceAuthZ）。渡さないなら、生成しない方がよい。");

                r.Done();
            }
        }

        /// <summary>EX-4.4 拒否</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0404_ユーザが拒否すると機器にはaccess_deniedを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-4.4",
                    "ユーザが拒否すると、機器には access_denied を返す",
                    "拒否されたら、機器はポーリングをやめる必要がある。"
                    + "**pending のままだと、期限が切れるまで叩き続ける。**",
                    "RFC 8628 §3.5（access_denied）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3
                    + " / 拒否するユーザ = " + TestEnv.TestUserName);
                r.Step("(1) 機器 : device_code と user_code を得る");
                r.Step("(2) ユーザ : /device_verify で user_code を入力して拒否する");
                r.Step("(3) 機器 : トークンを要求する");

                JsonResponse start = await StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること");

                bool accepted = await client.SubmitDeviceUserCodeAsync(userCode, false);

                Assert.True(accepted, "前提: 検証画面が操作を受け付けること");

                JsonResponse poll = await PollAsync(client, reg.ClientId, deviceCode);

                r.VerifyEqual("access_denied を返す", "access_denied", poll.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(poll.AccessToken),
                    "access_token を返さない",
                    poll.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>EX-4.5 device_code の再利用</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正。実測（2026/09/10, net10.0 / net48）では、"
            + "使用済みの device_code で HTTP 500 になる"
            + "（DeviceAuthZProvider.ReceiveTokenReq の KeyNotFoundException）。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0405_トークンを受け取った後のdevice_codeは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-4.5",
                    "トークンを受け取った後の device_code は、もう使えない",
                    "device_code は、承認 1 回につきトークン 1 回。"
                    + "**再び使えるなら、device_code を盗み見た者もトークンを得られる。**",
                    "RFC 8628 §3.5 / RFC 6749 §4.1.2（認可コードは 1 回限り。device_code も同じ役割を担う）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3);
                r.Step("(1) 承認まで済ませ、トークンを 1 回受け取る");

                JsonResponse start = await StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること");

                Assert.True(await client.SubmitDeviceUserCodeAsync(userCode, true),
                    "前提: 検証画面が承認を受け付けること");

                JsonResponse first = await PollAsync(client, reg.ClientId, deviceCode);

                Assert.False(string.IsNullOrEmpty(first.AccessToken), "前提: 1 回目はトークンが返ること");

                r.Step("(2) 同じ device_code で、もう一度トークンを要求する");

                JsonResponse second = await PollAsync(client, reg.ClientId, deviceCode);

                r.Verify("2 回目はトークンを発行しない", string.IsNullOrEmpty(second.AccessToken),
                    "access_token を返さない",
                    second.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Verify("2 回目は JSON のエラー応答を返す",
                    second.IsJson && !string.IsNullOrEmpty(second.Error),
                    "error を含む JSON", second.ToString());

                r.Observe("2 回目の error", second.Error ?? "なし",
                    "RFC 8628 §3.5 の語彙では expired_token、RFC 6749 §5.2 では invalid_grant が近い。");

                r.Done();
            }
        }

        /// <summary>EX-4.6 未登録の client_id</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0406_登録されていないclient_idでは始められない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-4.6",
                    "登録されていない client_id では、デバイス認可を始められない",
                    "未登録のクライアントの名義で user_code を発行すると、ユーザは"
                    + "**誰に権限を渡すのか分からないまま**承認させられる。",
                    "RFC 8628 §3.1 / RFC 6749 §5.2（invalid_client）/ #193");

                r.Target("client_id = 登録されていない値");
                r.Step("POST " + AuthorizePath + " に、登録されていない client_id を送る");

                JsonResponse res = await StartAsync(client, "00000000000000000000000000000000");

                r.VerifyEqual("invalid_client で拒否される", "invalid_client", res.Error);

                r.Verify("device_code を発行しない", res.KindOf("device_code") == JsonValueKind.Undefined,
                    "device_code を返さない",
                    res.KindOf("device_code") == JsonValueKind.Undefined ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }
    }
}
