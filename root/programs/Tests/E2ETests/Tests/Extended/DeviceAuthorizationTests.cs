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
//*  2026/09/11  玄人 幸道         EX-4.5 の Skip を解除し、EX-4.7 を追加（#199）
//*  2026/09/11  玄人 幸道         /device_authz の要求を IdPClient.DeviceAuthorizationAsync へ移す
//*  2026/09/28  玄人 幸道         自己テストの Device AuthZ ボタン（RT-246.3）を追加（#246 の 3-a）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
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
            return client.DeviceAuthorizationAsync(new Dictionary<string, string>()
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
                r.Step("POST /device_authz に client_id と scope を送る");

                JsonResponse res = await StartAsync(client, reg.ClientId);

                foreach (string name in new string[] { "device_code", "user_code", "verification_uri", "expires_in" })
                {
                    bool has = res.KindOf(name) != JsonValueKind.Undefined;

                    r.Verify(name + " がある", has, "あり", has ? "あり" : "なし（" + res.ToString() + "）");
                }

                // **絶対 URI であること**（RFC 8628 3.2）。相対だと、機器は開く URL を組み立てられない。
                //   自己テストの画面は、これをそのままリンクにする（足すと二重になり 404。#246）。
                string verificationUri = res.String("verification_uri") ?? "";

                bool absolute = verificationUri.StartsWith("https://")
                    || verificationUri.StartsWith("http://");

                r.Verify("verification_uri は絶対 URI である", absolute,
                    "http(s):// で始まる", absolute ? verificationUri : "**" + verificationUri + "**");

                r.Observe("verification_uri", string.IsNullOrEmpty(verificationUri) ? "なし" : verificationUri,
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
                r.Step("(1) 機器 : POST /device_authz で device_code を得る");

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
                r.Step("(1) 機器 : POST /device_authz で device_code と user_code を得る");
                r.Step("(2) ユーザ : サインインした端末で /device_verify を開き、user_code を入力して許可する");
                r.Step("(3) 機器 : grant_type=device_code でトークンを要求する");
                r.Note("このテストでは 1 つの HTTP クライアントが両方の役を務める。"
                    + "機器側の要求（/device_authz と /token）は Cookie に依存しないので、"
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
                    // **sub の値では判定しない**（#151 の段階 4。sub は利用者名から利用者 ID になった）。
                    //   **このトークンの payload に利用者の属性は入っていない**
                    //   （code からの発行は「カスタムクレームは含めない」。CmnAccessToken）。
                    //   そこで **/userinfo に引かせる。**
                    //   **sub から承認した利用者に戻れることまで確かめられる**ので、
                    //   以前の「sub が利用者名と一致するか」より強い。
                    JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                    r.VerifyEqual("承認したユーザのトークンである（/userinfo の email）",
                        TestEnv.TestUserEmail, userinfo.String("email") ?? "（無し）");

                    r.VerifyEqual("/userinfo の sub が、トークンの sub と一致する",
                        Jwt.String(Jwt.Payload(token.AccessToken), "sub"),
                        userinfo.String("sub") ?? "（無し）");
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
        [SkippableTheory]
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

                bool rfcValue = second.Error == "invalid_grant" || second.Error == "expired_token";

                r.Verify("2 回目の error が RFC の値である", rfcValue,
                    "invalid_grant（RFC 6749 §5.2）または expired_token（RFC 8628 §3.5）",
                    second.Error ?? "なし");

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
                r.Step("POST /device_authz に、登録されていない client_id を送る");

                JsonResponse res = await StartAsync(client, "00000000000000000000000000000000");

                r.VerifyEqual("invalid_client で拒否される", "invalid_client", res.Error);

                r.Verify("device_code を発行しない", res.KindOf("device_code") == JsonValueKind.Undefined,
                    "device_code を返さない",
                    res.KindOf("device_code") == JsonValueKind.Undefined ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>EX-4.7 不正な device_code</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0407_不正なdevice_codeは500にならずエラーで返る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-4.7",
                    "発行していない・送らない device_code は、HTTP 500 にせずエラーとして返す",
                    "機器が送ってくる device_code は、信用できない入力である。"
                    + "**どんな値でも、サーバが落ちずに、機器が解釈できるエラーを返す**こと。"
                    + "（EX-4.5 は使用済みの値。こちらは最初から存在しない値と、値が無い場合）",
                    "RFC 8628 §3.4（device_code は REQUIRED）/ RFC 6749 §5.2（invalid_grant / invalid_request）/ #199");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3);
                r.Step("(1) 発行していない device_code でトークンを要求する");

                JsonResponse unknown = await PollAsync(client, reg.ClientId, "00000000000000000000000000000000");

                r.Verify("発行していない値 : JSON のエラー応答を返す（HTTP 500 にならない）",
                    unknown.IsJson && !string.IsNullOrEmpty(unknown.Error),
                    "error を含む JSON", unknown.ToString());

                r.VerifyEqual("発行していない値 : invalid_grant で拒否される", "invalid_grant", unknown.Error);

                r.Step("(2) device_code を付けずにトークンを要求する");

                JsonResponse missing = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", GrantType },
                    { "client_id", reg.ClientId }
                });

                r.Verify("値が無い : JSON のエラー応答を返す（HTTP 500 にならない）",
                    missing.IsJson && !string.IsNullOrEmpty(missing.Error),
                    "error を含む JSON", missing.ToString());

                r.VerifyEqual("値が無い : invalid_request で拒否される", "invalid_request", missing.Error);

                r.Done();
            }
        }

        /// <summary>RT-246.3 自己テストの Device AuthZ ボタン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24603_自己テストのDeviceAuthZボタンが判定を画面に出す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-246.3",
                    "自己テストの Device AuthZ ボタンが、ポーリングの判定を画面に出す",
                    "**以前は `?ret=OK_NORMAL_END` という URL に移るだけだった**（CIBA と同じ形。#246 の 3-a）。"
                    + "`OK_` が接頭辞なので可否が読めず、ポーリングの実値も出ていなかった。"
                    + "**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。"
                    + "**承認まで通す経路を測れるのは、この流れだけである**"
                    + "（CIBA は実機の認証デバイスが要るため、`RT-246.2` は異常系しか測れない）。",
                    "RFC 8628 §3.4 / §3.5 / #246 の 3-a / 3-b");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.DeviceAuthZGrant（device）");

                // **サイトがクライアント証明書を要求している間は、この通しを始められない。**
                //   その状態では、**アプリ自身の内部呼び出し（Helper の HttpClient）も証明書を提示する**
                //   （SpRp_ClientCertPfxFilePath）。/device_authz は証明書を提示されたクライアントを
                //   コンフィデンシャル扱いにするので、**公開クライアント（TestClient3）が 401 になる。**
                //   **E2E が mTLS（FA-6）のために要求させているだけで、製品の欠陥ではない**（#226）。
                Skip.If(Environment.GetEnvironmentVariable(
                    client.Target.Key == TestEnv.NetFxKey ? "MPAS_NETFX_MTLS" : "MPAS_CORE_MTLS") == "true",
                    client.Target.DisplayName + " はクライアント証明書を要求している（#226）。"
                    + "その状態ではアプリ自身の内部呼び出しも証明書を提示するため、"
                    + "公開クライアントの /device_authz が 401（invalid_client）になる。");

                r.Step("(1) 機器 : ボタンを押して device_code と user_code を得る");

                HttpResponseMessage started = await client.StartSelfTestAsync(
                    "DeviceAuthZGrant", "device");

                r.VerifyEqual("HTTP 200（DeviceAuthZResponse 画面）",
                    "200", ((int)started.StatusCode).ToString());

                string screen = System.Net.WebUtility.HtmlDecode(
                    await started.Content.ReadAsStringAsync());

                Match userCode = Regex.Match(screen, "UserCode : (?<code>[^< ]+)");

                r.Verify("user_code が画面に出る", userCode.Success,
                    "出る", userCode.Success ? "出ている（値は伏せる）" : "**出ていない**");

                Assert.True(userCode.Success, "前提: user_code が画面に出ること");

                bool hasInterval = Regex.IsMatch(screen,
                    "name=\"interval\"[^>]*value=\"[0-9]+\"");

                r.Verify("interval を hidden で持ち回す（RFC 8628 §3.5）", hasInterval,
                    "hidden にある", hasInterval ? "ある" : "**無い**");

                // **承認の画面（/device_verify）へのリンクが開けること。**
                //   応答の verification_uri は絶対 URI なので、画面が RootURI を足すと二重になり
                //   **404 になって、承認の画面に行けなかった**（#246）。
                Match link = Regex.Match(screen, "href=\"(?<url>[^\"]*device_verify[^\"]*)\"");

                r.Verify("承認の画面へのリンクがある", link.Success,
                    "ある", link.Success ? link.Groups["url"].Value : "**無い**");

                if (link.Success)
                {
                    HttpResponseMessage opened = await client.GetAsync(link.Groups["url"].Value);

                    r.VerifyEqual("そのリンクが開く（HTTP 200）",
                        "200", ((int)opened.StatusCode).ToString());
                }

                r.Step("(2) 利用者 : 別の端末で user_code を入力して許可する");

                bool accepted = await client.SubmitDeviceUserCodeAsync(
                    userCode.Groups["code"].Value, true);

                r.Verify("検証画面が承認を受け付ける", accepted,
                    "受け付ける", accepted ? "受け付けた" : "**受け付けなかった**");

                r.Step("(3) 機器 : [Start polling.] を押して、結果の画面を確かめる");

                HttpResponseMessage polled = await client.SubmitDeviceAuthZPollingAsync(screen);

                r.VerifyEqual("HTTP 200（結果の画面）", "200", ((int)polled.StatusCode).ToString());

                // **net10.0 版の Razor は非 ASCII を数値文字参照で出す**ので、戻してから判定する。
                string html = System.Net.WebUtility.HtmlDecode(
                    await polled.Content.ReadAsStringAsync());

                bool notError = !html.Contains("エラーが発生しました");

                r.Verify("エラー画面ではない", notError,
                    "結果の画面", notError ? "結果の画面" : "**エラー画面**");

                Assert.True(notError, "前提: 結果の画面が開くこと（Razor は実行時コンパイル）");

                bool normal = html.Contains("NORMAL_END") && !html.Contains("ABNORMAL_END");

                r.Verify("判定は NORMAL_END（承認済みなので通る）", normal,
                    "NORMAL_END",
                    normal ? "NORMAL_END"
                           : (html.Contains("ABNORMAL_END") ? "**ABNORMAL_END**" : "**判定が出ていない**"));

                r.Verify("`OK_` の接頭辞は付かない", !html.Contains("OK_NORMAL_END"),
                    "付かない", html.Contains("OK_NORMAL_END") ? "**付いている**" : "付いていない");

                bool hasToken = Regex.IsMatch(html, "\"access_token\"");

                r.Verify("トークンの応答が画面に出る", hasToken,
                    "access_token を含む応答が出る（値は伏せる）",
                    hasToken ? "出ている" : "**出ていない**");

                Match count = Regex.Match(html, "秒 × (?<n>[0-9]+) 回");

                r.Verify("ポーリングの回数が画面に出る", count.Success,
                    "回数が出る", count.Success ? count.Groups["n"].Value + " 回" : "**出ていない**");

                r.Note("**承認済みなので 1 回で終わる。** 承認しなければ interval（既定 5 秒）ごとに"
                    + "問い合わせ、上限（60 秒）で打ち切って ABNORMAL_END になる（#246 の 3-b）。"
                    + "以前は `ExponentialBackoff(10, 5)` で、**間隔がサーバの interval と無関係**だった。");

                r.Done();
            }
        }
    }
}
