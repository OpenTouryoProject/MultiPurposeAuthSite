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
//* クラス名        ：CibaRequestTests
//* クラス日本語名  ：RT-233 CIBA の認証要求を request で直接受け取る（#233）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/24  玄人 幸道         新規（#233）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-233. CIBA の認証要求を、`request`（署名付き JWT）で直接受け取る。
    /// </summary>
    /// <remarks>
    /// **CIBA Core が定めているのは `request` を直接送る形**（§7.1.1）で、
    /// `request_uri` にあたる仕組みは無い（PAR は認可エンドポイント向けで、対象外）。
    /// これまでは `/ros` に預けて `request_uri` を渡す独自の形だけを受け付けていたため、
    /// **標準の CIBA クライアントからは繋がらなかった。**
    ///
    /// `request_uri` の受け口は後方互換のため残してある（EX-8 が通る）。
    /// ここでは **`request` の経路**と、**両方あれば `request` が優先されること**を見る。
    ///
    /// **EX-8（CibaTests）と同じコレクションに入れる。** どちらも既定の利用者に端末（device_token）を
    /// 登録してプッシュ通知を受けるので、並行して動くと端末の登録を奪い合う。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class CibaRequestTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaRequestTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CIBA の認証要求（署名付き JWT）を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="bindingMessage">binding_message（認証デバイスに表示される）</param>
        /// <returns>JWS</returns>
        private static Task<string> CreateRequestAsync(
            IdPClient client, ClientRegistration reg, string bindingMessage)
        {
            return RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId, new Dictionary<string, object>()
            {
                { "login_hint", TestEnv.TestUserName },
                { "binding_message", bindingMessage }
            });
        }

        /// <summary>RT-233.1 request を直接送って、承認までを通す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23301_requestを直接送ってCIBAが成立する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-233.1",
                    "/ciba_authz に request（署名付き JWT）を直接送ると、CIBA が成立する",
                    "**CIBA Core が定めている送り方**（§7.1.1 : 署名した認証要求を request パラメタで POST）。"
                    + "以前は /ros に預けた request_uri しか受け付けておらず、これは CIBA Core に無い独自拡張だった。"
                    + "**標準の CIBA クライアントが繋がるかどうか**を、ここで見る。",
                    "CIBA Core §7.1.1 / #233");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                string bindingMessage = "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                r.Target("client_name=" + KnownClients.TestClient4 + " / login_hint=" + TestEnv.TestUserName
                    + "（/ros を経由しない。認証デバイスとプッシュ通知は、テストで置き換える）");

                r.Step("(1) 利用者 : 認証デバイスを登録する（POST /SetDeviceToken）");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : request に署名付き JWT を入れて POST /ciba_authz");

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", await CibaRequestTests.CreateRequestAsync(client, reg, bindingMessage) }
                });

                string authReqId = start.String("auth_req_id");

                r.VerifyEqual("認証リクエスト : HTTP 200", "200", ((int)start.StatusCode).ToString());

                r.Verify("auth_req_id が返る", !string.IsNullOrEmpty(authReqId),
                    "auth_req_id あり", string.IsNullOrEmpty(authReqId) ? start.ToString() : "あり（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること");

                r.Step("(3) サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）");

                FcmOutbox.Message push = await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                string shown;
                push.Data.TryGetValue("binding_message", out shown);
                r.VerifyEqual("request に入れた binding_message が載る", bindingMessage, shown);

                r.Step("(4) 利用者 : 認証デバイスで「許可」を押す（POST /ciba_result、result=true）");

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                r.VerifyEqual("返答 : HTTP 200", "200", ((int)answer.StatusCode).ToString());

                r.Step("(5) クライアント : ポーリングしてトークンを取る");

                JsonResponse granted = await CibaTests.PollAsync(client, reg, authReqId);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(granted.AccessToken),
                    "access_token あり",
                    granted.AccessToken == null ? "なし（" + granted.ToString() + "）" : "あり（値は伏せる）");

                r.Note("**/ros を一度も呼んでいない。** 認証要求は request で直接渡している。");

                r.Done();
            }
        }

        /// <summary>RT-233.2 request と request_uri の両方があれば request を使う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23302_両方あればrequestを優先する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-233.2",
                    "request と request_uri の両方を送ると、request が使われる",
                    "**後方互換のため request_uri の受け口を残す**ので、両方が届き得る。"
                    + "そのとき**どちらが効くかを決めておく**（仕様にある request を優先）。"
                    + "決めていないと、実装によって結果が変わる。",
                    "CIBA Core §7.1.1 / #233");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                string viaRequest = "E2E-req-" + Guid.NewGuid().ToString("N").Substring(0, 6);
                string viaRequestUri = "E2E-uri-" + Guid.NewGuid().ToString("N").Substring(0, 6);

                r.Target("client_name=" + KnownClients.TestClient4
                    + " / request と request_uri で binding_message を変え、どちらが届くかを見る");

                r.Step("(1) 利用者 : 認証デバイスを登録する");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) /ros に別の binding_message の要求を預けて、request_uri を得る");

                string requestUri = await RequestObjectBuilder.RegisterAsync(client,
                    await CibaRequestTests.CreateRequestAsync(client, reg, viaRequestUri));

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: /ros が CIBA の要求を受け付けること");

                r.Step("(3) クライアント : request と request_uri の両方を入れて POST /ciba_authz");

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", await CibaRequestTests.CreateRequestAsync(client, reg, viaRequest) },
                    { "request_uri", requestUri }
                });

                string authReqId = start.String("auth_req_id");

                r.VerifyEqual("認証リクエスト : HTTP 200", "200", ((int)start.StatusCode).ToString());

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること");

                r.Step("(4) プッシュ通知の binding_message を見る");

                FcmOutbox.Message push = await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                string shown;
                push.Data.TryGetValue("binding_message", out shown);

                r.VerifyEqual("request 側の binding_message が届く（request_uri 側ではない）", viaRequest, shown);

                r.Done();
            }
        }

        /// <summary>RT-233.3 署名が壊れている request は断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23303_署名が壊れたrequestを断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-233.3",
                    "署名が壊れている request は、認証要求として受け付けない",
                    "**request は署名だけがクライアントの証明**である（/ciba_authz は HTTP のクライアント認証を行わない）。"
                    + "署名を確かめずに中身を信じると、誰でも他人のクライアントを名乗れる。"
                    + "**利用者に通知を送る前に断る**こと。",
                    "CIBA Core §7.1.1 / §13 / #233");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("client_name=" + KnownClients.TestClient4 + "（署名の最後の 1 文字を書き換えた request）");

                r.Step("(1) 正しい request を作り、署名の部分だけを書き換える");

                string jws = await CibaRequestTests.CreateRequestAsync(client, reg, "E2E-broken");
                string[] parts = jws.Split('.');
                string signature = parts[2];

                // **先頭の 1 文字を変える**（Base64URL の範囲のまま、値だけ変える）。
                //   末尾を変えると、署名が変わらないことがある。ES256 の署名は 64 バイト＝ 512 ビットで、
                //   Base64URL の 86 文字には 516 ビット入る。**最後の 1 文字は下位 4 ビットが余りなので、
                //   そこだけ変えても復号すると同じ 64 バイトになる**（実際、それで検証を通ってしまった）。
                parts[2] = (signature.StartsWith("A") ? "B" : "A") + signature.Substring(1);

                r.Step("(2) POST /ciba_authz");

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", string.Join(".", parts) }
                });

                string authReqId = start.String("auth_req_id");

                r.Verify("auth_req_id を返さない（利用者へ通知しない）",
                    string.IsNullOrEmpty(authReqId),
                    "返さない",
                    string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

                r.VerifyEqual("HTTP 400", "400", ((int)start.StatusCode).ToString());

                r.VerifyEqual("エラーは invalid_request", "invalid_request", start.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-233.4 request も request_uri も無ければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23304_requestもrequest_uriも無ければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-233.4",
                    "request も request_uri も無い認証要求は、invalid_request で断る",
                    "**受け口を 2 つにしたので、「どちらも無い」が新しい入口になる。**"
                    + "エラーの形（400 と invalid_request）が変わっていないことを見る。",
                    "CIBA Core §13 / #233");

                r.Target("空のフォームで POST /ciba_authz");

                r.Step("(1) POST /ciba_authz（scope だけを入れ、request も request_uri も入れない）");

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "scope", "openid" }
                });

                r.VerifyEqual("HTTP 400", "400", ((int)start.StatusCode).ToString());

                r.VerifyEqual("エラーは invalid_request", "invalid_request", start.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-234.1 aud が Issuer Identifier でなければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23401_audがissuerでなければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-234.1",
                    "aud が OP の Issuer Identifier でない認証要求は、invalid_request で断る",
                    "**CIBA Core §7.1.1 は、aud に OP の Issuer Identifier を入れることを MUST としている。**"
                    + "見ないと、**別の認可サーバ宛てに作られた要求**を、"
                    + "同じクライアントの鍵が登録されているこの IdP でも受け付けてしまう。"
                    + "以前は exp / nbf だけを見ており、aud は取り出してもいなかった。",
                    "CIBA Core §7.1.1 / §13 / #234 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Step("(1) Discovery から issuer を読む（テストに値を書かない）");

                string issuer = await client.IssuerAsync();

                r.Verify("issuer が広告されている", !string.IsNullOrEmpty(issuer),
                    "issuer あり", issuer ?? "（無し）");

                r.Observe("issuer", issuer ?? "（無し）",
                    "**待ち受けている URL とは別の値**（設定キー IssuerId）。aud はこちらでなければならない。");

                r.Step("(2) aud に別の認可サーバの識別子を入れた request を送る");

                string otherAud = "https://another-op.example.invalid";

                string jws = await RequestObjectBuilder.CreateCibaAsync(
                    client, reg.ClientId, new Dictionary<string, object>()
                    {
                        { "login_hint", TestEnv.TestUserName },
                        { "binding_message", "E2E-aud" },
                        { "aud", otherAud }
                    });

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", jws }
                });

                string authReqId = start.String("auth_req_id");

                r.Verify("auth_req_id を返さない（利用者へ通知しない）",
                    string.IsNullOrEmpty(authReqId),
                    "返さない",
                    string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

                r.VerifyEqual("HTTP 400", "400", ((int)start.StatusCode).ToString());

                r.VerifyEqual("エラーは invalid_request", "invalid_request", start.Error ?? "（無し）");

                r.Note("**署名は正しい。** 正しい鍵で署名されていても、宛先が違えば受け付けない。");

                r.Done();
            }
        }

        /// <summary>RT-234.2 aud が無い認証要求を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23402_audが無ければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-234.2",
                    "aud が入っていない認証要求は、invalid_request で断る",
                    "**CIBA Core §7.1.1 の必須クレーム**（aud / iss / exp / iat / nbf / jti）の 1 つ。"
                    + "欠落は、Open棟梁 が返す server_error ではなく invalid_request に読み替える（#196 と同じ扱い）。",
                    "CIBA Core §7.1.1 / §13 / #234 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("client_name=" + KnownClients.TestClient4 + "（aud を外した request）");

                r.Step("(1) aud を入れずに request を作って送る");

                string jws = await RequestObjectBuilder.CreateCibaAsync(
                    client, reg.ClientId, new Dictionary<string, object>()
                    {
                        { "login_hint", TestEnv.TestUserName },
                        { "binding_message", "E2E-no-aud" },
                        { RequestObjectBuilder.RemoveClaim, "aud" }
                    });

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", jws }
                });

                r.VerifyEqual("HTTP 400", "400", ((int)start.StatusCode).ToString());

                r.VerifyEqual("エラーは invalid_request", "invalid_request", start.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-234.3 同じ jti の認証要求を二度は受け付けない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23403_同じjtiの要求を二度は受け付けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-234.3",
                    "同じ認証要求（同じ jti）を送り直すと、invalid_request で断る",
                    "**CIBA Core §7.1.1 は jti を「署名した認証要求の一意な識別子」としている。**"
                    + "見ないと、**同じ要求 JWT を exp まで何度でも送り直せる**。"
                    + "`/ciba_authz` はクライアント認証をしないので（段階 3 で入れる）、"
                    + "要求を手に入れた者が、利用者に通知を繰り返し送れてしまう。"
                    + "`request_uri` の経路も同じで、`/ros` に預け直せば新しい参照を取れた。",
                    "CIBA Core §7.1.1 / §13 / #234 の段階 2");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("client_name=" + KnownClients.TestClient4
                    + "（既定の login_hint ＝ 存在しない利用者。**通知を出さずに jti の消費だけを見る**）");

                r.Step("(1) 認証要求を 1 回送る");

                // 既定の login_hint は存在しない利用者なので、検証は通るが利用者が見つからない。
                // **jti は、利用者を探す前の検証で消費される。**
                string jws = await RequestObjectBuilder.CreateCibaAsync(
                    client, reg.ClientId, new Dictionary<string, object>());

                JsonResponse first = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", jws }
                });

                r.VerifyEqual("1 回目 : エラーは unknown_user_id（検証は通っている）",
                    "unknown_user_id", first.Error ?? "（無し）");

                r.Step("(2) まったく同じ要求を、もう一度送る");

                JsonResponse second = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", jws }
                });

                r.VerifyEqual("2 回目 : HTTP 400", "400", ((int)second.StatusCode).ToString());

                r.VerifyEqual("2 回目 : エラーは invalid_request（jti は使用済み）",
                    "invalid_request", second.Error ?? "（無し）");

                r.Verify("2 回目 : エラーが変わる（1 回目と同じ応答ではない）",
                    first.Error != second.Error,
                    "1 回目と違うエラー",
                    "1 回目 = " + (first.Error ?? "（無し）") + " / 2 回目 = " + (second.Error ?? "（無し）"));

                r.Note("**記録は Request Object のストアを使い回している**（接頭辞付きのキー）。"
                    + "#188 で入れた有効期限と掃除がそのまま効くので、新しい表を作っていない。");

                r.Done();
            }
        }
    }
}
