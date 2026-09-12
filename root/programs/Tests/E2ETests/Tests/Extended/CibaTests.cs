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
//* クラス名        ：CibaTests
//* クラス日本語名  ：EX-8 CIBA（認証デバイスとプッシュ通知はテストで置き換える）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/12  玄人 幸道         新規（プッシュ通知を送信箱で受け、認証デバイスの返答をテストが送る）（#196）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-8. CIBA（OpenID Connect Client-Initiated Backchannel Authentication）。
    ///
    /// クライアントが、ユーザの**別の端末（認証デバイス）**に承認を求めてトークンを得る。
    ///
    ///   ユーザ       : 認証デバイスでサインインし、端末を登録する（POST /SetDeviceToken）
    ///   クライアント : 署名した認証リクエストを /ros に登録し、POST /ciba_authz で始める
    ///   サーバ       : 認証デバイスへプッシュ通知（FCM）を送る
    ///   ユーザ       : 認証デバイスで「許可 / 拒否」を押す（POST /ciba_result）
    ///   クライアント : POST /token（grant_type=urn:openid:params:grant-type:ciba）をポーリングする
    ///
    /// **認証デバイス（authentication_device）とプッシュ通知は、テストで置き換える。**
    /// サーバは FCM に送らず送信箱（FcmOutbox）にファイルとして書き（test.ps1 -Launch のときだけ）、
    /// テストはそれを受け取って、認証デバイスと同じ HTTP 要求（/SetDeviceToken・/ciba_result）を送る。
    ///
    /// /ciba_result は、メモリのストアでは auth_req_id を見ずに、保留中の全ての要求へ結果を書き込む。
    /// そのため、返答を送るテストはこのクラスに集めて、順に流す（xUnit は、クラスの中を順に実行する）。
    /// </summary>
    public class CibaTests : TargetTestBase
    {
        /// <summary>grant_type</summary>
        private const string GrantType = "urn:openid:params:grant-type:ciba";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient（サインイン済み）</param>
        /// <returns>ユーザのアクセス トークンと、登録したデバイス・トークン</returns>
        private static async Task<(string AccessToken, string DeviceToken)> RegisterDeviceAsync(
            TestReport r, IdPClient client)
        {
            // 認証デバイスは、サインインして得たユーザのトークンで、自分の宛先（device_token）を登録する。
            JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

            Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: ユーザの access_token が返ること");

            string deviceToken = "e2e-device-" + Guid.NewGuid().ToString("N");
            JsonResponse res = await client.SetDeviceTokenAsync(token.AccessToken, deviceToken);

            r.VerifyEqual("端末の登録 : HTTP 200", "200", ((int)res.StatusCode).ToString());
            r.VerifyEqual("端末の登録 : 本文は OK", "OK", res.Text);

            return (token.AccessToken, deviceToken);
        }

        /// <summary>クライアント : CIBA の認証リクエストを送る（/ros に登録 → POST /ciba_authz）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="bindingMessage">binding_message（認証デバイスに表示される）</param>
        /// <returns>JsonResponse</returns>
        private static async Task<JsonResponse> StartAsync(
            IdPClient client, ClientRegistration reg, string bindingMessage)
        {
            string requestUri = await RequestObjectBuilder.RegisterAsync(client,
                RequestObjectBuilder.CreateCiba(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "login_hint", TestEnv.TestUserName },
                    { "binding_message", bindingMessage }
                }));

            Assert.False(string.IsNullOrEmpty(requestUri), "前提: /ros が CIBA の要求を受け付けること");

            return await client.CibaAuthorizeAsync(new Dictionary<string, string>()
            {
                { "request_uri", requestUri }
            });
        }

        /// <summary>クライアント : トークンを要求する（ポーリングの 1 回分）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="authReqId">auth_req_id</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> PollAsync(IdPClient client, ClientRegistration reg, string authReqId)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", GrantType },
                { "auth_req_id", authReqId },
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret }
            });
        }

        /// <summary>サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="authReqId">auth_req_id</param>
        /// <param name="deviceToken">登録したデバイス・トークン</param>
        /// <returns>プッシュ通知</returns>
        private static async Task<FcmOutbox.Message> ReceivePushAsync(
            TestReport r, IdPClient client, string authReqId, string deviceToken)
        {
            FcmOutbox.Message push = await FcmOutbox.WaitForAsync(
                client.Target, "auth_req_id", authReqId, TimeSpan.FromSeconds(10));

            r.Verify("プッシュ通知が送られる（auth_req_id を載せて）", push != null,
                "送信箱に届く", push != null ? "届いた" : "**届かない**");

            Assert.True(push != null, "前提: プッシュ通知が送信箱に届くこと");

            r.Verify("宛先は、登録した端末", push.Token == deviceToken,
                "登録した device_token", push.Token == deviceToken ? "一致" : "**別の宛先**");

            return push;
        }

        /// <summary>EX-8.1 許可</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0801_認証デバイスで許可するとクライアントはトークンを取得できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("EX-8.1",
                    "認証デバイスで許可すると、クライアントはトークンを取得できる",
                    "CIBA の本筋。ユーザは、クライアントの画面ではなく**手元の認証デバイス**で承認する。"
                    + "承認までは authorization_pending を返し、**承認した後にだけトークンを出す**こと。"
                    + "プッシュ通知は、登録した端末に、要求の binding_message を載せて届くこと。",
                    "CIBA Core §7（認証リクエスト）/ §10（ポーリング）/ §11（authorization_pending）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                string bindingMessage = "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                r.Target("client_name=" + KnownClients.TestClient4 + " / login_hint=" + TestEnv.TestUserName
                    + "（認証デバイスとプッシュ通知は、テストで置き換える）");

                r.Step("(1) ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）");

                (string AccessToken, string DeviceToken) device = await RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : CIBA の認証リクエストを送る（/ros に登録 → POST /ciba_authz）");

                JsonResponse start = await StartAsync(client, reg, bindingMessage);
                string authReqId = start.String("auth_req_id");

                r.VerifyEqual("認証リクエスト : HTTP 200", "200", ((int)start.StatusCode).ToString());

                r.Verify("auth_req_id が返る", !string.IsNullOrEmpty(authReqId),
                    "auth_req_id あり", string.IsNullOrEmpty(authReqId) ? start.ToString() : "あり（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること");

                r.Step("(3) サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）");

                FcmOutbox.Message push = await ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                string shown;
                push.Data.TryGetValue("binding_message", out shown);
                r.VerifyEqual("binding_message が載る", bindingMessage, shown);

                r.Step("(4) クライアント : 承認の前にポーリングする");

                JsonResponse pending = await PollAsync(client, reg, authReqId);

                r.VerifyEqual("authorization_pending が返る", "authorization_pending", pending.Error);

                r.Verify("トークンを出さない", string.IsNullOrEmpty(pending.AccessToken),
                    "access_token を返さない", pending.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Step("(5) ユーザ : 認証デバイスで「許可」を押す（POST /ciba_result、result=true）");

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                r.VerifyEqual("返答 : HTTP 200", "200", ((int)answer.StatusCode).ToString());
                r.VerifyEqual("返答 : 本文は OK", "OK", answer.Text);

                r.Step("(6) クライアント : もう一度ポーリングする");

                JsonResponse granted = await PollAsync(client, reg, authReqId);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(granted.AccessToken),
                    "access_token あり",
                    granted.AccessToken == null ? "なし（" + granted.ToString() + "）" : "あり（値は伏せる）");

                r.Observe("id_token", string.IsNullOrEmpty(granted.IdToken) ? "返らない" : "返る",
                    "CIBA Core は、成功のトークン応答に id_token を含めるとしている。");

                r.Done();
            }
        }

        /// <summary>EX-8.2 拒否</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0802_認証デバイスで拒否するとaccess_denied(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("EX-8.2",
                    "認証デバイスで拒否すると、クライアントには access_denied を返す",
                    "ユーザが身に覚えのない要求を**手元で断れる**ことが、CIBA の安全性の要。"
                    + "拒否した要求で、トークンが出てはならない。",
                    "CIBA Core §11（access_denied）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("client_name=" + KnownClients.TestClient4 + " / login_hint=" + TestEnv.TestUserName
                    + "（認証デバイスとプッシュ通知は、テストで置き換える）");

                r.Step("(1) ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）");

                (string AccessToken, string DeviceToken) device = await RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : CIBA の認証リクエストを送る");

                JsonResponse start = await StartAsync(client, reg, "E2E-deny");
                string authReqId = start.String("auth_req_id");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること（" + start.ToString() + "）");

                r.Step("(3) サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）");

                await ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                r.Step("(4) ユーザ : 認証デバイスで「拒否」を押す（POST /ciba_result、result=false）");

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "false");

                r.VerifyEqual("返答 : HTTP 200", "200", ((int)answer.StatusCode).ToString());
                r.VerifyEqual("返答 : 本文は OK", "OK", answer.Text);

                r.Step("(5) クライアント : ポーリングする");

                JsonResponse denied = await PollAsync(client, reg, authReqId);

                r.VerifyEqual("access_denied が返る", "access_denied", denied.Error);

                r.Verify("トークンを出さない", string.IsNullOrEmpty(denied.AccessToken),
                    "access_token を返さない", denied.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }
    }
}
