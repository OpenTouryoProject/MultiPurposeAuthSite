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
//* クラス名        ：MalformedJwtTests
//* クラス日本語名  ：RT-241 JWT でない値で 500 にしない（#241）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/26  玄人 幸道         新規（#241）
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
    /// RT-241. JWT でない値を渡されても、処理されない例外にしない。
    /// </summary>
    /// <remarks>
    /// **公開鍵を引くには payload の `iss` が要る**ので、**署名検証の前に payload を読む**ことになる。
    /// そこに壊れた値を渡されると、以前は **HTTP 500**（JSON でない本文）になっていた。
    ///
    /// | 場所 | 以前の壊れ方 |
    /// |---|---|
    /// | `/ros`（`RegisterRequestObject`） | `Split('.')[1]` / Base64URL の復号 / null の `JObject` |
    /// | `client_assertion` の検証 | 同上 ＋ **`iss` が無いと辞書の参照で例外** |
    /// | 公開鍵の復号 | **未登録のクライアント**では null を復号して例外 |
    ///
    /// **`client_assertion` は、#238 / #239 で受け口が増えた**ので
    /// （`/token` の各グラント・`/par`・`/ciba_authz`・`/revoke`・`/introspect`）、
    /// **どの口からでも 500 に落とせる**状態だった。
    ///
    /// `RT-238.3` / `RT-239.4` は「**形は JWT で署名が壊れている**」場合を測っており、
    /// **JWT の形でないもの**はここで測る。
    /// </remarks>
    public class MalformedJwtTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public MalformedJwtTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>client_assertion として送るフォームを作る</summary>
        /// <param name="assertion">アサーションに見せる値</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> Form(string assertion)
        {
            return new Dictionary<string, string>()
            {
                { "token", "dummy-token" },
                { "client_assertion", assertion },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
            };
        }

        /// <summary>RT-241.1 /ros に JWT でない本文</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24101_rosにJWTでない本文を渡しても500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-241.1",
                    "/ros に JWT でない本文を渡しても、HTTP 400 で返す（500 にしない）",
                    "**処理されない例外は、JSON でない本文（開発モードでは例外の平文）を返す**ので、"
                    + "RP は何が起きたか読めない（#196 / #210 と同じ理由）。"
                    + "公開鍵を引くために**署名検証の前に payload を読む**必要があり、"
                    + "そこが外から来た文字列で壊れていた（#241）。",
                    "RFC 6749 §5.2 / #196 / #210 / #241");

                r.Target("POST /ros（本文は生の文字列）");

                r.Step("(1) `.` が無い文字列");

                JsonResponse noDot = await client.PostTextAsync("/ros", "not-a-jwt");

                r.VerifyEqual("HTTP 400", "400", ((int)noDot.StatusCode).ToString());

                r.Step("(2) `.` はあるが Base64URL でない文字列");

                JsonResponse badBase64 = await client.PostTextAsync("/ros", "aaa.bbb.ccc");

                r.VerifyEqual("HTTP 400", "400", ((int)badBase64.StatusCode).ToString());

                r.Step("(3) JSON がオブジェクトでない JWT");

                // payload が文字列（"abc"）の JWT。Base64URL としては正しい。
                JsonResponse notObject = await client.PostTextAsync(
                    "/ros", "eyJhbGciOiJSUzI1NiJ9.ImFiYyI.c2ln");

                r.VerifyEqual("HTTP 400", "400", ((int)notObject.StatusCode).ToString());

                r.Done();
            }
        }

        /// <summary>RT-241.2 client_assertion に JWT でない値</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24102_client_assertionにJWTでない値を渡しても500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-241.2",
                    "client_assertion が JWT でなければ、クライアント認証の失敗（401）で返す",
                    "**`client_assertion` は #238 / #239 で受け口が増えた**"
                    + "（`/token` の各グラント・`/par`・`/ciba_authz`・`/revoke`・`/introspect`）。"
                    + "**どの口からでも 500 に落とせる**状態だったので、"
                    + "**アサーション無しとして扱い**、認証失敗にする"
                    + "（`client_assertion_type` が誤りのときと同じ扱い。#238）。",
                    "RFC 7523 §2.2 / RFC 6749 §5.2 / #241");

                r.Target("/revoke と /introspect（どちらも同じ検証を通る）");

                r.Step("(1) `.` が無い文字列を client_assertion に入れる");

                JsonResponse revoke = await client.PostJsonAsync("/revoke", MalformedJwtTests.Form("not-a-jwt"));

                r.VerifyEqual("/revoke : HTTP 401", "401", ((int)revoke.StatusCode).ToString());
                r.VerifyEqual("/revoke : エラーは invalid_client",
                    "invalid_client", revoke.Error ?? "（無し）");

                JsonResponse introspect = await client.PostJsonAsync(
                    "/introspect", MalformedJwtTests.Form("not-a-jwt"));

                r.VerifyEqual("/introspect : HTTP 401", "401", ((int)introspect.StatusCode).ToString());
                r.VerifyEqual("/introspect : エラーは invalid_client",
                    "invalid_client", introspect.Error ?? "（無し）");

                r.Step("(2) トークン エンドポイント（refresh_token グラント）でも同じ");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", "dummy" },
                    { "client_assertion", "not-a-jwt" },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
                });

                r.VerifyEqual("/token : HTTP 401", "401", ((int)token.StatusCode).ToString());
                r.VerifyEqual("/token : エラーは invalid_client",
                    "invalid_client", token.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-241.3 iss の無い JWT、未登録の iss</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24103_issが無いか未登録でも500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-241.3",
                    "iss が無い・未登録のクライアントを指す client_assertion も、401 で返す",
                    "**公開鍵は `iss` で引く**ので、`iss` が無ければ引けない（以前は辞書の参照で例外）。"
                    + "**未登録のクライアントでは登録値が空**で、"
                    + "それを Base64URL として復号しようとして例外になっていた"
                    + "（**空かどうかを確かめる前に復号していた**）。",
                    "RFC 7523 §3 / #241");

                r.Target("形は JWT だが、iss が無い／未登録のもの");

                r.Step("(1) iss の無い JWT");

                string noIss = JwsSigner.SignRS256(client, new Dictionary<string, object>()
                {
                    { "sub", "dummy" },
                    { "aud", client.Target.BaseUrl + "/token" }
                });

                JsonResponse res1 = await client.PostJsonAsync("/introspect", MalformedJwtTests.Form(noIss));

                r.VerifyEqual("HTTP 401", "401", ((int)res1.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_client", "invalid_client", res1.Error ?? "（無し）");

                r.Step("(2) 未登録の client_id を iss にした JWT");

                string unknownIss = JwsSigner.SignRS256(client, new Dictionary<string, object>()
                {
                    { "iss", "00000000000000000000000000000000" },
                    { "sub", "00000000000000000000000000000000" },
                    { "aud", client.Target.BaseUrl + "/token" },
                    { "jti", Guid.NewGuid().ToString("N") }
                });

                JsonResponse res2 = await client.PostJsonAsync("/introspect", MalformedJwtTests.Form(unknownIss));

                r.VerifyEqual("HTTP 401", "401", ((int)res2.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_client", "invalid_client", res2.Error ?? "（無し）");

                r.Note("**登録の値が壊れている場合も同じ扱い**（運用の誤りだが、"
                    + "要求の側から区別できないので認証失敗にする）。");

                r.Done();
            }
        }
    }
}
