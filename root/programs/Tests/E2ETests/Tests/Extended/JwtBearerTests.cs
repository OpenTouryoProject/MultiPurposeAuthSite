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
//* クラス名        ：JwtBearerTests
//* クラス日本語名  ：EX-7 JWT Bearer グラント（RFC 7523）
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
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-7. JWT Bearer グラント（RFC 7523 §2.1）。
    ///
    /// クライアントが自分の秘密鍵で署名した JWT（assertion）を示して、トークンを得る。
    /// サーバは、登録済みの公開鍵（jwk_rsa_publickey）で署名を確かめる。
    ///
    /// assertion は JwtBearerAssertion で作る（実装側のコードは使わない）。
    /// </summary>
    public class JwtBearerTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public JwtBearerTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>assertion を示してトークンを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="assertion">assertion</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> RequestAsync(IdPClient client, string assertion)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", JwtBearerAssertion.GrantType },
                { "assertion", assertion }
            });
        }

        /// <summary>EX-7.1 正常系</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0701_署名したassertionでトークンを取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-7.1",
                    "クライアントが署名した JWT（assertion）で、トークンを取得できる",
                    "パスワードやシークレットを送らずに、**秘密鍵による署名**で自分を証明してトークンを得る。"
                    + "サーバは、登録済みの公開鍵で署名を確かめる。",
                    "RFC 7523 §2.1（grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer）/ §3（JWT の要件）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + "（jwk_rsa_publickey 登録済み）/ 署名鍵は SpRp_RsaPfxFilePath");
                r.Step("(1) iss=sub=client_id、aud=トークン エンドポイント、exp=5 分後 の JWT を RS256 で署名する");
                r.Step("(2) POST /token に grant_type と assertion を送る");

                string assertion = JwtBearerAssertion.Create(client, reg.ClientId);

                JsonResponse token = await RequestAsync(client, assertion);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(token.AccessToken))
                {
                    r.Observe("access_token の sub",
                        Jwt.String(Jwt.Payload(token.AccessToken), "sub") ?? "なし",
                        "ユーザの文脈を持たないので、クライアント自身を指すのが自然。");
                }

                r.Step("(3) 同じ assertion を、もう一度送る");

                JsonResponse again = await RequestAsync(client, assertion);

                r.Observe("同じ assertion の再利用",
                    !string.IsNullOrEmpty(again.AccessToken)
                        ? "受け付けた"
                        : "拒否した（error=" + (again.Error ?? "なし") + "）",
                    "jti による再利用の防止は任意（RFC 7523 §3 (7) : MAY）。");

                r.Note("この実装は scope を assertion の中から読む。"
                    + "RFC 7523 §2.1 では、scope はトークン要求のパラメタである。");

                r.Done();
            }
        }

        /// <summary>EX-7.2 aud の不一致</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0702_audが違うassertionは拒否される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-7.2",
                    "aud が認可サーバを指していない assertion は拒否される",
                    "**他のサーバ向けに作られた assertion の流用**を防ぐ。"
                    + "aud が自分（トークン エンドポイント）でなければ、受け付けてはならない。",
                    "RFC 7523 §3 (3)（aud に自分が含まれなければ拒否。MUST）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("aud=https://attacker.example.com/token の assertion を送る（署名は正しい）");

                string assertion = JwtBearerAssertion.Create(client, reg.ClientId,
                    new Dictionary<string, object>() { { "aud", "https://attacker.example.com/token" } });

                JsonResponse token = await RequestAsync(client, assertion);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Observe("error", token.Error ?? "なし", "RFC 7523 §3.1 は invalid_grant としている。");

                r.Done();
            }
        }

        /// <summary>EX-7.3 署名の改ざん</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0703_署名が正しくないassertionは拒否される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-7.3",
                    "署名が正しくない assertion（改ざん / alg=none）は拒否される",
                    "署名が合わない JWT を受け付けるなら、**誰でも任意のクライアントを名乗れる。**",
                    "RFC 7523 §3（署名または MAC が必須。検証できなければ拒否）/ RFC 8725 §3.1（alg=none）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("(1) ペイロードだけを書き換え、署名はそのままの assertion を送る");

                string assertion = JwtBearerAssertion.Create(client, reg.ClientId);

                JsonResponse tampered = await RequestAsync(client, Jwks.Tamper(assertion));

                r.Verify("改ざんした assertion : トークンを発行しない",
                    string.IsNullOrEmpty(tampered.AccessToken),
                    "access_token を返さない",
                    tampered.AccessToken == null ? "返さなかった（error=" + (tampered.Error ?? "なし") + "）"
                                                 : "**返してしまった**");

                r.Step("(2) alg=none に書き換え、署名を落とした assertion を送る");

                JsonResponse none = await RequestAsync(client, Jwks.ToAlgNone(assertion));

                r.Verify("alg=none の assertion : トークンを発行しない",
                    string.IsNullOrEmpty(none.AccessToken),
                    "access_token を返さない",
                    none.AccessToken == null ? "返さなかった（" + none.ToString() + "）"
                                             : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>EX-7.4 期限切れ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0704_期限切れのassertionは拒否される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-7.4",
                    "期限切れの assertion は拒否される",
                    "assertion は短命であることが前提。"
                    + "**古い assertion が使えると、漏れたものを後から使われる。**",
                    "RFC 7523 §3 (4)（exp を過ぎていれば拒否。MUST）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("exp=10 分前 の assertion を送る（署名は正しい）");

                string assertion = JwtBearerAssertion.Create(client, reg.ClientId,
                    new Dictionary<string, object>() { { "iat", now - 900 }, { "exp", now - 600 } });

                JsonResponse token = await RequestAsync(client, assertion);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった（error=" + (token.Error ?? "なし") + "）"
                                              : "**返してしまった**");

                r.Done();
            }
        }
    }
}
