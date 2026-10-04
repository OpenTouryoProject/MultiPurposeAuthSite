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
//* クラス名        ：CorsTests
//* クラス日本語名  ：RT-265 CORS をエンドポイント単位にする
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/04  玄人 幸道         新規（#265）
//*  2026/10/04  玄人 幸道         両系統に流すようにし、資格情報の確認を足した
//*  2026/10/04  玄人 幸道         RT-266.1（web_originsの登録）を追加（#266）
//**********************************************************************************

using System;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-265 CORS が、口の性質ごとに分かれている（#265）。
    /// </summary>
    /// <remarks>
    /// **以前は全エンドポイントで `AllowAnyOrigin` だった。**
    /// `Startup.cs` の `UseCors` にインラインの全開ポリシーが在り、
    /// **`/token` `/revoke` `/introspect` まで任意オリジンから叩けた**（実測）。
    ///
    /// | 口 | 方針 |
    /// |---|---|
    /// | `.well-known/openid-configuration` / `jwkcerts` | **常に全開**（公開情報） |
    /// | `/userinfo` / `/token` / `/SetDeviceToken` / `/ciba_result` / `/2fa_result` | **許すオリジンだけ** |
    /// | `/revoke` / `/introspect` | **CORS を付けない**（ブラウザから叩く口ではない） |
    ///
    /// **許すオリジンは、登録から導く。**
    /// **構成ファイルの public クライアント（`client_secret` を持たないもの）の
    /// `redirect_uri_*` のオリジン**である（`CmnEndpoints.GetCorsAllowedOrigins`）。
    /// **SPA の `redirect_uri` は、必ずその SPA のオリジン上にある**ため。
    /// 追加分は `CorsAllowedOrigins`（空でよい）。
    ///
    /// **両系統に流す。** **仕組みは違う**（net10.0 版はポリシー、net48 版は Web API の属性）が、
    /// **外から見た振る舞いは同じ**にしてある。
    /// </remarks>
    public class CorsTests : TargetTestBase
    {
        /// <summary>導出に使う登録（web ビルドの認証デバイス。public クライアント）</summary>
        private const string DerivedFrom = "AuthenticationDevice_Web";

        /// <summary>許していないオリジン</summary>
        private const string Evil = "https://evil.example";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CorsTests(ITestOutputHelper output) : base(output) { }

        /// <summary>RT-265.1 CORS が口の性質ごとに分かれている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT26501_CORSが口の性質ごとに分かれている(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-265.1",
                    "公開情報は全開、ブラウザから叩く口は登録から導いたオリジンだけ、"
                    + "/revoke と /introspect には CORS を付けない",
                    "**以前は全エンドポイントで `AllowAnyOrigin` だった**（#265）。"
                    + "`Startup.cs` の `UseCors` にインラインの全開ポリシーが在り、"
                    + "**`/token` `/revoke` `/introspect` まで任意オリジンから叩けた。**"
                    + "**開ける必要があるのは `/userinfo` と公開情報、"
                    + "それに SPA が叩く `/token` 程度**で、"
                    + "**`/revoke` `/introspect` はブラウザから叩く口ではない。**"
                    + "**許すオリジンは、登録した `redirect_uri` から導く**"
                    + "（Keycloak の Web origins の既定値 `+` と同じ考え方）。",
                    "Fetch Standard（CORS）/ OAuth 2.0 for Browser-Based Apps / #265");

                // **両系統で同じ振る舞いを測る。**
                //   仕組みは違う（net10.0 版はポリシー、net48 版は Web API の属性）。

                // **導出元の登録から、許されるオリジンを作る。**
                //   **サーバ側と同じ計算**になっていることも、これで一緒に測れる。
                string clientId = client.Config.FindClientIdByName(CorsTests.DerivedFrom);

                Skip.If(string.IsNullOrEmpty(clientId),
                    "client_name=" + CorsTests.DerivedFrom + " が構成ファイルに在りません。"
                    + "（CORS のオリジンは、public クライアントの redirect_uri から導く。#265）");

                string registered = client.Config.GetClientAttribute(clientId, "redirect_uri_code");

                Skip.If(string.IsNullOrEmpty(registered)
                    || !Uri.TryCreate(registered, UriKind.Absolute, out Uri registeredUri)
                    || (registeredUri.Scheme != Uri.UriSchemeHttp
                        && registeredUri.Scheme != Uri.UriSchemeHttps),
                    "client_name=" + CorsTests.DerivedFrom
                    + " の redirect_uri_code が http(s) の絶対URLではありません: " + registered);

                string allowed = new Uri(registered).GetLeftPart(UriPartial.Authority);

                r.Target("許すオリジン=" + allowed
                    + "（" + CorsTests.DerivedFrom + " の redirect_uri_code から導出）"
                    + " / 許さないオリジン=" + CorsTests.Evil);

                r.Verify("導出したオリジンが、サイト自身のオリジンとは違う（測る前提）",
                    !allowed.Equals(client.Target.BaseUrl, StringComparison.OrdinalIgnoreCase),
                    "違う",
                    allowed.Equals(client.Target.BaseUrl, StringComparison.OrdinalIgnoreCase)
                        ? "**同じ**（同一オリジンでは CORS を測れない）" : "違う");

                r.Step("(1) 公開情報は、許していないオリジンにも開く");

                foreach (string ep in new string[] { "/.well-known/openid-configuration", "/jwkcerts" })
                {
                    HttpResponseMessage res = await client.GetWithOriginAsync(ep, CorsTests.Evil);
                    string value = IdPClient.AllowOrigin(res);

                    r.VerifyEqual(ep + " の Access-Control-Allow-Origin", "*", value);
                }

                r.Step("(2) ブラウザから叩く口は、導出したオリジンだけ通る");

                foreach (string ep in new string[] {
                    "/token", "/SetDeviceToken", "/ciba_result", "/2fa_result" })
                {
                    HttpResponseMessage ok = await client.PreflightAsync(ep, allowed, "POST");
                    HttpResponseMessage ng = await client.PreflightAsync(ep, CorsTests.Evil, "POST");

                    r.VerifyEqual(ep + " は、導出したオリジンを許す",
                        allowed, IdPClient.AllowOrigin(ok));

                    r.VerifyEqual(ep + " は、それ以外を許さない",
                        "（無し）", CorsTests.Shown(IdPClient.AllowOrigin(ng)));
                }

                // **`/userinfo` は GET の口。** プリフライトは GET で測る
                //   （`Access-Control-Request-Method` で経路が選ばれるため）。
                HttpResponseMessage userInfoOk =
                    await client.PreflightAsync("/userinfo", allowed, "GET");
                HttpResponseMessage userInfoNg =
                    await client.PreflightAsync("/userinfo", CorsTests.Evil, "GET");

                r.VerifyEqual("/userinfo は、導出したオリジンを許す",
                    allowed, IdPClient.AllowOrigin(userInfoOk));

                r.VerifyEqual("/userinfo は、それ以外を許さない",
                    "（無し）", CorsTests.Shown(IdPClient.AllowOrigin(userInfoNg)));

                r.Step("(3) /revoke と /introspect には CORS を付けない");

                foreach (string ep in new string[] { "/revoke", "/introspect" })
                {
                    HttpResponseMessage res = await client.PreflightAsync(ep, allowed, "POST");

                    r.VerifyEqual(ep + " は、許したオリジンにも CORS を付けない",
                        "（無し）", CorsTests.Shown(IdPClient.AllowOrigin(res)));
                }

                r.Step("(4) 資格情報は許さない");

                HttpResponseMessage credentials =
                    await client.PreflightAsync("/token", allowed, "POST");

                r.VerifyEqual("/token に Access-Control-Allow-Credentials を付けない",
                    "（無し）",
                    CorsTests.Shown(credentials.Headers.Contains("Access-Control-Allow-Credentials")
                        ? string.Join(",", credentials.Headers.GetValues("Access-Control-Allow-Credentials"))
                        : ""));

                r.Note("**`Access-Control-Allow-Credentials` は、どちらのポリシーにも付けていない。**"
                    + "**Cookie で通る口をこの範囲に入れない**ため"
                    + "（入れると、他オリジンの JS から利用者の資格情報で呼べる）。");

                r.Note("**プリフライトは、実際に叩くメソッドで測ること。**"
                    + "ASP.NET Core は `Access-Control-Request-Method` で経路を選ぶので、"
                    + "**GET だけの口に `POST` を書くと、経路が当たらず 404 になる**（実測で踏んだ）。");

                r.Done();
            }
        }

        /// <summary>RT-266.1 web_origins を登録すると、そのオリジンだけが許される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT26601_web_originsを登録するとそのオリジンだけが許される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-266.1",
                    "クライアント登録の web_origins が、CORS の許可オリジンになる",
                    "**#265 では、許可オリジンを「構成ファイルの public クライアントの "
                    + "`redirect_uri_*`」から導いていた。**"
                    + "**画面から登録した SPA は導出に含まれず**、配備側で `CorsAllowedOrigins` に "
                    + "書く必要があった。"
                    + "**クライアント単位の登録項目 `web_origins` を足した**（#266）。"
                    + "**空なら従来どおり `redirect_uri_*` から導く**"
                    + "（Keycloak の Web origins の既定値 `+` と同じ考え方）。",
                    "Fetch Standard（CORS）/ OIDC Dynamic Client Registration（web_origins 相当）/ #266");

                // **TestClient_16 は構成ファイルに無い**（種データが user store に作る。#264）。
                //   **client_secret を空にした public クライアント**で、
                //   **`web_origins` と、別のオリジンの `redirect_uri_code` を持つ。**
                Flows.InjectedRegistration(client, KnownClients.TestClient_16);

                r.Target("client_name=" + KnownClients.TestClient_16
                    + "（web_origins=" + KnownClients.WebOrigin
                    + " / redirect_uri_code のオリジン=" + KnownClients.NotAllowedOrigin + "）");

                r.Step("(1) 登録した web_origins は許される（画面登録＝user store の経路）");

                HttpResponseMessage allowed =
                    await client.PreflightAsync("/token", KnownClients.WebOrigin, "POST");

                r.VerifyEqual("/token が web_origins を許す",
                    KnownClients.WebOrigin, IdPClient.AllowOrigin(allowed));

                r.Step("(2) web_origins を書いたら、redirect_uri_code からは導出しない");

                HttpResponseMessage notAllowed =
                    await client.PreflightAsync("/token", KnownClients.NotAllowedOrigin, "POST");

                r.VerifyEqual("/token は redirect_uri_code のオリジンを許さない",
                    "（無し）", CorsTests.Shown(IdPClient.AllowOrigin(notAllowed)));

                r.Step("(3) CORS を付けない口は、web_origins を登録しても開かない");

                HttpResponseMessage revoke =
                    await client.PreflightAsync("/revoke", KnownClients.WebOrigin, "POST");

                r.VerifyEqual("/revoke は CORS を付けない",
                    "（無し）", CorsTests.Shown(IdPClient.AllowOrigin(revoke)));

                r.Note("**(1) が #266 の本題である。**"
                    + "**画面から登録したクライアントのオリジンが、設定を書かずに効く。**"
                    + "種データは user store（`saml2OAuth2Data`）に入るので、**画面登録と同じ経路**である。");

                r.Note("**(2) は、`web_origins` が `redirect_uri_*` に勝つことを見ている。**"
                    + "**書いたときは導出しない**（登録どおりに絞る）。"
                    + "**空なら従来どおり導出する**（`RT-265.1` が、その経路を測っている）。");

                r.Note("**許可オリジンはキャッシュしている**（60 秒＋登録の保存で破棄）。"
                    + "**複数インスタンスでは、他のインスタンスのキャッシュは捨てられない。**"
                    + "**期限が、その取りこぼしを拾う**（共有キャッシュには E-2 が要る）。");

                r.Done();
            }
        }

        /// <summary>報告に出す形（空なら「（無し）」）</summary>
        /// <param name="value">値</param>
        /// <returns>表示用</returns>
        private static string Shown(string value)
        {
            return string.IsNullOrEmpty(value) ? "（無し）" : value;
        }
    }
}
