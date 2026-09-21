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
//* クラス名        ：CacheControlTests
//* クラス日本語名  ：RT 資格情報・属性を返す口のキャッシュ制御（#218）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/17  玄人 幸道         新規（#218 : /introspect・/userinfo・/device_authz・/ciba_authz）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-218. 資格情報・属性を返す口のキャッシュ制御。
    /// </summary>
    /// <remarks>
    /// トークン応答（/token）そのものは TC-3.2 で測る（RFC 6749 §5.1 / §5.2 の MUST）。
    /// **本クラスは、その MUST の外側**（RFC が明記していない口）を測る。
    /// </remarks>
    public class CacheControlTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CacheControlTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>
        /// no-store / no-cache が付いているかを確かめる。
        /// </summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">エンドポイントの名前</param>
        /// <param name="res">JsonResponse</param>
        /// <remarks>
        /// **値の完全一致では見ない。** net48 版は System.Web の Response.Cache を使うため、
        /// Cache-Control が "no-store, no-cache" になる。
        /// </remarks>
        private static void VerifyNoStore(TestReport r, string label, JsonResponse res)
        {
            string cacheControl = res.Header("Cache-Control");
            string pragma = res.Header("Pragma");

            r.Verify(label + " : Cache-Control に no-store が付く",
                cacheControl != null && cacheControl.Contains("no-store"),
                "no-store を含む", cacheControl ?? "（ヘッダ無し）");

            r.Verify(label + " : Pragma に no-cache が付く",
                pragma != null && pragma.Contains("no-cache"),
                "no-cache を含む", pragma ?? "（ヘッダ無し）");
        }

        /// <summary>RT-218.1 資格情報・属性を返す口のキャッシュ制御</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT218_01_資格情報や属性を返す口にもキャッシュ制御が付く(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-218.1",
                    "/introspect・/userinfo・/device_authz・/ciba_authz にもキャッシュ制御が付く",
                    "**RFC が MUST としているのは /token だけ**（RFC 6749 §5.1 / §5.2）。"
                    + "しかしこの 4 つも、資格情報（device_code / auth_req_id）や"
                    + "利用者の属性を返すので、**中間キャッシュやブラウザ履歴に残ると困る点は同じ**。",
                    "RFC 6749 §5.1 / §5.2（/token の MUST）/ #218");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コード フローでトークンを得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が取れること");

                r.Step("(2) /introspect の応答ヘッダを見る");

                VerifyNoStore(r, "/introspect",
                    await Flows.IntrospectAsync(client, reg, token.AccessToken, null));

                r.Step("(3) /userinfo の応答ヘッダを見る");

                VerifyNoStore(r, "/userinfo", await client.UserInfoAsync(token.AccessToken));

                r.Step("(4) /device_authz の応答ヘッダを見る");

                VerifyNoStore(r, "/device_authz", await client.DeviceAuthorizationAsync(
                    new Dictionary<string, string>()
                    {
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret },
                        { "scope", "openid email" }
                    }));

                r.Step("(5) /ciba_authz の応答ヘッダを見る（要求の中身は問わない）");

                r.Note("(5) は要求が不正でもよい。**エラー応答にも付くこと**を確かめる（RFC 6749 §5.2 と同じ考え方）。");

                VerifyNoStore(r, "/ciba_authz", await client.CibaAuthorizeAsync(
                    new Dictionary<string, string>()
                    {
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    }));

                r.Done();
            }
        }
    }
}
