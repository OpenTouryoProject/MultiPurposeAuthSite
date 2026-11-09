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
//* クラス名        ：EmptyClaimTests
//* クラス日本語名  ：RT-354 値の無いクレームを、空文字列で返さない（#354）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/10  玄人 幸道         新規（#354）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-354. 値の無いクレームを、空文字列で返さない（名前ごと省く）。
    /// </summary>
    /// <remarks>
    /// **電話番号の無い利用者に、userinfo が `"phone_number": ""` を返していた**（#354）。
    /// 適合性テスト（#350）の `ValidateUserInfoStandardClaims` で見つかった。
    /// **JWT の access_token のクレームも同じ形だった**ので、同じ部品（`UserClaims.AddContactClaims`）でそろえた。
    ///
    /// **種データの利用者は電話番号を持たない**（サインアップ時は空文字列）。**メール アドレスは持つ**ので、対照に使う。
    /// </remarks>
    public class EmptyClaimTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public EmptyClaimTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-354.1 値の無い phone_number は、userinfo にも access_token にも出ない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35401_値の無いphone_numberはuserinfoにもaccess_tokenにも出ない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-354.1",
                    "値の無い phone_number は、userinfo にも access_token にも出ない（空文字列で返さない）",
                    "**値の無いクレームは、名前ごと省く**（空文字列・null で返さない）。"
                    + "**`phone_number_verified` も、`phone_number` が無ければ出さない**（確かめた対象が無いため）。"
                    + "対照として、値の在る `email` と `email_verified` は返ることを見る。"
                    + "**JWT の access_token のクレームも、userinfo と同じ部品で作る。**",
                    "OIDC Core 1.0 §5.3.2 / #354");

                r.Target("client_name=" + KnownClients.MvcSample + " / scope=openid email phone / username="
                    + TestEnv.TestUserName(targetKey) + "（種データの利用者。電話番号なし。パスワードは構成ファイルから読む）");

                r.Step("(1) scope=\"openid email phone\" で認可コードを引き換え、/userinfo を叩く");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること（" + token.ToString() + "）");

                JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                Assert.True(userinfo.IsJson, "前提: userinfo が JSON を返すこと（" + userinfo.ToString() + "）");

                r.Observe("userinfo の phone_number（種データの利用者は電話番号を持たない）",
                    userinfo.KindOf("phone_number") == JsonValueKind.Undefined ? "項目なし" : "型 = " + userinfo.KindOf("phone_number"),
                    "電話番号を持つ利用者なら、値の在る文字列で返る（E2E では登録できないので測っていない）。");

                EmptyClaimTests.VerifyContact(r, "userinfo",
                    userinfo.KindOf("phone_number"), userinfo.String("phone_number"),
                    userinfo.KindOf("phone_number_verified"),
                    userinfo.KindOf("email"), userinfo.String("email"),
                    userinfo.KindOf("email_verified"));

                r.Step("(2) grant_type=password で取った access_token（JWT）のペイロードを見る");

                //  **email / phone のクレームを access_token に載せるのは `CreateFromClaims` の経路だけ**
                //  （ROPC・JWT Bearer・Implicit）。**認可コードの access_token には載らない**（`CreatePayloadForCode`）。
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "password");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                JsonResponse ropc = await client.TokenAsync(new System.Collections.Generic.Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName(targetKey) },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "openid email phone" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(ropc.AccessToken), "前提: ROPC で access_token が返ること（" + ropc.ToString() + "）");

                JsonElement payload = Jwt.Payload(ropc.AccessToken);

                EmptyClaimTests.VerifyContact(r, "access_token",
                    Jwt.KindOf(payload, "phone_number"), Jwt.String(payload, "phone_number"),
                    Jwt.KindOf(payload, "phone_number_verified"),
                    Jwt.KindOf(payload, "email"), Jwt.String(payload, "email"),
                    Jwt.KindOf(payload, "email_verified"));

                r.Done();
            }
        }

        /// <summary>email / phone のクレームの出し方を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">どこか（userinfo / access_token）</param>
        /// <param name="phoneKind">phone_number の型</param>
        /// <param name="phone">phone_number の値</param>
        /// <param name="phoneVerifiedKind">phone_number_verified の型</param>
        /// <param name="emailKind">email の型</param>
        /// <param name="email">email の値</param>
        /// <param name="emailVerifiedKind">email_verified の型</param>
        private static void VerifyContact(TestReport r, string label,
            JsonValueKind phoneKind, string phone, JsonValueKind phoneVerifiedKind,
            JsonValueKind emailKind, string email, JsonValueKind emailVerifiedKind)
        {
            bool phonePresent = phoneKind != JsonValueKind.Undefined;
            bool phoneOk = !phonePresent || (phoneKind == JsonValueKind.String && !string.IsNullOrEmpty(phone));

            r.Verify(label + "：phone_number は、項目なしか値の在る文字列（空文字列・null にしない）", phoneOk,
                "項目なし、または値の在る文字列",
                !phonePresent ? "項目なし"
                    : (phoneKind == JsonValueKind.String && string.IsNullOrEmpty(phone)) ? "**空文字列**" : "型 = " + phoneKind);

            r.VerifyEqual(label + "：phone_number_verified は、phone_number が在るときだけ在る",
                phonePresent ? "在る" : "無い",
                phoneVerifiedKind == JsonValueKind.Undefined ? "無い" : "在る");

            r.Verify(label + "：（対照）値の在る email は返る", emailKind == JsonValueKind.String && !string.IsNullOrEmpty(email),
                "値の在る文字列", emailKind == JsonValueKind.Undefined ? "**項目なし**" : "型 = " + emailKind + "（値は伏せる）");

            r.Verify(label + "：（対照）email_verified は真偽値で返る",
                emailVerifiedKind == JsonValueKind.True || emailVerifiedKind == JsonValueKind.False,
                "boolean", "email_verified の型 = " + emailVerifiedKind);
        }
    }
}
