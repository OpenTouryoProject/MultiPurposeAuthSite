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
//* クラス名        ：SelfTestFapi2Tests
//* クラス日本語名  ：RT 自己テストの FAPI2 のボタンを、PKCE・MTLS で結果の画面まで通す（#345）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/08  玄人 幸道         新規（#345）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Fapi;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-345. 自己テストの FAPI2 のボタンが、PKCE（S256）を使い、登録の方法（private_key_jwt・tls_client_auth）で認証して、結果の画面まで進む。
    /// </summary>
    /// <remarks>
    /// **FAPI 2.0 は、PAR と S256 の PKCE と、MTLS か private_key_jwt のクライアント認証を求める**（FAPI 2.0 Security Profile §5.3.2.1・§5.3.3.2）。
    /// 自己テストは、**Request Object に `code_challenge` を入れず**（Open棟梁 の `RequestObject.Create` に口が無かった。OpenTouryo#675）、
    /// **MTLS で認証するボタンも無かった**（トークン エンドポイント系の口が MTLS を送れなかった。OpenTouryo#676）。
    ///
    /// **自己テストは Open棟梁 のクライアントを使う唯一の場**なので、ここを通すことが、クライアントとサーバの相互接続性の確認になる（#246）。
    /// </remarks>
    public class SelfTestFapi2Tests : TargetTestBase
    {
        /// <summary>エラー画面の見出し</summary>
        private const string ErrorHeading = "<h2 class=\"text-danger\">";

        /// <summary>MTLS の登録の名前（雛形。#345）</summary>
        private const string Fapi2MtlsClient = "FAPI2_MTLS_Client";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SelfTestFapi2Tests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-345.1

        /// <summary>RT-345.1 自己テストの FAPI2 のボタン（/ros・PAR）が、PKCE を使って結果の画面まで進む</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34501_自己テストのFAPI2のボタンがPKCEで結果の画面まで進む(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-345.1",
                    "自己テストの FAPI2 のボタン（FAPI2 CC・FAPI2 CC, PAR）が、Request Object に code_challenge（S256）を入れ、code_verifier を送って引き換え、結果の画面まで進む",
                    "**FAPI 2.0 はクライアントに S256 の PKCE を求める。** PAR と Request Object を使うとき、"
                    + "**PKCE のパラメタは Request Object の中に入る。** "
                    + "**`code_challenge` を付けて認可を求めたコードは、トークン要求で `code_verifier` が要る**（無ければ引き換えられない）。",
                    "FAPI 2.0 Security Profile §5.3.3.2 / RFC 9101 §4 / RFC 7636 §4.3・§4.5 / #345");

                await client.SignInAsync();

                r.Target("自己テスト（ClientType=fapi2）: AuthorizationCodeFAPI2 / AuthorizationCodeFAPI2_PAR");

                foreach (string starter in new string[] { "AuthorizationCodeFAPI2", "AuthorizationCodeFAPI2_PAR" })
                {
                    r.Step("「" + starter + "」を押す");

                    HttpResponseMessage start = await client.StartSelfTestAsync(starter, "fapi2");
                    string authorizeUrl = null;

                    if (starter.EndsWith("_PAR"))
                    {
                        //  **PAR は、預けた結果の画面を返す**（Request Object の中身が見える）。
                        string pushed = await start.Content.ReadAsStringAsync();
                        string decoded = WebUtility.HtmlDecode(pushed);

                        bool isS256 = Regex.IsMatch(decoded, "\"code_challenge_method\"\\s*:\\s*\"S256\"");

                        r.Verify(starter + " : Request Object に code_challenge_method = S256 が入る", isS256,
                            "S256", isS256 ? "S256" : (Regex.IsMatch(decoded, "\"code_challenge_method\"") ? "**S256 以外**" : "**入っていない**"));

                        bool hasChallenge = Regex.IsMatch(decoded, "\"code_challenge\"\\s*:\\s*\"[A-Za-z0-9_\\-]{43}\"");

                        r.Verify(starter + " : Request Object に code_challenge が入る", hasChallenge,
                            "43 文字の値（S256 の BASE64URL）",
                            hasChallenge ? "43 文字の値" : (Regex.IsMatch(decoded, "\"code_challenge\"") ? "**形が違う**" : "**入っていない**"));

                        Match link = Regex.Match(pushed, "href=\"(?<url>[^\"]*request_uri=[^\"]*)\"");

                        Skip.If(!link.Success,
                            "PAR に預けられません（RT-246.1 を見ること。HTTP " + (int)start.StatusCode + "）。");

                        authorizeUrl = WebUtility.HtmlDecode(link.Groups["url"].Value);
                    }
                    else
                    {
                        authorizeUrl = (start.Headers.Location == null) ? null : client.ToLocalUrl(start.Headers.Location.OriginalString);

                        Skip.If(string.IsNullOrEmpty(authorizeUrl),
                            "自己テストが認可リクエストへ飛びません（HTTP " + (int)start.StatusCode + "。RT-197.1 を見ること）。");
                    }

                    string codeVerifier = client.SelfTestCodeVerifier();

                    r.Verify(starter + " : 自己テストが code_verifier を用意する（43 文字以上）",
                        codeVerifier.Length >= 43,
                        "43 文字以上", codeVerifier.Length == 0 ? "**無い**" : codeVerifier.Length + " 文字");

                    r.Step("認可して、戻りの画面を開く（トークン要求は private_key_jwt ＋ code_verifier）");

                    AuthZResponse authz = await client.AuthorizeAndGrantAsync(authorizeUrl);
                    Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                    HttpResponseMessage screen = await client.GetAsync(authz.Location);
                    string html = await screen.Content.ReadAsStringAsync();

                    r.Verify(starter + " : 結果の画面が返る（エラー画面にならない）",
                        screen.StatusCode == HttpStatusCode.OK && !html.Contains(ErrorHeading),
                        "HTTP 200 / エラー画面ではない", "HTTP " + (int)screen.StatusCode + " / " + Html.Describe(html));

                    string accessToken = Html.FieldValue(html, "AccessToken");

                    r.Verify(starter + " : access_token が出る（code_verifier を送って引き換えられた）", !string.IsNullOrEmpty(accessToken),
                        "出る", string.IsNullOrEmpty(accessToken) ? "**出ない**（" + Html.FieldValue(html, "Response") + "）" : "出る");

                    string idToken = Html.FieldValue(html, "IdToken");

                    r.Verify(starter + " : id_token が出る", !string.IsNullOrEmpty(idToken),
                        "出る", string.IsNullOrEmpty(idToken) ? "**出ない**" : "出る");

                    bool pkjAndVerifier = html.Contains("private_key_jwt") && html.Contains("code_verifier");

                    r.Verify(starter + " : 画面のクライアント認証の欄が、private_key_jwt と code_verifier を示す", pkjAndVerifier,
                        "private_key_jwt ＋ code_verifier",
                        pkjAndVerifier ? "private_key_jwt ＋ code_verifier"
                            : (html.Contains("code_verifier") ? "**private_key_jwt ではない**" : "**code_verifier が無い**"));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-345.2

        /// <summary>RT-345.2 FAPI2 の結果の画面のボタン（照会・更新・取り消し）が、private_key_jwt で送って通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34502_FAPI2の結果の画面のボタンがprivate_key_jwtで通る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-345.2",
                    "FAPI2 の自己テストの結果の画面で、照会・更新・取り消しのボタンが、登録の方法（private_key_jwt）で送って通る",
                    "**サーバは、登録が明示した方法でしか通さない**（`token_endpoint_auth_method`）。"
                    + "**以前の結果の画面のボタンは、クライアントによらず秘密を Basic で送っていた**ので、"
                    + "**private_key_jwt を明示した fapi2 の登録では断られていた。** "
                    + "fapi2 は refresh_token を、非対称の証明でだけ使える。",
                    "RFC 7523 §2.2 / RFC 6749 §6 / RFC 7009 §2.1 / RFC 7662 §2.1 / #345");

                await client.SignInAsync();

                r.Target("自己テスト（ClientType=fapi2）: AuthorizationCodeFAPI2 → 結果の画面のボタン");

                r.Step("(1) 自己テストを通し、結果の画面まで進む");

                HttpResponseMessage start = await client.StartSelfTestAsync("AuthorizationCodeFAPI2", "fapi2");
                string authorizeUrl = (start.Headers.Location == null) ? null : start.Headers.Location.OriginalString;

                Skip.If(string.IsNullOrEmpty(authorizeUrl),
                    "自己テストが認可リクエストへ飛びません（HTTP " + (int)start.StatusCode + "。RT-197.1 を見ること）。");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(authorizeUrl));
                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                HttpResponseMessage screen = await client.GetAsync(authz.Location);
                string html = await screen.Content.ReadAsStringAsync();

                string accessToken = Html.FieldValue(html, "AccessToken");
                string refreshToken = Html.FieldValue(html, "RefreshToken");

                Assert.False(string.IsNullOrEmpty(accessToken), "前提: 結果の画面に access_token が出ること（" + Html.FieldValue(html, "Response") + "）");
                Assert.False(string.IsNullOrEmpty(refreshToken), "前提: 結果の画面に refresh_token が出ること（fapi2 にも発行される。RT-239.5）");

                //  **ボタンを押す**（画面の値をそのまま送る。応答は画面の Response 欄に出る。RT-294.38 と同じ）。
                Func<string, Task<string>> press = async (button) =>
                {
                    r.Step("「" + button + "」を押す");

                    HttpResponseMessage res = await client.PostFormAsync("/Account/OAuth2AuthorizationCodeGrantClient2",
                        new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", Html.Antiforgery(html) },
                            { "ClientId", Html.FieldValue(html, "ClientId") },
                            { "State", Html.FieldValue(html, "State") },
                            { "Code", Html.FieldValue(html, "Code") },
                            { "AccessToken", Html.FieldValue(html, "AccessToken") },
                            { "IdToken", Html.FieldValue(html, "IdToken") ?? "" },
                            { "RefreshToken", Html.FieldValue(html, "RefreshToken") },
                            { "submit." + button, button }
                        });

                    html = await res.Content.ReadAsStringAsync();

                    Assert.True(res.StatusCode == HttpStatusCode.OK && !html.Contains(ErrorHeading),
                        "前提: 結果の画面が返ること（HTTP " + (int)res.StatusCode + " / " + Html.Describe(html) + "）");

                    return SelfTestFapi2Tests.TextAreaValue(html, "Response").Replace(" ", "").Replace("\r", "").Replace("\n", "");
                };

                string introspected = await press("IntrospectAccess");
                r.Verify("照会（access_token）: **有効**（private_key_jwt で認証できた）", introspected.Contains("\"active\":true"),
                    "active=true", SelfTestFapi2Tests.Brief(introspected));

                string refreshed = await press("Refresh");
                string newAccessToken = Html.FieldValue(html, "AccessToken");

                r.Verify("更新 : **新しい access_token が画面に出る**（private_key_jwt で認証できた）",
                    refreshed.Contains("access_token") && !string.IsNullOrEmpty(newAccessToken) && newAccessToken != accessToken,
                    "新しい access_token", SelfTestFapi2Tests.Brief(refreshed));

                await press("RevokeAccess");
                string revokedAccess = await press("IntrospectAccess");
                r.Verify("**取り消した access_token は、照会で無効**（取り消しも通った）", revokedAccess.Contains("\"active\":false"),
                    "active=false", SelfTestFapi2Tests.Brief(revokedAccess));

                r.Done();
            }
        }

        #endregion

        #region RT-345.3

        /// <summary>RT-345.3 自己テストの MTLS のボタンが、tls_client_auth で PAR に預け、引き換えて、結果の画面まで進む</summary>
        /// <param name="targetKey">core（net48 版は作らない。理由は remarks）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **net10.0 版だけを測る。** 自己テストが添える証明書（`SpRp_ClientCertPfxFilePath`）は自己署名で、
        /// **net48 版（IIS Express）は自己署名の証明書をアプリより前で断る**（`FA-6` の `-NetFxMtls` は、テスト用 CA の発行した別の証明書を使う）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT34503_自己テストのMTLSのボタンが結果の画面まで進む(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-345.3",
                    "自己テストの MTLS のボタンが、tls_client_auth を明示した fapi2 の登録を選び、PAR とトークン要求をクライアント証明書で認証して、結果の画面まで進む",
                    "**FAPI 2.0 が認めるクライアント認証は MTLS か private_key_jwt。** "
                    + "**自己テストは private_key_jwt しか試せなかった**（MTLS で引き換える口が Open棟梁 に無かった。OpenTouryo#676）。"
                    + "**MTLS は明示した登録でしか通らない**ので、ボタンはその登録だけを選ぶ。",
                    "RFC 8705 §2 / RFC 9126 §2 / FAPI 2.0 Security Profile §5.3.2.1 / #345");

                MtlsTests.SkipIfNoMtls(client.Target);

                string configured = client.Config.FindClientIdByName(SelfTestFapi2Tests.Fapi2MtlsClient);

                Skip.If(string.IsNullOrEmpty(configured),
                    "client_name=" + SelfTestFapi2Tests.Fapi2MtlsClient + " が構成ファイルに在りません（雛形から写してください。#345）: "
                    + client.Config.Path);

                string pfx = client.Config.Get("SpRp_ClientCertPfxFilePath");

                Skip.If(string.IsNullOrEmpty(pfx) || !File.Exists(pfx),
                    "自己テストのクライアント証明書（SpRp_ClientCertPfxFilePath）がありません（GenClientCertByOpenSSL.bat で作る）。");

                await client.SignInAsync();

                r.Target("自己テスト（ClientType=fapi2）: AuthorizationCodeFAPI2_PAR_MTLS / " + SelfTestFapi2Tests.Fapi2MtlsClient + "（token_endpoint_auth_method=tls_client_auth）");

                r.Step("(1) 「AuthorizationCodeFAPI2_PAR_MTLS」を押す（tls_client_auth で /par に預ける）");

                HttpResponseMessage start = await client.StartSelfTestAsync("AuthorizationCodeFAPI2_PAR_MTLS", "fapi2");
                string pushed = await start.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200（預けた結果の画面）", "200", ((int)start.StatusCode).ToString());

                r.Verify("選んだ登録が " + SelfTestFapi2Tests.Fapi2MtlsClient + " である", pushed.Contains(configured),
                    configured, pushed.Contains(configured) ? configured : "**違う**（" + Html.Describe(pushed) + "）");

                r.Verify("PAR のクライアント認証が tls_client_auth である", pushed.Contains("tls_client_auth"),
                    "tls_client_auth", pushed.Contains("tls_client_auth") ? "tls_client_auth" : "**違う**");

                Match link = Regex.Match(pushed, "href=\"(?<url>[^\"]*request_uri=[^\"]*)\"");

                r.Verify("request_uri で認可へ進むリンクが出る（PAR が証明書で認証できた）", link.Success,
                    "リンクあり", link.Success ? "あり" : "**無し**（" + SelfTestFapi2Tests.Brief(SelfTestFapi2Tests.TextAreaValue(pushed, "Response")) + "）");

                Assert.True(link.Success, "前提: PAR に預けられること");

                r.Step("(2) 認可して、戻りの画面を開く（トークン要求は tls_client_auth ＋ code_verifier）");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(WebUtility.HtmlDecode(link.Groups["url"].Value));
                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                HttpResponseMessage screen = await client.GetAsync(authz.Location);
                string html = await screen.Content.ReadAsStringAsync();

                r.Verify("結果の画面が返る（エラー画面にならない）",
                    screen.StatusCode == HttpStatusCode.OK && !html.Contains(ErrorHeading),
                    "HTTP 200 / エラー画面ではない", "HTTP " + (int)screen.StatusCode + " / " + Html.Describe(html));

                string accessToken = Html.FieldValue(html, "AccessToken");

                r.Verify("access_token が出る（証明書で認証して引き換えられた）", !string.IsNullOrEmpty(accessToken),
                    "出る", string.IsNullOrEmpty(accessToken) ? "**出ない**（" + Html.FieldValue(html, "Response") + "）" : "出る");

                bool tlsAndVerifier = html.Contains("tls_client_auth") && html.Contains("code_verifier");

                r.Verify("画面のクライアント認証の欄が、tls_client_auth と code_verifier を示す", tlsAndVerifier,
                    "tls_client_auth ＋ code_verifier",
                    tlsAndVerifier ? "tls_client_auth ＋ code_verifier"
                        : (html.Contains("tls_client_auth") ? "**code_verifier が無い**" : "**tls_client_auth ではない**"));

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>textarea の中身（無ければ空。AccountFlowTests と同じ）</summary>
        /// <param name="body">画面の本文</param>
        /// <param name="name">name</param>
        /// <returns>中身（HTML の文字参照は戻す）</returns>
        private static string TextAreaValue(string body, string name)
        {
            Match m = Regex.Match(body,
                "<textarea\\b[^>]*\\bname=\"" + Regex.Escape(name) + "\"[^>]*>(?<v>.*?)</textarea>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            return m.Success ? WebUtility.HtmlDecode(m.Groups["v"].Value) : "";
        }

        /// <summary>応答を、報告に出せる長さに縮める（トークンの値は出さない。AccountFlowTests と同じ）</summary>
        /// <param name="response">応答</param>
        /// <returns>先頭の 80 文字（JWT は伏せる）</returns>
        private static string Brief(string response)
        {
            string squashed = Regex.Replace(response ?? "", "ey[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-\\.]+", "(JWT)");
            return (squashed.Length <= 80) ? squashed : squashed.Substring(0, 80) + "…";
        }

        #endregion
    }
}
