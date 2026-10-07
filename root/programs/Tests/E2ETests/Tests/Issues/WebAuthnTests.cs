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
//* クラス名        ：WebAuthnTests
//* クラス日本語名  ：RT-137 WebAuthn（fido2-net-lib 4.2.0）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#137）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-137. WebAuthn を fido2-net-lib 4.2.0 で作り直した（#137）。
    /// </summary>
    /// <remarks>
    /// **以前は 4 ファイルともビルド対象外で、設定キーだけが残っていた**
    /// （`CommonLibrary/ANALYSIS.md` 12 節）。
    ///
    /// | | |
    /// |---|---|
    /// | **net10.0 版** | `Fido2` 4.2.0 で復活させた |
    /// | **net48 版** | **退役**。`Fido2` は 2.0.2 を最後に `netstandard2.0` を落としており、他の WebAuthn ライブラリも net8.0 以降しか無い |
    /// | **MsPass** | **退役**。`navigator.authentication` は EdgeHTML 専用の前身 API |
    ///
    /// **測れるのはサーバ側だけである。**
    /// **`navigator.credentials` を呼ぶのはブラウザ**なので、
    /// **attestation / assertion を作るには仮想認証器（CDP）が要る。**
    /// **この基盤は HttpClient だけなので、そこまでは測らない。**
    ///
    /// **測るのは「要求を組み立てる段」と「壊れた入力の扱い」と「退役したこと」**である。
    /// </remarks>
    public class WebAuthnTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public WebAuthnTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-137.1 登録の要求（CredentialCreateOptions）が組み立てられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT13701_登録の要求が組み立てられる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-137.1",
                    "WebAuthn の登録画面が、CredentialCreateOptions を組み立てて返す",
                    "**`RequestNewCredential` は 4.x で引数オブジェクトになった**"
                    + "（`RequestNewCredentialParams`）。**戻り値の直列化も "
                    + "Newtonsoft から System.Text.Json に変わっている。**"
                    + "**組み立てた JSON が、W3C の `PublicKeyCredentialCreationOptions` の形で"
                    + "出ているか**を見る。"
                    + "**net48 版はこの口を持たない**（現行版のライブラリが netstandard2.0 を支えていない）。",
                    "W3C WebAuthn Level 2 §5.4 / fido2-net-lib 4.2.0 / #137");

                r.Target("POST /Manage/AddWebAuthnData（sequenceNo=0）");

                bool isCore = (targetKey == TestEnv.CoreKey);

                if (!isCore)
                {
                    r.Step("(1) net48 版には、WebAuthn の登録画面が無い");

                    string gone = await client.WebAuthnCreationOptionsAsync(
                        TestEnv.TestUserName(targetKey));

                    r.Verify("登録画面が開かない", gone == null,
                        "開かない", (gone == null) ? "開かなかった" : "**開いた**");

                    r.Note("**退役させた**（#137）。"
                        + "**`Fido2` は 2.0.2 を最後に `netstandard2.0` を落としている**"
                        + "（3.0 以降は `net6.0` / `net8.0` / `net10.0`）。"
                        + "**`WebAuthn.Net` / `Shark.Fido2` / `Rsk.AspNetCore.Fido` も net8.0 以降だけ**"
                        + "なので、**net48 で支えられる現行版が存在しない。**");

                    r.Done();
                    return;
                }

                r.Step("(1) 登録画面を開いて、options を受け取る");

                string html = await client.WebAuthnCreationOptionsAsync(
                    TestEnv.TestUserName(targetKey),
                    residentKey: false,
                    authenticatorAttachment: "cross-platform",
                    userVerification: "preferred",
                    attestation: "none");

                r.Verify("登録画面が開く", html != null,
                    "開く", (html != null) ? "開いた" : "**開かなかった**");

                Assert.NotNull(html);

                string json = Html.FieldValue(html, "fido2Data");

                r.Verify("options が隠しフィールドに入る", !string.IsNullOrEmpty(json),
                    "入る", string.IsNullOrEmpty(json) ? "**空**" : "入っている");

                Assert.False(string.IsNullOrEmpty(json), "前提: options が返ること");

                r.Step("(2) options の中身が、W3C の形になっている");

                JsonElement o = JsonDocument.Parse(json).RootElement;

                string status = o.TryGetProperty("status", out JsonElement st)
                    ? st.GetString() : "";

                r.VerifyEqual("status が ok", "ok", status);

                if (status != "ok")
                {
                    r.Note("**errorMessage: "
                        + (o.TryGetProperty("errorMessage", out JsonElement em)
                            ? em.GetString() : "(無し)") + "**");
                }

                Assert.Equal("ok", status);

                r.Verify("challenge がある",
                    o.TryGetProperty("challenge", out JsonElement ch)
                        && !string.IsNullOrEmpty(ch.GetString()),
                    "ある", o.TryGetProperty("challenge", out JsonElement ch2)
                        ? ("長さ " + (ch2.GetString() ?? "").Length + " 文字（base64url）") : "**無い**");

                r.Verify("rp.id がある（RPID）",
                    o.TryGetProperty("rp", out JsonElement rp)
                        && rp.TryGetProperty("id", out JsonElement rpid)
                        && !string.IsNullOrEmpty(rpid.GetString()),
                    "ある",
                    (o.TryGetProperty("rp", out JsonElement rp2)
                        && rp2.TryGetProperty("id", out JsonElement rpid2))
                        ? rpid2.GetString() : "**無い**");

                r.Verify("user.id がある",
                    o.TryGetProperty("user", out JsonElement us)
                        && us.TryGetProperty("id", out JsonElement uid)
                        && !string.IsNullOrEmpty(uid.GetString()),
                    "ある",
                    (o.TryGetProperty("user", out JsonElement us2)
                        && us2.TryGetProperty("id", out JsonElement uid2))
                        ? "ある" : "**無い**");

                int algs = o.TryGetProperty("pubKeyCredParams", out JsonElement pk)
                    ? pk.GetArrayLength() : 0;

                r.Verify("pubKeyCredParams に鍵アルゴリズムが並ぶ", 0 < algs,
                    "1 件以上", algs + " 件");

                r.Verify("認証器の指定が渡る（cross-platform）",
                    o.TryGetProperty("authenticatorSelection", out JsonElement sel)
                        && sel.TryGetProperty("authenticatorAttachment", out JsonElement at)
                        && at.GetString() == "cross-platform",
                    "cross-platform",
                    (o.TryGetProperty("authenticatorSelection", out JsonElement sel2)
                        && sel2.TryGetProperty("authenticatorAttachment", out JsonElement at2))
                        ? at2.GetString() : "**無い**");

                r.Note("**`status` / `errorMessage` は、こちらで付けている封筒である**（#137）。"
                    + "**4.x の options は `Status` も `ErrorMessage` も持たない**"
                    + "（成功は「例外が出ないこと」で表す形になった）。"
                    + "**画面は form post で値を往復させる**ので、"
                    + "**HTTP のステータス コードでエラーを伝える余地が無い。**");

                r.Done();
            }
        }

        /// <summary>RT-137.2 認証の要求（AssertionOptions）が組み立てられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT13702_認証の要求が組み立てられる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-137.2",
                    "サインイン画面が、AssertionOptions を組み立てて返す",
                    "**`GetAssertionOptions` も 4.x で引数オブジェクトになった**"
                    + "（`GetAssertionOptionsParams`）。"
                    + "**1.x では `UserVerificationRequirement.Discouraged` 固定で、"
                    + "画面の指定を捨てていた**ので、**渡るようにした。**"
                    + "**net48 版は、サインイン画面に WebAuthn のボタンを出さない。**",
                    "W3C WebAuthn Level 2 §5.5 / fido2-net-lib 4.2.0 / #137");

                r.Target("POST /Account/Login（submitButtonName=webauthn_signin / SequenceNo=0）");

                bool isCore = (targetKey == TestEnv.CoreKey);

                r.Step("(1) サインイン画面に WebAuthn のボタンが在るかを見る");

                string login = await client.GetStringAsync("/Account/Login");

                bool hasButton = !string.IsNullOrEmpty(login)
                    && login.Contains("webauthn_signin");

                if (!isCore)
                {
                    r.Verify("net48 版にはボタンが無い", !hasButton,
                        "無い", hasButton ? "**在る**" : "無い");

                    r.Note("**net48 版では WebAuthn を退役させた**（#137。RT-137.1 の Note と同じ理由）。");

                    r.Done();
                    return;
                }

                r.Verify("net10.0 版にはボタンが在る", hasButton,
                    "在る", hasButton ? "在る" : "**無い**");

                Assert.True(hasButton, "前提: 設定が webauthn で、ボタンが出ていること");

                r.Step("(2) 利用者名を送って、options を受け取る");

                string html = await client.WebAuthnAssertionOptionsAsync(
                    TestEnv.TestUserName(targetKey), "required");

                r.Verify("応答が返る", html != null, "返る", (html != null) ? "返った" : "**返らない**");

                Assert.NotNull(html);

                string sequenceNo = Html.FieldValue(html, "SequenceNo");

                r.VerifyEqual("段階が 1 へ進む", "1", sequenceNo ?? "(無し)");

                string json = Html.FieldValue(html, "Fido2Data");

                r.Verify("options が隠しフィールドに入る", !string.IsNullOrEmpty(json),
                    "入る", string.IsNullOrEmpty(json) ? "**空**" : "入っている");

                Assert.False(string.IsNullOrEmpty(json), "前提: options が返ること");

                JsonElement o = JsonDocument.Parse(json).RootElement;

                string status = o.TryGetProperty("status", out JsonElement st)
                    ? st.GetString() : "";

                r.VerifyEqual("status が ok", "ok", status);

                if (status != "ok")
                {
                    r.Note("**errorMessage: "
                        + (o.TryGetProperty("errorMessage", out JsonElement em)
                            ? em.GetString() : "(無し)") + "**");
                }

                Assert.Equal("ok", status);

                r.Verify("challenge がある",
                    o.TryGetProperty("challenge", out JsonElement ch)
                        && !string.IsNullOrEmpty(ch.GetString()),
                    "ある", o.TryGetProperty("challenge", out JsonElement ch2)
                        ? ("長さ " + (ch2.GetString() ?? "").Length + " 文字（base64url）") : "**無い**");

                r.Verify("rpId がある",
                    o.TryGetProperty("rpId", out JsonElement rpid)
                        && !string.IsNullOrEmpty(rpid.GetString()),
                    "ある", o.TryGetProperty("rpId", out JsonElement rpid2)
                        ? rpid2.GetString() : "**無い**");

                string uv = o.TryGetProperty("userVerification", out JsonElement u)
                    ? u.GetString() : "(無し)";

                r.VerifyEqual("userVerification に画面の指定が渡る", "required", uv);

                r.Note("**`allowCredentials` は空である**（この利用者は認証器を登録していない）。"
                    + "**登録には実際の認証器が要る**ので、**この基盤では踏めない。**");

                r.Done();
            }
        }

        /// <summary>RT-137.3 壊れた attestation は、エラーとして返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT13703_壊れた入力はエラーとして返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-137.3",
                    "壊れた attestation を送っても、例外が画面に漏れない",
                    "**4.x は失敗を `Fido2VerificationException` で返す**"
                    + "（`Status` を持たない形になった）。"
                    + "**封筒の `status` が `error` になり、HTTP 500 にならないこと**を見る。"
                    + "**JSON の直列化が System.Text.Json に変わった**ので、"
                    + "**形の違う JSON は `JsonException` で落ちる。** それも封筒に入る必要がある。",
                    "fido2-net-lib 4.2.0 / #137");

                r.Target("POST /Manage/AddWebAuthnData（sequenceNo=1 / 壊れた JSON）");

                r.Step("(1) 段階 0 を通して、段階 1 のトークンを得る");

                string step0 = await client.WebAuthnCreationOptionsAsync(
                    TestEnv.TestUserName(targetKey));

                r.Verify("段階 0 が通る", step0 != null,
                    "通る", (step0 != null) ? "通った" : "**通らない**");

                Assert.NotNull(step0);

                r.Step("(2) 段階 1 に、attestation ではない JSON を送る");

                string html = await client.WebAuthnAttestationAsync(step0, "{\"id\":\"x\"}");

                r.Verify("画面が返る（500 ではない）", html != null,
                    "返る", (html != null) ? "返った" : "**返らない**");

                Assert.NotNull(html);

                string json = Html.FieldValue(html, "fido2Data");

                r.Verify("結果が隠しフィールドに入る", !string.IsNullOrEmpty(json),
                    "入る", string.IsNullOrEmpty(json) ? "**空**" : "入っている");

                Assert.False(string.IsNullOrEmpty(json), "前提: 結果が返ること");

                JsonElement o = JsonDocument.Parse(json).RootElement;

                string status = o.TryGetProperty("status", out JsonElement st)
                    ? st.GetString() : "";

                r.VerifyEqual("status が error", "error", status);

                string message = o.TryGetProperty("errorMessage", out JsonElement em)
                    ? em.GetString() : "";

                r.Verify("理由が入る", !string.IsNullOrEmpty(message),
                    "入る", string.IsNullOrEmpty(message) ? "**空**" : "入っている");

                r.Note("**画面を白くしない**のが要点である。"
                    + "**net48 版は `customErrors` が例外を 302 に変える**ため、"
                    + "**「未認証のリダイレクト」と見分けがつかなくなる**（#272 で踏んだ）。"
                    + "**net10.0 版は 500 になる**ので、**封筒に入れて 200 で返す。**");

                r.Done();
            }
        }

        /// <summary>RT-137.4 challenge は要求ごとに変わる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT13704_challengeは要求ごとに変わる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-137.4",
                    "challenge は要求ごとに作り直される（使い回さない）",
                    "**challenge は再生攻撃を防ぐためのもの**なので、"
                    + "**要求ごとに新しい値でなければならない**（W3C WebAuthn §13.4.3）。"
                    + "**`Fido2Configuration.ChallengeSize` の既定は 16 バイト**で、"
                    + "**`RequestNewCredential` が毎回作る。**"
                    + "**セッションに置いた値を使い回していないこと**を、2 回取って確かめる。",
                    "W3C WebAuthn Level 2 §13.4.3 / #137");

                r.Target("POST /Manage/AddWebAuthnData（sequenceNo=0）を 2 回");

                r.Step("(1) options を 2 回取る");

                string first = Html.FieldValue(
                    await client.WebAuthnCreationOptionsAsync(TestEnv.TestUserName(targetKey)),
                    "fido2Data");
                string second = Html.FieldValue(
                    await client.WebAuthnCreationOptionsAsync(TestEnv.TestUserName(targetKey)),
                    "fido2Data");

                r.Verify("2 回とも返る",
                    !string.IsNullOrEmpty(first) && !string.IsNullOrEmpty(second),
                    "返る",
                    (!string.IsNullOrEmpty(first) && !string.IsNullOrEmpty(second))
                        ? "返った" : "**返らない**");

                Assert.False(string.IsNullOrEmpty(first));
                Assert.False(string.IsNullOrEmpty(second));

                string c1 = JsonDocument.Parse(first).RootElement
                    .GetProperty("challenge").GetString();
                string c2 = JsonDocument.Parse(second).RootElement
                    .GetProperty("challenge").GetString();

                r.Step("(2) challenge が違うことを確かめる");

                r.Verify("challenge が違う", c1 != c2,
                    "違う", (c1 != c2) ? "違う" : "**同じ**（使い回している）");

                r.Verify("16 バイト分の長さがある（base64url で 22 文字）",
                    (c1 ?? "").Length >= 22,
                    "22 文字以上", ((c1 ?? "").Length) + " 文字");

                r.Note("**値そのものは出さない。** 長さだけを記録する。");

                r.Done();
            }
        }
    }
}
