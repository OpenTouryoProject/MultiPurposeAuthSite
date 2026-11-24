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
//* クラス名        ：ClientDisplayTests
//* クラス日本語名  ：ClientDisplay の単体テスト（承認の画面に出す URL の絞り込み）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規作成（#427）
//*  2026/11/24  玄人 幸道         見えない文字の判定を足した（#430）
//**********************************************************************************

using MultiPurposeAuthSite.Util.Sts;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `ClientDisplay`（E2E は登録した値が画面に出ること・出ないことを測り、ここで URL の境界を測る）
    /// </summary>
    public class ClientDisplayTests
    {
        /// <summary>https の絶対 URI は、正規化して通す</summary>
        /// <param name="value">登録された値</param>
        /// <param name="expected">出す値</param>
        [Theory]
        [Basis("OIDC Registration 1.0 §2 / #427（設計：ClientDisplay の remarks）")]
        [InlineData("https://rp.example.com/logo.png", "https://rp.example.com/logo.png")]
        [InlineData("HTTPS://RP.example.com/logo.png", "https://rp.example.com/logo.png")]
        [InlineData("  https://rp.example.com/policy  ", "https://rp.example.com/policy")]
        [InlineData("https://rp.example.com:8443/tos?lang=ja", "https://rp.example.com:8443/tos?lang=ja")]
        public void httpsの絶対URIは通す(string value, string expected)
        {
            Assert.Equal(expected, ClientDisplay.HttpsOnly(value));
        }

        /// <summary>https でない・絶対でない・利用者情報を持つ値は通さない</summary>
        /// <param name="value">登録された値</param>
        [Theory]
        [Basis("OIDC Registration 1.0 §2 / #427（設計：ClientDisplay の remarks）")]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("http://rp.example.com/logo.png")]
        [InlineData("javascript:alert(427)")]
        [InlineData("data:text/html,tos")]
        [InlineData("ftp://rp.example.com/tos")]
        [InlineData("//rp.example.com/logo.png")]
        [InlineData("/logo.png")]
        [InlineData("https://user:pw@rp.example.com/policy")]
        [InlineData("https://trusted.example.com@evil.example.com/tos")]
        public void httpsの絶対URIでなければ通さない(string value)
        {
            Assert.Null(ClientDisplay.HttpsOnly(value));
        }

        /// <summary>見えない文字（Cc・Cf・Zl・Zp）を含む名前を見分ける</summary>
        /// <param name="value">名前</param>
        /// <param name="expected">含むか</param>
        [Theory]
        [Basis("#430（設計：ClientDisplay.HasInvisibleCharacter の remarks。別モデルのレビューの指摘）")]
        [InlineData("E2E RP <430> & 表示名", false)]
        [InlineData("abc\u202Edef", true)]
        [InlineData("abc\u2066def", true)]
        [InlineData("abc\u200Bdef", true)]
        [InlineData("abc\uFEFFdef", true)]
        [InlineData("abc\u00ADdef", true)]
        [InlineData("abc\u2028def", true)]
        [InlineData("abc\ndef", true)]
        [InlineData("abc\tdef", true)]
        public void 見えない文字を含む名前を見分ける(string value, bool expected)
        {
            Assert.Equal(expected, ClientDisplay.HasInvisibleCharacter(value));
        }

        /// <summary>ReturnUrl が同じサイトの相対パスでなければ、クライアントを引かない</summary>
        /// <param name="returnUrl">ReturnUrl</param>
        [Theory]
        [Basis("#427（設計：ClientDisplay.FromReturnUrl の remarks。別モデルのレビューの指摘）")]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("https://evil.example.com/authorize?client_id=x")]
        [InlineData("//evil.example.com/authorize?client_id=x")]
        [InlineData("/\\evil.example.com/authorize?client_id=x")]
        [InlineData("authorize?client_id=x")]
        public void ReturnUrlが同じサイトの相対パスでなければ出さない(string returnUrl)
        {
            Assert.Null(ClientDisplay.FromReturnUrl(returnUrl));
        }
    }
}
