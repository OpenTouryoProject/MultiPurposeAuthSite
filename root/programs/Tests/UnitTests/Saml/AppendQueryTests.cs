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
//* クラス名        ：AppendQueryTests
//* クラス日本語名  ：Redirect Binding の送り先の URL にクエリ文字列を足す
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規作成（#393）
//**********************************************************************************

using MultiPurposeAuthSite.SamlProviders;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Saml
{
    /// <summary>
    /// CmnSaml2Response.AppendQuery。**SAML2 の ID 連携の要求（上流の SSO の口）と、IdP の役の Redirect Binding の応答（SP の ACS URL）が使う**（#393）。
    /// **E2E の上流・SP の URL はクエリを持たない**ので、組み立てだけをここで確かめる。
    /// </summary>
    public class AppendQueryTests
    {
        /// <summary>クエリを持たない送り先には ? でつなぐ</summary>
        [Fact]
        [Basis("SAML Bindings §3.4.4.1 / #393")]
        public void クエリを持たない送り先にはクエスチョンでつなぐ()
        {
            Assert.Equal("https://idp.example/sso?SAMLRequest=abc",
                CmnSaml2Response.AppendQuery("https://idp.example/sso", "SAMLRequest=abc"));
        }

        /// <summary>クエリを持つ送り先には &amp; でつなぐ（? を重ねない）</summary>
        [Fact]
        [Basis("SAML Bindings §3.4.4.1 / #393")]
        public void クエリを持つ送り先にはアンドでつなぐ()
        {
            Assert.Equal("https://idp.example/sso?tenant=a&SAMLRequest=abc",
                CmnSaml2Response.AppendQuery("https://idp.example/sso?tenant=a", "SAMLRequest=abc"));
        }

        /// <summary>送り先が ? か &amp; で終わっていれば、区切りを重ねない</summary>
        [Theory]
        [Basis("設計：CmnSaml2Response.AppendQuery のコメント（区切りを重ねない）/ #393")]
        [InlineData("https://sp.example/acs?", "https://sp.example/acs?SAMLResponse=abc")]
        [InlineData("https://sp.example/acs?x=1&", "https://sp.example/acs?x=1&SAMLResponse=abc")]
        public void 区切りで終わる送り先には区切りを重ねない(string url, string expected)
        {
            Assert.Equal(expected, CmnSaml2Response.AppendQuery(url, "SAMLResponse=abc"));
        }

        /// <summary>足すものが空なら、送り先をそのまま返す</summary>
        [Fact]
        [Basis("設計：CmnSaml2Response.AppendQuery のコメント（足すものが空なら、送り先をそのまま返す）")]
        public void 足すものが空なら送り先をそのまま返す()
        {
            Assert.Equal("https://sp.example/acs?x=1", CmnSaml2Response.AppendQuery("https://sp.example/acs?x=1", ""));
        }
    }
}
