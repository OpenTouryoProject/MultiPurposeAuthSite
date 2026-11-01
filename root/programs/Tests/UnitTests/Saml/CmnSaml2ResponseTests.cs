//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：CmnSaml2ResponseTests
//* クラス日本語名  ：SAML2 の応答の理由
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.SamlProviders;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Saml
{
    /// <summary>
    /// CmnSaml2Response。**`SAML2VerifyResult` は外から作れない**（Open棟梁 の検証だけが作る）ので、
    /// **値の無い応答の文面（`OrNone`）は、ここでは確かめられない**（`COVERAGE.md`）。
    /// </summary>
    public class CmnSaml2ResponseTests
    {
        /// <summary>検証の結果が無ければ、成功と出さない</summary>
        [Fact]
        [Basis("設計：CmnSaml2Response.VerdictOf のコメント（認証の判断には IsValid だけを使う）")]
        public void 検証の結果が無ければ成功と出さない()
        {
            Assert.NotEqual(Const.VerdictNormalEnd, CmnSaml2Response.VerdictOf(null));
        }
    }
}
