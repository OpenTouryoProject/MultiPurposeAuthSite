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
//* クラス名        ：FrontChannelLogoutTests
//* クラス日本語名  ：FrontChannelLogout の単体テスト（ログアウトの画面が進む先の絞り込み）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/25  玄人 幸道         新規作成（#426）
//**********************************************************************************

using MultiPurposeAuthSite.Extensions.Sts;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `FrontChannelLogout.ToContinueUrl`（画面がリンクと meta refresh に出す、進む先の境界を測る。#426）
    /// </summary>
    public class FrontChannelLogoutTests
    {
        /// <summary>http・https の絶対 URI と、同じサイトの相対パスは通す</summary>
        /// <param name="value">進む先</param>
        [Theory]
        [Basis("#426（設計：FrontChannelLogout.ToContinueUrl の remarks）")]
        [InlineData("https://rp.example.com/logged_out?state=s")]
        [InlineData("http://localhost:8080/logged_out")]
        [InlineData("http://intranet.example.local/out")]
        [InlineData("/")]
        [InlineData("/Home/Index")]
        [InlineData("/authorize?client_id=x&response_type=code")]
        public void httpとhttpsの絶対URIと同じサイトの相対パスは通す(string value)
        {
            Assert.Equal(value, FrontChannelLogout.ToContinueUrl(value));
        }

        /// <summary>それ以外のスキーム・ほかのホストへの相対の形は通さない</summary>
        /// <param name="value">進む先</param>
        [Theory]
        [Basis("#426（設計：FrontChannelLogout.ToContinueUrl の remarks）/ #427 と同じ考え方")]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("javascript:alert(426)")]
        [InlineData("JavaScript:alert(426)")]
        [InlineData("data:text/html,out")]
        [InlineData("vbscript:msgbox(426)")]
        [InlineData("ftp://rp.example.com/out")]
        [InlineData("com.example.app:/logged_out")]
        [InlineData("//evil.example.com/out")]
        [InlineData("/\\evil.example.com/out")]
        [InlineData("/\t/evil.example.com/out")]
        [InlineData("/\n/evil.example.com/out")]
        [InlineData("https://rp.example.com/out\r\n")]
        [InlineData("logged_out")]
        public void それ以外は通さない(string value)
        {
            Assert.Null(FrontChannelLogout.ToContinueUrl(value));
        }
    }
}
