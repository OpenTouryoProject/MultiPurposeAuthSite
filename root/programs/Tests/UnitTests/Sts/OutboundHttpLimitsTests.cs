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
//* クラス名        ：OutboundHttpLimitsTests
//* クラス日本語名  ：OP が外へ出す要求の、時間と大きさの上限（#375）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規作成（#375）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;

using MultiPurposeAuthSite.Network;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `OutboundHttpLimits`（E2E は大きさの上限で `jwks_uri` を読まないことを測る。`RT-375.1`）
    /// </summary>
    public class OutboundHttpLimitsTests
    {
        /// <summary>既定の上限は 30 秒・1MB</summary>
        [Fact]
        [Basis("#375（設計：OutboundHttpLimits の remarks）")]
        public void 既定の上限は30秒と1MB()
        {
            using (HttpClient client = OutboundHttpLimits.ApplyDefaults(new HttpClient()))
            {
                Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
                Assert.Equal(1024 * 1024, client.MaxResponseContentBufferSize);
            }
        }

        /// <summary>設定が無い・読めない・1 未満なら既定、正の値ならその値</summary>
        [Fact]
        [Basis("#375（設計：Config.OutboundHttpTimeoutSeconds・OutboundHttpMaxResponseBytes のコメント）")]
        public void 設定が無いか読めなければ既定で正の値ならその値()
        {
            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                using (HttpClient client = OutboundHttpLimits.ApplyConfigured(new HttpClient()))
                {
                    Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
                    Assert.Equal(1024 * 1024, client.MaxResponseContentBufferSize);
                }

                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "OutboundHttpTimeoutSeconds", "0" },
                    { "OutboundHttpMaxResponseBytes", "abc" }
                });

                using (HttpClient client = OutboundHttpLimits.ApplyConfigured(new HttpClient()))
                {
                    Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
                    Assert.Equal(1024 * 1024, client.MaxResponseContentBufferSize);
                }

                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "OutboundHttpTimeoutSeconds", "90" },
                    { "OutboundHttpMaxResponseBytes", "5242880" }
                });

                using (HttpClient client = OutboundHttpLimits.ApplyConfigured(new HttpClient()))
                {
                    Assert.Equal(TimeSpan.FromSeconds(90), client.Timeout);
                    Assert.Equal(5242880, client.MaxResponseContentBufferSize);
                }
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }
    }
}
