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
//* クラス名        ：CmnDPoPNonceTests
//* クラス日本語名  ：DPoP の nonce
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using MultiPurposeAuthSite.Extensions.Sts;

using Touryo.Infrastructure.Public.Util;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// DPoP の nonce（E2E の通しの既定では通らない。`-DPoPNonce` で起動したときだけ）
    /// </summary>
    public class CmnDPoPNonceTests
    {
        /// <summary>設定（nonce を要求する配備）</summary>
        public CmnDPoPNonceTests()
        {
            GetConfigParameter.InitConfiguration(new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>
                {
                    { "appSettings:EnableDPoPNonce", "true" }
                })
                .Build());
        }

        /// <summary>用途が違えば nonce も違う</summary>
        [Fact]
        [Basis("#311（設計：CmnDPoP.PurposeAs のコメント）")]
        public void 用途が違えばnonceも違う()
        {
            Assert.NotEqual(
                CmnDPoP.CurrentNonce(CmnDPoP.PurposeAs),
                CmnDPoP.CurrentNonce(CmnDPoP.PurposeRs));
        }

        /// <summary>nonce は NQCHAR の文字だけでできている</summary>
        [Fact]
        [Basis("RFC 9449 §8.1（nonce = 1*NQCHAR）")]
        public void nonceは使える文字だけでできている()
        {
            Assert.Matches(@"^[\x21\x23-\x5B\x5D-\x7E]+$", CmnDPoP.CurrentNonce(CmnDPoP.PurposeAs));
        }

        /// <summary>DPoP スキームで来たら、チャレンジに nonce を載せる</summary>
        [Fact]
        [Basis("RFC 9449 §9（保護されたリソースの nonce）")]
        public void DPoPスキームならチャレンジにnonceを載せる()
        {
            Assert.False(string.IsNullOrEmpty(CmnDPoP.NonceForChallenge(true)));
        }

        /// <summary>Bearer で来たら、nonce を載せない</summary>
        [Fact]
        [Basis("#311（設計：CmnDPoP.NonceForChallenge のコメント）")]
        public void Bearerならチャレンジにnonceを載せない()
        {
            Assert.Null(CmnDPoP.NonceForChallenge(false));
        }
    }
}
