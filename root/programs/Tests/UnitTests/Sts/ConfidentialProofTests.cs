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
//* クラス名        ：ConfidentialProofTests
//* クラス日本語名  ：秘密を持つクライアントの証明か（refresh_token を DPoP の鍵に縛るかを決める）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規作成（#367）
//**********************************************************************************

using MultiPurposeAuthSite.TokenProviders;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// **秘密を持つクライアントの証明か**（`CmnEndpoints.IsConfidentialProof`）。
    /// **公開クライアントは `refresh_token` の経路で認証できない**ので、
    /// **「公開クライアントの refresh_token は縛る」側は E2E では通らない**（`TESTING.md`）。その前提を、ここで固定する。
    /// </summary>
    public class ConfidentialProofTests
    {
        /// <summary>資格情報で認証した証明は、秘密を持つクライアント</summary>
        /// <param name="proof">証明</param>
        [Theory]
        [InlineData(ClientModePolicy.Proof.ClientSecret)]
        [InlineData(ClientModePolicy.Proof.ClientSecretAndPkce)]
        [InlineData(ClientModePolicy.Proof.PrivateKeyJwt)]
        [InlineData(ClientModePolicy.Proof.Mtls)]
        [Basis("RFC 9449 §5（秘密を持つクライアントの refresh_token は縛らない）/ #367")]
        public void 資格情報で認証した証明は秘密を持つクライアント(ClientModePolicy.Proof proof)
        {
            Assert.True(CmnEndpoints.IsConfidentialProof(proof));
        }

        /// <summary>PKCE だけ・証明なしは、公開クライアント</summary>
        /// <param name="proof">証明</param>
        [Theory]
        [InlineData(ClientModePolicy.Proof.None)]
        [InlineData(ClientModePolicy.Proof.PkceS256)]
        [InlineData(ClientModePolicy.Proof.PkcePlain)]
        [InlineData(ClientModePolicy.Proof.Any)]
        [Basis("RFC 9449 §5（公開クライアントの refresh_token は縛る）/ #367")]
        public void PKCEだけや証明なしは公開クライアント(ClientModePolicy.Proof proof)
        {
            Assert.False(CmnEndpoints.IsConfidentialProof(proof));
        }
    }
}
