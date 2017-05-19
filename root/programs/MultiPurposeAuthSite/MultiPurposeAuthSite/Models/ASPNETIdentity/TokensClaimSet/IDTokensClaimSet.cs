//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：IDTokensClaimSet
//* クラス日本語名  ：IDトークン生成用（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************;

using Newtonsoft.Json;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.TokensClaimSet</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokensClaimSet
{
    /// <summary>IDTokensClaimSet</summary>
    public class IDTokensClaimSet
    {
        /// <summary>
        /// issuer
        /// AuthorizationServerの識別子（URI形式が推奨）
        /// </summary>
        [JsonProperty(PropertyName = "iss")]
        public string Issuer = "";

        /// <summary>
        /// audience
        /// クライアント識別子
        /// </summary>
        [JsonProperty(PropertyName = "aud")]
        public string Audience = "";

        /// <summary>
        /// subject
        /// ユーザーID
        /// </summary>

        [JsonProperty(PropertyName = "sub")]
        public string Subject = "";

        /// <summary>
        /// issued at
        /// 発行日時（Unix時間）
        /// </summary>
        [JsonProperty(PropertyName = "iat")]
        public string IssuedAt = "";

        /// <summary>
        /// expiration time
        /// 有効期限（Unix時間）
        /// </summary>
        [JsonProperty(PropertyName = "exp")]
        public string ExpirationTime = "";

        /// <summary>
        /// nonce（CSRF対策）
        /// </summary>
        [JsonProperty(PropertyName = "nonce")]
        public string Nonce = "";

        /// <summary>メアド</summary>
        [JsonProperty(PropertyName = "email")]
        public string Email = "";


    }
}