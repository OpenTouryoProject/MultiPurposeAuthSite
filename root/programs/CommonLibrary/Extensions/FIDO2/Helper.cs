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
//* クラス名        ：FIDO2Helper
//* クラス日本語名  ：FIDO2Helper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/10/16  西野 大介         新規
//**********************************************************************************

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
//using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Extensions.FIDO2
{
    /// <summary>FIDO2Helper（ライブラリ）</summary>
    public class Helper
    {
        private string PublicKey = "";
        private string Challenge = "";

        /// <summary>constructor</summary>
        /// <param name="publicKey">string</param>
        /// <param name="challenge">string</param>
        public Helper(string publicKey, string challenge)
        {
            this.PublicKey = publicKey;
            this.Challenge = challenge;
        }

        /// <summary>ValidateSignature</summary>
        
        /// <param name="clientData">string</param>
        /// <param name="authenticatorData">string</param>
        /// <param name="signature">string</param>
        /// <returns>
        /// true  : valid
        /// false : invalid
        /// </returns>
        public bool ValidateSignature(
            string clientData, string authenticatorData, string signature)
        {
            bool ret = false;

            byte[] clientDataBytes = CustomEncode.FromBase64UrlString(clientData);
            byte[] authenticatorDataBytes = CustomEncode.FromBase64UrlString(authenticatorData);
            byte[] signatureBytes = CustomEncode.FromBase64UrlString(signature);

            // Challengeの一致を確認する。
            JObject clientJson = JObject.Parse(//Encoding.ASCII.GetString(clientDataBytes));
                Encoding.ASCII.GetString(clientDataBytes).Replace("\0", "").Trim());

            byte[] hashBytes = null;
            byte[] data = null;
            hashBytes = GetHash.GetHashBytes(clientDataBytes, EnumHashAlgorithm.SHA256_M, 0);
            data = authenticatorDataBytes.Concat(hashBytes).ToArray();

            if ((string)clientJson["challenge"] == this.Challenge)
            {
                // Challengeの一致

                // Load public key
                RSACryptoServiceProvider rsaCryptoServiceProvider =
                    (RSACryptoServiceProvider)RsaPublicKeyConverter.JwkToProvider(this.PublicKey);
                
                // VerifyData
                ret = rsaCryptoServiceProvider.VerifyData(
                    data, signatureBytes,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return ret;
            }
            else
            {
                // Challengeの不一致
                return false;
            }
        }
    }
}