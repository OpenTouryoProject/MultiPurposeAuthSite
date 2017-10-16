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
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.FIDO2Extension
{
    /// <summary>FIDO2Helper（ライブラリ）</summary>
    public class FIDO2Helper
    {
        private string PublicKey = "";
        private string Challenge = "";

        /// <summary>constructor</summary>
        /// <param name="publicKey">string</param>
        /// <param name="challenge">string</param>
        public FIDO2Helper(string publicKey, string challenge)
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

            Debug.WriteLine("publicKey: " + this.PublicKey);
            Debug.WriteLine("challenge: " + this.Challenge);
            Debug.WriteLine("clientData: " + clientData);
            Debug.WriteLine("authenticatorData: " + authenticatorData);
            Debug.WriteLine("signature: " + signature);

            byte[] clientDataBytes = this.FromBase64Url(clientData);
            byte[] authenticatorDataBytes = this.FromBase64Url(authenticatorData);
            byte[] signatureBytes = this.FromBase64Url(signature);

            // Challengeの一致を確認する。
            JObject clientJson = JObject.Parse(//Encoding.ASCII.GetString(clientDataBytes));
                Encoding.ASCII.GetString(clientDataBytes).Replace("\0", "").Trim());

            if ((string)clientJson["challenge"] == this.Challenge)
            {
                // Challengeの一致

                // Load public key
                JObject jwk = JObject.Parse(this.PublicKey);

                if (jwk["alg"].ToString().ToLower() == "rs256")
                {
                    // RSAParameters
                    RSAParameters rsaParameters = new RSAParameters();
                    string modulus = (string)jwk["n"]; // JWK - ...
                    string exponent = (string)jwk["e"]; // JWK - Key
                    Debug.WriteLine("modulus: " + modulus);
                    Debug.WriteLine("exponent: " + exponent);

                    // VerifyData
                    byte[] hashBytes = null;
                    byte[] data = null;

                    // ----------

                    // FromBase64Stringだとエラーになる。

                    //// ModulusとExponentを指定してRSAで暗号化/復号する（.NET） - misc.log
                    //// http://backyard.hatenablog.com/entry/20161219/1482146423
                    //// java - How to get public RSA key from unformatted String - Stack Overflow
                    //// https://stackoverflow.com/questions/28204659/how-to-get-public-rsa-key-from-unformatted-string

                    // RSAParameters
                    // FromBase64Stringだとエラーになる。
                    //rsaParameters = new RSAParameters
                    //{
                    //    Modulus = CustomEncode.FromBase64String(modulus),
                    //    Exponent = CustomEncode.FromBase64String(exponent),
                    //};
                    rsaParameters = new RSAParameters
                    {
                        Modulus = this.FromBase64Url(modulus), //CustomEncode.FromBase64UrlString(modulus),
                        Exponent = this.FromBase64Url(exponent), //CustomEncode.FromBase64UrlString(exponent),
                    };

                    hashBytes = GetHash.GetHashBytes(clientDataBytes, EnumHashAlgorithm.SHA256Managed, 0);
                    data = authenticatorDataBytes.Concat(hashBytes).ToArray();

                    Debug.WriteLine("hashBytes : " + CustomEncode.ToHexString(hashBytes));
                    Debug.WriteLine("data : " + CustomEncode.ToHexString(data));

                    RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                    rsaCryptoServiceProvider.ImportParameters(rsaParameters);
                    ret = rsaCryptoServiceProvider.VerifyData(
                        data, signatureBytes,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    Debug.WriteLine("ret : " + ret);
                    
                    #region ゴミ

                    // Hash data with sha-256
                    SHA256Managed sha256Managed = new SHA256Managed();
                    hashBytes = sha256Managed.ComputeHash(clientDataBytes);

                    // Create "authnrData + hash" data buffer to verify signature over
                    data = new byte[authenticatorDataBytes.Length + hashBytes.Length];
                    authenticatorDataBytes.CopyTo(data, 0);
                    hashBytes.CopyTo(data, authenticatorDataBytes.Length);

                    Debug.WriteLine("hashBytes1: " + CustomEncode.ToHexString(hashBytes));
                    Debug.WriteLine("data1: " + CustomEncode.ToHexString(data));

                    // Verify signature is correct for authnrData + hash by RSACng.
                    RSACng rsaCng = new RSACng();
                    rsaCng.ImportParameters(rsaParameters);
                    ret = rsaCng.VerifyData(
                        data, signatureBytes,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    
                    Debug.WriteLine("ret1: " + ret);

                    // ----------

                    // Hash data with sha-256
                    SHA256 sha256 = SHA256.Create();
                    hashBytes = sha256.ComputeHash(clientDataBytes);

                    // Create "authnrData + hash" data buffer to verify signature over
                    data = authenticatorDataBytes.Concat(hashBytes).ToArray();

                    Debug.WriteLine("hashBytes2: " + CustomEncode.ToHexString(hashBytes));
                    Debug.WriteLine("data2: " + CustomEncode.ToHexString(data));
                    
                    // Verify signature is correct for authnrData + hash by RSACng.
                    RSA rsa = RSA.Create();
                    rsa.ImportParameters(rsaParameters);
                    ret = rsa.VerifyData(
                        data, signatureBytes,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    Debug.WriteLine("ret2: " + ret);

                    #endregion
                }

                return ret;
            }
            else
            {
                // Challengeの不一致
                return false;
            }
        }

        /// <summary>rfc4648_base64_url_decode</summary>
        /// <param name="url">url</param>
        /// <returns>decoded</returns>
        private byte[] FromBase64Url(string url)
        {
            url = url.Replace('-', '+');
            url = url.Replace('_', '/');

            switch (url.Length % 4)
            {

                case 0:
                    break;

                case 2:
                    url += "==";
                    break;

                case 3:
                    url += "=";
                    break;

                default:
                    throw new ArgumentException();
            }

            return Convert.FromBase64String(url);
        }
    }
}