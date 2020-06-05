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
//* クラス名        ：CreateJwtBearerTokenFlowAssertion.Program
//* クラス日本語名  ：Jwt Bearer Token FlowのJwt Assertion生成ツール（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/12/25  西野 大介         新規
//*  2018/11/27  西野 大介         XML(Base64) ---> Jwk(Base64Url)に変更。
//*  2019/02/13  西野 大介         自動生成から、証明書利用に変更。
//*  2020/03/04  西野 大介         CIBA対応（ECDsaのJwt Assertion生成）
//**********************************************************************************

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace CreateJwtBearerTokenFlowAssertion
{
    class Program
    {
        static void Main(string[] args)
        {
#if NETCORE
            // configの初期化
            GetConfigParameter.InitConfiguration("appsettings.json");
#endif

            string jwkPrivateKey = "";
            string jwkPublicKey = "";
            string jwtAssertion = "";

            string iss = CmnClientParams.Isser;
            string aud = OAuth2AndOIDCParams.Audience;
            string scopes = "hoge1 hoge2 hoge3";
            JObject jobj = null;

            #region RS256
            DigitalSignX509 dsX509_RS256 = new DigitalSignX509(
                CmnClientParams.RsaPfxFilePath,
                CmnClientParams.RsaPfxPassword, HashAlgorithmName.SHA256);

            #region PrivateKey
            Console.WriteLine("PrivateKey(RS256):");

            RsaPrivateKeyConverter rpvkc = new RsaPrivateKeyConverter(JWS_RSA.RS._256);
            jwkPrivateKey = rpvkc.ParamToJwk(((RSA)dsX509_RS256.AsymmetricAlgorithm).ExportParameters(true));
            jwkPrivateKey = CustomEncode.ToBase64UrlString(CustomEncode.StringToByte(jwkPrivateKey, CustomEncode.us_ascii));

            Console.WriteLine(jwkPrivateKey);
            Console.WriteLine("");
            #endregion

            #region PublicKey
            Console.WriteLine("PublicKey(RS256):");

            RsaPublicKeyConverter rpbkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
            jwkPublicKey = rpbkc.ParamToJwk(((RSA)dsX509_RS256.AsymmetricAlgorithm).ExportParameters(false));
            jwkPublicKey = CustomEncode.ToBase64UrlString(CustomEncode.StringToByte(jwkPublicKey, CustomEncode.us_ascii));

            Console.WriteLine(jwkPublicKey);
            Console.WriteLine("");
            #endregion

            #region Check
            jwtAssertion = JwtAssertion.Create(
                CmnClientParams.Isser, OAuth2AndOIDCParams.Audience, new TimeSpan(0, 30, 0), scopes,
                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwkPrivateKey), CustomEncode.us_ascii));

            if (JwtAssertion.Verify(
                jwtAssertion, out iss, out aud, out scopes, out jobj,
                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwkPublicKey), CustomEncode.us_ascii)))
            {
                if (iss == CmnClientParams.Isser
                    && aud == OAuth2AndOIDCParams.Audience)
                {
                    Console.WriteLine("JwtAssertion(RS256):");
                    Console.WriteLine(jwtAssertion);
                    Console.WriteLine("");
                }
            }

            #endregion

            #endregion

            #region ES256
            DigitalSignECDsaX509 dsX509_ES256 = new DigitalSignECDsaX509(
                CmnClientParams.EcdsaPfxFilePath,
                CmnClientParams.EcdsaPfxPassword, HashAlgorithmName.SHA256);

            #region PrivateKey
            // ECDsa.ExportParameters(true)が動かないので実行不可能。
            //Console.WriteLine("PrivateKey(ES256):");

            //EccPrivateKeyConverter epvkc = new EccPrivateKeyConverter(JWS_ECDSA.ES._256);
            //jwkPrivateKey = epvkc.ParamToJwk(((ECDsa)dsX509_ES256.AsymmetricAlgorithm).ExportParameters(true));
            //jwkPrivateKey = CustomEncode.ToBase64UrlString(CustomEncode.StringToByte(jwkPrivateKey, CustomEncode.us_ascii));

            //Console.WriteLine(jwkPrivateKey);
            //Console.WriteLine("");
            #endregion

            #region PublicKey
            Console.WriteLine("PublicKey(ES256):");

            EccPublicKeyConverter epbkc = new EccPublicKeyConverter(JWS_ECDSA.ES._256);
            jwkPublicKey = epbkc.ParamToJwk(((ECDsa)dsX509_ES256.AsymmetricAlgorithm).ExportParameters(false));
            jwkPublicKey = CustomEncode.ToBase64UrlString(CustomEncode.StringToByte(jwkPublicKey, CustomEncode.us_ascii));

            Console.WriteLine(jwkPublicKey);
            Console.WriteLine("");
            #endregion

            #region Check

            jwtAssertion = JwtAssertion.CreateByECDsa(
                CmnClientParams.Isser, OAuth2AndOIDCParams.Audience, new TimeSpan(0, 30, 0), scopes,
                CmnClientParams.EcdsaPfxFilePath, CmnClientParams.EcdsaPfxPassword);
                //CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwkPrivateKey), CustomEncode.us_ascii));

            if (JwtAssertion.Verify(
                jwtAssertion, out iss, out aud, out scopes, out jobj,
                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwkPublicKey), CustomEncode.us_ascii)))
            {
                if (iss == CmnClientParams.Isser
                    && aud == OAuth2AndOIDCParams.Audience)
                {
                    Console.WriteLine("JwtAssertion(ES256):");
                    Console.WriteLine(jwtAssertion);
                    Console.WriteLine("");
                }
            }

            #endregion

            #endregion

            Console.ReadLine();
        }
    }
}
