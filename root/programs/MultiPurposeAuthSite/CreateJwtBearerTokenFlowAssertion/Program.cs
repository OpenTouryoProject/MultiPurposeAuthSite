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
//**********************************************************************************

using System;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Str;

namespace CreateJwtBearerTokenFlowAssertion
{
    class Program
    {
        static void Main(string[] args)
        {
            string iss = OAuth2AndOIDCParams.Isser;
            string aud = OAuth2AndOIDCParams.Audience;

            string scopes = "hoge1 hoge2 hoge3";
            JObject jobj = null;

            JWT_RS256_XML jwt_RS256 = new JWT_RS256_XML();

            Console.WriteLine("PrivateKey:");
            Console.WriteLine(CustomEncode.ToBase64String(
                CustomEncode.StringToByte(jwt_RS256.XMLPrivateKey, CustomEncode.us_ascii)));
            Console.WriteLine("");

            Console.WriteLine("PublicKey:");
            Console.WriteLine(CustomEncode.ToBase64String(
                CustomEncode.StringToByte(jwt_RS256.XMLPublicKey, CustomEncode.us_ascii)));
            Console.WriteLine("");

            string jwtAssertion = JwtAssertion.CreateJwtBearerTokenFlowAssertion(
                OAuth2AndOIDCParams.Isser,
                OAuth2AndOIDCParams.Audience,
            new System.TimeSpan(0, 30, 0), scopes,
                jwt_RS256.XMLPrivateKey);

            if (JwtAssertion.VerifyJwtBearerTokenFlowAssertion(
                jwtAssertion, out iss, out aud, out scopes, out jobj, jwt_RS256.XMLPublicKey))
            {
                if (iss == OAuth2AndOIDCParams.Isser
                    && aud == OAuth2AndOIDCParams.Audience)
                {
                    Console.WriteLine("JwtAssertion:");
                    Console.WriteLine(jwtAssertion);
                    Console.WriteLine("");

                    Console.ReadLine();

                    return;
                }
            }

            Console.WriteLine("Error");
            Console.ReadLine();
        }
    }
}
