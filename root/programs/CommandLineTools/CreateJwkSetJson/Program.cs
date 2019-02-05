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
//* クラス名        ：CreateJwkSetJson
//* クラス日本語名  ：JWKSetJson情報の生成ツール（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/08/15  西野 大介         新規
//**********************************************************************************

using System.IO;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace CreateJwkSetJson
{
    class Program
    {
        static void Main(string[] args)
        {
#if NETCORE
            // configの初期化
            GetConfigParameter.InitConfiguration("appsettings.json");
#endif

            // 現在の証明書のJwk
            JObject rsaJwkObject = 
                JsonConvert.DeserializeObject<JObject>(
                    RsaPublicKeyConverter.X509CerToJwk(OAuth2AndOIDCParams.RS256Cer));
            JObject ecdsaJwkObject =
                JsonConvert.DeserializeObject<JObject>(
                    EccPublicKeyConverter.X509CerToJwk(OAuth2AndOIDCParams.ES256Cer, HashAlgorithmName.SHA256));

            // JwkSet.jsonファイルの存在チェック
            if (!ResourceLoader.Exists(OAuth2AndOIDCParams.JwkSetFilePath, false))
            {
                // 新規
                File.Create(OAuth2AndOIDCParams.JwkSetFilePath).Close();
            }
            else
            {
                // 既存？
            }

            // JwkSet.jsonファイルのロード
            JwkSet jwkSetObject = JwkSet.LoadJwkSet(OAuth2AndOIDCParams.JwkSetFilePath);

            // 判定
            if (jwkSetObject == null)
            {
                // 新規
                jwkSetObject = new JwkSet();
                jwkSetObject.keys.Add(rsaJwkObject);
                jwkSetObject.keys.Add(ecdsaJwkObject);
            }
            else
            {
                // 既存

                // kidの重複確認
                JwkSet.AddJwkToJwkSet(jwkSetObject, rsaJwkObject);
                JwkSet.AddJwkToJwkSet(jwkSetObject, ecdsaJwkObject);
            }

            // jwkSetObjectのセーブ
            JwkSet.SaveJwkSet(OAuth2AndOIDCParams.JwkSetFilePath, jwkSetObject);
        }
    }
}
