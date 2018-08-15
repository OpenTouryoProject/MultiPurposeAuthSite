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
using System.Text;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;

namespace CreateJwkSetJson
{
    class Program
    {
        static void Main(string[] args)
        {
            // 現在の証明書のJwk
            Dictionary<string, string> jwkObject = 
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    RS256_KeyConverter.X509CerToJwkPublicKey(OAuth2AndOIDCParams.RS256Cer));

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
            string jwkSetString = ResourceLoader.LoadAsString(
                OAuth2AndOIDCParams.JwkSetFilePath,
                Encoding.GetEncoding(CustomEncode.UTF_8));

            JwkSet jwkSetObject = new JwkSet();

            // 判定
            if (string.IsNullOrWhiteSpace(jwkSetString))
            {
                // 新規
                jwkSetObject.keys.Add(jwkObject);
            }
            else
            {
                // 既存
                jwkSetObject = JsonConvert.DeserializeObject<JwkSet>(jwkSetString);

                // kidの重複確認
                bool exist = false;
                foreach (Dictionary<string, string> key in jwkSetObject.keys)
                {
                    if (key["kid"] == jwkObject["kid"])
                    {
                        exist = true;
                    }
                }
                
                if (exist)
                {
                    // 既存
                    return; // 終了
                }
                else
                {
                    // 追加
                    jwkSetObject.keys.Add(jwkObject);
                }
            }

            // jwkSetObjectのセーブ
            using (StreamWriter sr = File.CreateText(OAuth2AndOIDCParams.JwkSetFilePath))
            {
                sr.Write(
                    JsonConvert.SerializeObject(
                        jwkSetObject,
                        new JsonSerializerSettings
                        {
                            Formatting = Formatting.Indented,
                            ContractResolver = new CamelCasePropertyNamesContractResolver()
                        }));
            }
        }
    }
}
