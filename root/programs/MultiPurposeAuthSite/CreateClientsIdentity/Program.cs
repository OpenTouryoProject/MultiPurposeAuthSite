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
//* クラス名        ：CreateClientsIdentity.Program
//* クラス日本語名  ：Client情報の生成ツール（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Touryo.Infrastructure.Public.Util;

namespace CreateClientsIdentity
{
    class Program
    {
        static void Main(string[] args)
        {
            Dictionary<string, Dictionary<string, string>> obj
                = new Dictionary<string, Dictionary<string, string>>();
            
            for (int i = 0; i < 5; i++)
            {
                obj.Add(
                    Guid.NewGuid().ToString("N"),
                    new Dictionary<string, string>()
                    {
                        {"client_secret", GetPassword.Base64UrlSecret(32)},
                        { "redirect_uri_code", "http://hogehoge" + i.ToString() + "/aaa"},
                        { "redirect_uri_token", "http://hogehoge" + i.ToString() + "/bbb"},
                        { "client_name", "hogehoge" + i.ToString()}
                    });
            }

            string json = JsonConvert.SerializeObject(obj, Formatting.Indented);
            Console.WriteLine(json);

            //obj = JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, string>>>(json);
            //json = Console.ReadLine();
        }
    }
}
