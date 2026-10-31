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
//* クラス名        ：CmnAccessToken
//* クラス日本語名  ：CmnAccessToken の 利用者の SecurityStamp（refresh_token の失効。C-54）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（CmnAccessToken.cs から partial に分割。#294）
//**********************************************************************************

using System;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken（利用者の SecurityStamp（refresh_token の失効。C-54））</summary>
    public partial class CmnAccessToken
    {
        #region SecurityStamp

        /// <summary>預ける refresh_token の payload に書く、利用者の SecurityStamp のハッシュの名前（#294）</summary>
        /// <remarks>
        /// **access_token には載せない**（`TakeSecurityStamp` で外してから `ProtectFromPayload` に渡す）。
        /// </remarks>
        private const string SecurityStampHashName = "urn:mpas:refresh_token:security_stamp";

        /// <summary>預ける payload に、利用者の SecurityStamp のハッシュを書く（#294）</summary>
        /// <param name="payload">access_token の payload（JSON の文字列）</param>
        /// <param name="securityStamp">利用者の SecurityStamp（**空なら書かない**）</param>
        /// <returns>書き換えた payload（読めなければ、受け取ったものをそのまま返す）</returns>
        /// <remarks>
        /// **パスワードの変更などで SecurityStamp が変わったら、refresh_token を使えなくする**ためである。
        /// **値そのものは書かない**（ハッシュにする。SecurityStamp は Cookie の検証にも使う値である）。
        /// </remarks>
        public static string BindSecurityStamp(string payload, string securityStamp)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return payload;
            }

            try
            {
                JObject jobj = (JObject)JsonConvert.DeserializeObject(payload);

                if (jobj == null)
                {
                    return payload;
                }

                if (string.IsNullOrEmpty(securityStamp))
                {
                    jobj.Remove(CmnAccessToken.SecurityStampHashName);
                }
                else
                {
                    jobj[CmnAccessToken.SecurityStampHashName] = CmnAccessToken.HashSecurityStamp(securityStamp);
                }

                return JsonConvert.SerializeObject(jobj);
            }
            catch (Exception)
            {
                // **読めない payload は、そのまま返す**（この関数で要求を止めない）。
                return payload;
            }
        }

        /// <summary>預かった payload から、利用者の SecurityStamp のハッシュを取り出して外す（#294）</summary>
        /// <param name="payload">access_token の payload（JSON の文字列）</param>
        /// <param name="securityStampHash">書かれていたハッシュ（無ければ空）</param>
        /// <returns>ハッシュを外した payload（読めなければ、受け取ったものをそのまま返す）</returns>
        /// <remarks>
        /// **外してから `ProtectFromPayload` に渡す**（payload の項目は、そのまま access_token に載るため）。
        /// </remarks>
        public static string TakeSecurityStamp(string payload, out string securityStampHash)
        {
            securityStampHash = "";

            if (string.IsNullOrEmpty(payload))
            {
                return payload;
            }

            try
            {
                JObject jobj = (JObject)JsonConvert.DeserializeObject(payload);

                if (jobj == null || jobj[CmnAccessToken.SecurityStampHashName] == null)
                {
                    return payload;
                }

                securityStampHash = (string)jobj[CmnAccessToken.SecurityStampHashName] ?? "";
                jobj.Remove(CmnAccessToken.SecurityStampHashName);

                return JsonConvert.SerializeObject(jobj);
            }
            catch (Exception)
            {
                // **読めなければ、書かれていないものとして扱う**（従来の挙動に倒す）。
                return payload;
            }
        }

        /// <summary>SecurityStamp の SHA-256 を BASE64URL した値（#294）</summary>
        /// <param name="securityStamp">SecurityStamp</param>
        /// <returns>BASE64URL の文字列</returns>
        public static string HashSecurityStamp(string securityStamp)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(
                    sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(securityStamp ?? "")));
            }
        }

        #endregion
    }
}
