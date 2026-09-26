//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：UserClaims
//* クラス日本語名  ：scope に応じて返す利用者のクレームを組み立てる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/25  玄人 幸道         新規（profile / address のクレームを設定で対応付ける。#230）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

// **ApplicationUser の名前空間は、ターゲットで違う**（net48 は Entity、net10.0 はルート）。
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif

using System;
using System.Collections.Generic;
using System.Linq;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// scope に応じて返す利用者のクレームを組み立てる（#230）
    /// </summary>
    /// <remarks>
    /// **`profile` / `address` のクレームは、この実装が項目を持っていない。**
    /// 利用者情報の入れ物は `ApplicationUser.UnstructuredData`（JSON の文字列）で、
    /// **その中身は導入する側が決める**ため、こちらで項目を作り込まない。
    ///
    /// そこで **「どのキーを、どのクレームとして返すか」だけを設定で持つ**
    /// （`Config.UserClaimsMapping`）。**既定は空で、何も返らない**（従来どおり）。
    ///
    /// **どのクレームがどの scope に属するかは、仕様が決めている**（OIDC Core §5.4）ので、
    /// 設定には書かせない。ここの表が一次情報。
    /// </remarks>
    public class UserClaims
    {
        #region クレームと scope の対応（OIDC Core 5.4）

        /// <summary>profile が要求するクレーム（OIDC Core 5.4。14 個）</summary>
        public static readonly string[] ProfileClaims = new string[]
        {
            "name", "family_name", "given_name", "middle_name", "nickname",
            "preferred_username", "profile", "picture", "website", "gender",
            "birthdate", "zoneinfo", "locale", "updated_at"
        };

        /// <summary>address が要求するクレーム（OIDC Core 5.4）</summary>
        /// <remarks>
        /// **`address` は JSON オブジェクト**で、副フィールドを持つ（OIDC Core 5.1.1）。
        /// 設定では `address.postal_code` のように書いて組み立てられる。
        /// </remarks>
        public const string AddressClaim = "address";

        /// <summary>address の副フィールド（OIDC Core 5.1.1。すべて文字列）</summary>
        public static readonly string[] AddressSubFields = new string[]
        {
            "formatted", "street_address", "locality", "region", "postal_code", "country"
        };

        /// <summary>`user:` で指せる ApplicationUser の項目（白名簿）</summary>
        /// <remarks>
        /// **何でも指せるようにはしない。** 秘密（`PasswordHash` / `SecurityStamp` など）や
        /// 内部の識別子が、設定の書き間違いで外に出るのを防ぐ。
        /// </remarks>
        public static readonly string[] UserProperties = new string[]
        {
            "UserName", "Email", "PhoneNumber"
        };

        /// <summary>`user:`（ApplicationUser の項目を指す）の接頭辞</summary>
        private const string UserPrefix = "user:";

        #endregion

        #region 対応付け

        /// <summary>この scope で返すクレームの対応付けを返す</summary>
        /// <param name="scope">scope（profile / address）</param>
        /// <returns>クレーム名 → 値の在り処</returns>
        private static Dictionary<string, string> GetMappingForScope(string scope)
        {
            Dictionary<string, string> mapping = Config.UserClaimsMapping;
            Dictionary<string, string> forScope = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> item in mapping)
            {
                if (UserClaims.GetScopeOfClaim(item.Key) == scope)
                {
                    forScope.Add(item.Key, item.Value);
                }
            }

            return forScope;
        }

        /// <summary>そのクレームが属する scope を返す（未知なら null）</summary>
        /// <param name="claim">クレーム名（`address.postal_code` のような形も可）</param>
        /// <returns>scope（profile / address）。未知なら null</returns>
        public static string GetScopeOfClaim(string claim)
        {
            if (string.IsNullOrEmpty(claim))
            {
                return null;
            }

            if (UserClaims.ProfileClaims.Contains(claim))
            {
                return OAuth2AndOIDCConst.Scope_Profile;
            }

            // address 丸ごと、または address.<副フィールド>
            if (claim == UserClaims.AddressClaim)
            {
                return OAuth2AndOIDCConst.Scope_Address;
            }

            if (claim.StartsWith(UserClaims.AddressClaim + "."))
            {
                string subField = claim.Substring(UserClaims.AddressClaim.Length + 1);

                if (UserClaims.AddressSubFields.Contains(subField))
                {
                    return OAuth2AndOIDCConst.Scope_Address;
                }
            }

            // **標準のクレーム以外は扱わない。**
            //   勝手な名前を返すと、scope で括る意味が無くなる（何で許可されたのか分からなくなる）。
            return null;
        }

        /// <summary>
        /// 対応付けに載っているクレームの一覧（Discovery の claims_supported 用）
        /// </summary>
        /// <returns>クレーム名（`address.…` は `address` にまとめる）</returns>
        /// <remarks>
        /// **設定から作る。** 固定の一覧にすると、
        /// 「広告しているのに返らない」「返るのに広告していない」がどちらも起きる（#228 の 13）。
        /// </remarks>
        public static List<string> GetSupportedClaims()
        {
            List<string> claims = new List<string>();

            foreach (KeyValuePair<string, string> item in Config.UserClaimsMapping)
            {
                if (UserClaims.GetScopeOfClaim(item.Key) == null)
                {
                    // 未知のクレーム名は広告しない（返してもいない）。
                    continue;
                }

                // address.<副フィールド> は、クレームとしては address ひとつ。
                string claim = item.Key.StartsWith(UserClaims.AddressClaim + ".")
                    ? UserClaims.AddressClaim : item.Key;

                if (!claims.Contains(claim))
                {
                    claims.Add(claim);
                }
            }

            return claims;
        }

        #endregion

        #region 値の組み立て

        /// <summary>
        /// この scope で返すクレームを、claimSet に足す
        /// </summary>
        /// <param name="claimSet">足す先（id_token / UserInfo のクレーム）</param>
        /// <param name="user">利用者</param>
        /// <param name="scope">scope（profile / address）</param>
        /// <remarks>
        /// **値が無い・空のクレームは足さない。** 空の項目を並べても RP の役に立たない。
        /// </remarks>
        public static void AddClaims(Dictionary<string, object> claimSet, ApplicationUser user, string scope)
        {
            if (claimSet == null || user == null)
            {
                return;
            }

            Dictionary<string, string> mapping = UserClaims.GetMappingForScope(scope);

            if (mapping.Count == 0)
            {
                return;
            }

            // UnstructuredData（JSON）は、1 回だけ読む。
            JObject unstructuredData = UserClaims.ParseUnstructuredData(user);

            // address の副フィールドは、まとめて 1 つのオブジェクトにする。
            Dictionary<string, object> address = new Dictionary<string, object>();

            foreach (KeyValuePair<string, string> item in mapping)
            {
                object value = UserClaims.GetValue(item.Value, user, unstructuredData);

                if (value == null)
                {
                    continue;
                }

                if (item.Key.StartsWith(UserClaims.AddressClaim + "."))
                {
                    address[item.Key.Substring(UserClaims.AddressClaim.Length + 1)] = value;
                }
                else if (item.Key == UserClaims.AddressClaim)
                {
                    // 丸ごと持っている場合（オブジェクトのまま返す）。
                    claimSet[UserClaims.AddressClaim] = value;
                }
                else
                {
                    claimSet[item.Key] = value;
                }
            }

            if (address.Count != 0)
            {
                // **副フィールドから組み立てた方を優先する**（両方が設定されている場合）。
                claimSet[UserClaims.AddressClaim] = address;
            }
        }

        /// <summary>UnstructuredData を JSON として読む（読めなければ null）</summary>
        /// <param name="user">利用者</param>
        /// <returns>JObject（読めなければ null）</returns>
        /// <remarks>
        /// **中身は導入する側が決めるので、JSON でないこともあり得る。**
        /// その場合に例外を投げると、`/userinfo` が 500 になる。**黙って「無し」として扱う。**
        /// </remarks>
        private static JObject ParseUnstructuredData(ApplicationUser user)
        {
            if (string.IsNullOrEmpty(user.UnstructuredData))
            {
                return null;
            }

            try
            {
                return JsonConvert.DeserializeObject(user.UnstructuredData) as JObject;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>値の在り処から、値を取り出す（無ければ null）</summary>
        /// <param name="source">`user:&lt;項目&gt;` または UnstructuredData 内のパス（`.` で辿る）</param>
        /// <param name="user">利用者</param>
        /// <param name="unstructuredData">UnstructuredData（JSON）</param>
        /// <returns>値（無ければ null）</returns>
        private static object GetValue(string source, ApplicationUser user, JObject unstructuredData)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }

            if (source.StartsWith(UserClaims.UserPrefix))
            {
                return UserClaims.GetUserProperty(source.Substring(UserClaims.UserPrefix.Length), user);
            }

            if (unstructuredData == null)
            {
                return null;
            }

            // `.` で辿る（SelectToken は $ や [] も解釈するので使わない）。
            JToken token = unstructuredData;

            foreach (string name in source.Split('.'))
            {
                JObject current = token as JObject;

                if (current == null || current[name] == null)
                {
                    return null;
                }

                token = current[name];
            }

            return UserClaims.ToClaimValue(token);
        }

        /// <summary>白名簿の ApplicationUser の項目を取り出す（無ければ null）</summary>
        /// <param name="name">項目名</param>
        /// <param name="user">利用者</param>
        /// <returns>値（無ければ null）</returns>
        private static object GetUserProperty(string name, ApplicationUser user)
        {
            if (!UserClaims.UserProperties.Contains(name))
            {
                // 白名簿の外（設定の書き間違い）。
                return null;
            }

            string value = null;

            switch (name)
            {
                case "UserName":
                    value = user.UserName;
                    break;
                case "Email":
                    value = user.Email;
                    break;
                case "PhoneNumber":
                    value = user.PhoneNumber;
                    break;
            }

            return string.IsNullOrEmpty(value) ? null : value;
        }

        /// <summary>JSON の値を、クレームの値にする（空は null）</summary>
        /// <param name="token">JToken</param>
        /// <returns>値（空なら null）</returns>
        private static object ToClaimValue(JToken token)
        {
            if (token == null || token.Type == JTokenType.Null)
            {
                return null;
            }

            if (token is JObject || token is JArray)
            {
                // オブジェクト・配列は、そのまま返す（`address` を丸ごと持っている場合）。
                return token;
            }

            string value = (string)token;

            return string.IsNullOrEmpty(value) ? null : (object)value;
        }

        #endregion
    }
}
