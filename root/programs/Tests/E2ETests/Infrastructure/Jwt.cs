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
//* クラス名        ：Jwt
//* クラス日本語名  ：JWTのデコード（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         c_hash / at_hash の計算を追加（拡張仕様のテスト）
//**********************************************************************************

using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// JWTのヘッダ・ペイロードを取り出す。
    ///
    /// 検証（署名・exp）は行わない。ブラックボックス テストとして、
    /// 実装側のJWTライブラリを使わずに独立してデコードする
    /// （同じコードで作って同じコードで読むと、型の誤りを検出できないため）。
    /// </summary>
    public static class Jwt
    {
        /// <summary>ヘッダを返す</summary>
        /// <param name="jwt">JWT</param>
        /// <returns>ヘッダのJSON</returns>
        public static JsonElement Header(string jwt)
        {
            return Part(jwt, 0);
        }

        /// <summary>ペイロードを返す</summary>
        /// <param name="jwt">JWT</param>
        /// <returns>ペイロードのJSON</returns>
        public static JsonElement Payload(string jwt)
        {
            return Part(jwt, 1);
        }

        /// <summary>クレームの JsonValueKind を返す（無ければ Undefined）</summary>
        /// <param name="claimSet">クレーム セット</param>
        /// <param name="name">クレーム名</param>
        /// <returns>JsonValueKind</returns>
        public static JsonValueKind KindOf(JsonElement claimSet, string name)
        {
            JsonElement value;
            return claimSet.TryGetProperty(name, out value) ? value.ValueKind : JsonValueKind.Undefined;
        }

        /// <summary>クレームが存在するか</summary>
        /// <param name="claimSet">クレーム セット</param>
        /// <param name="name">クレーム名</param>
        /// <returns>存在すれば true</returns>
        public static bool Has(JsonElement claimSet, string name)
        {
            JsonElement value;
            return claimSet.TryGetProperty(name, out value);
        }

        /// <summary>クレームを文字列で返す（無ければ null）</summary>
        /// <param name="claimSet">クレーム セット</param>
        /// <param name="name">クレーム名</param>
        /// <returns>値</returns>
        public static string String(JsonElement claimSet, string name)
        {
            JsonElement value;

            if (!claimSet.TryGetProperty(name, out value))
            {
                return null;
            }

            return (value.ValueKind == JsonValueKind.String) ? value.GetString() : value.ToString();
        }

        /// <summary>
        /// c_hash / at_hash / s_hash に入るべき値を計算する。
        ///
        /// OIDC Core §3.3.2.11 : 値の ASCII 表現を、id_token の alg に対応するハッシュ
        /// （RS256 なら SHA-256）にかけ、**左半分**を BASE64URL にしたもの。
        /// 実装側の IdToken.CreateHash は使わない（同じコードで作って同じコードで確かめないため）。
        /// </summary>
        /// <param name="value">code / access_token / state</param>
        /// <returns>ハッシュ値（BASE64URL）</returns>
        public static string HalfHash(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes(value));
                byte[] half = new byte[hash.Length / 2];
                Array.Copy(hash, half, half.Length);

                return Convert.ToBase64String(half)
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }

        /// <summary>指定位置のパートをJSONとして返す</summary>
        /// <param name="jwt">JWT</param>
        /// <param name="index">0=ヘッダ, 1=ペイロード</param>
        /// <returns>JSON</returns>
        private static JsonElement Part(string jwt, int index)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                throw new ArgumentException("JWTが空です。", "jwt");
            }

            string[] parts = jwt.Split('.');

            if (parts.Length < 2)
            {
                throw new ArgumentException("JWTの形式ではありません（'.' が足りません）。", "jwt");
            }

            byte[] json = FromBase64Url(parts[index]);

            // JsonDocument は Dispose 後に無効になるため、
            // クローンした JsonElement を返す。
            using (JsonDocument doc = JsonDocument.Parse(Encoding.UTF8.GetString(json)))
            {
                return doc.RootElement.Clone();
            }
        }

        /// <summary>BASE64URL をデコードする</summary>
        /// <param name="value">BASE64URL文字列</param>
        /// <returns>バイト列</returns>
        private static byte[] FromBase64Url(string value)
        {
            string temp = value.Replace('-', '+').Replace('_', '/');

            switch (temp.Length % 4)
            {
                case 2:
                    temp += "==";
                    break;
                case 3:
                    temp += "=";
                    break;
            }

            return Convert.FromBase64String(temp);
        }
    }
}
