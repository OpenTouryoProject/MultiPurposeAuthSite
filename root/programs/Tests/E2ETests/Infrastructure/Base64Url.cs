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
//* クラス名        ：Base64Url
//* クラス日本語名  ：BASE64URL の変換（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/11  玄人 幸道         新規（Jwt / Jwks / RequestObjectBuilder に重複していた変換を集約）
//**********************************************************************************

using System;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// BASE64URL（RFC 4648 §5、パディングなし）の変換。
    ///
    /// JWT の各パート、c_hash / at_hash、JWK の n / e は、いずれもこの形式。
    /// 実装側の CustomEncode は使わない（同じコードで作って同じコードで読まないため）。
    /// </summary>
    public static class Base64Url
    {
        /// <summary>BASE64URL にする</summary>
        /// <param name="value">バイト列</param>
        /// <returns>BASE64URL文字列（パディングなし）</returns>
        public static string Encode(byte[] value)
        {
            return Convert.ToBase64String(value)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>BASE64URL をデコードする</summary>
        /// <param name="value">BASE64URL文字列</param>
        /// <returns>バイト列</returns>
        public static byte[] Decode(string value)
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
