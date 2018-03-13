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
//* クラス名        ：CustomPasswordHasher
//* クラス日本語名  ：CustomPasswordHasher（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using Microsoft.AspNet.Identity;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.Manager</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Manager
{

    /// <summary>
    /// CustomPasswordHasher
    /// </summary>
    public class CustomPasswordHasher : IPasswordHasher
    {
        /// <summary>
        /// PasswordをHashedPasswordに変換する。
        /// </summary>
        /// <param name="password">password</param>
        /// <returns>hashedPassword</returns>
        public string HashPassword(string password)
        {
            //// $0$ バージョン
            //return this.V0HashAlgorithm(password);

            // $1$ バージョン
            return this.V1HashAlgorithm(password);
        }

        #region Hash AlgorithmのVersion管理

        /// <summary>テスト用 Version 0</summary>
        /// <param name="password">password</param>
        /// <returns>hashPassword</returns>
        private string V0HashAlgorithm(string password)
        {
            // $0$ バージョンの実装
            return "$0$" + "." + password;
        }

        /// <summary>Version 1</summary>
        /// <param name="password">password</param>
        /// <returns>hashPassword</returns>
        private string V1HashAlgorithm(string password)
        {
            // $1$ バージョンの実装
            return "$1$" + "." +
                GetKeyedHash.GetSaltedPassword(
                    password,                            // password
                    EnumKeyedHashAlgorithm.MACTripleDES, // algorithm
                    GetPassword.Generate(10, 3),         // key(pwd)
                    10,                                  // salt length
                    ASPNETIdentityConfig.StretchCount    // stretch count
                );
        }

        #endregion

        /// <summary>
        /// providedPasswordとhashedPasswordを比較検証する。
        /// </summary>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        public PasswordVerificationResult VerifyHashedPassword(
            string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword))
            {
                // 外部ログインのみの（ローカル・パスワードが存在しない）状態
                return PasswordVerificationResult.Failed;
            }
            else
            {
                // バージョン情報を見て振り分ける
                if (hashedPassword.IndexOf("$0$") == 0)
                {
                    return this.V0VerifyHashAlgorithm(hashedPassword, providedPassword);
                }
                if (hashedPassword.IndexOf("$1$") == 0)
                {
                    return this.V1VerifyHashAlgorithm(hashedPassword, providedPassword);
                }
                else
                {
                    return PasswordVerificationResult.Failed;
                }
            }
        }

        #region Verify Hash AlgorithmのVersion管理
        
        /// <summary>テスト用 Version 0</summary>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        private PasswordVerificationResult V0VerifyHashAlgorithm(
            string hashedPassword, string providedPassword)
        {
            if (hashedPassword.Substring(4) == providedPassword)
            {
                return PasswordVerificationResult.Success;
            }
            else
            {
                return PasswordVerificationResult.Failed;
            }
        }

        /// <summary>Version 1</summary>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        private PasswordVerificationResult V1VerifyHashAlgorithm(
            string hashedPassword, string providedPassword)
        {   
            if(GetKeyedHash.EqualSaltedPassword(
                providedPassword, hashedPassword.Substring(4),
                EnumKeyedHashAlgorithm.MACTripleDES))
            {
                return PasswordVerificationResult.Success;
            }
            else
            {
                return PasswordVerificationResult.Failed;
            }
        }

        #endregion
    }
}