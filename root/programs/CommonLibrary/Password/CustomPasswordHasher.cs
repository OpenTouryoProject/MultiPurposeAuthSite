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

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;

using Microsoft.AspNet.Identity;
#else
using MultiPurposeAuthSite;

using Microsoft.AspNetCore.Identity;
#endif

using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;

/// <summary>MultiPurposeAuthSite.Password</summary>
namespace MultiPurposeAuthSite.Password
{
    /// <summary>
    /// CustomPasswordHasher
    /// </summary>
#if NETFX
    public class CustomPasswordHasher : IPasswordHasher
#else
    public class CustomPasswordHasher<TUser> : PasswordHasher<TUser> where TUser : class
#endif
    {
        /// <summary>
        /// PasswordをHashedPasswordに変換する。
        /// </summary>
#if NETFX
        /// <param name="password">password</param>
        /// <returns>hashedPassword</returns>
        public string HashPassword(string password)
#else
        /// <param name="user">ApplicationUser</param>
        /// <param name="password">password</param>
        /// <returns>hashedPassword</returns>
        public override string HashPassword(TUser user, string password)
#endif
        {
            //// $0$ バージョン
            //return this.V0HashAlgorithm(password);

            //// $1$ バージョン
            //return this.V1HashAlgorithm(password);

            // $2$ バージョン
            return this.V2HashAlgorithm(password);
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

#if NETFX
        /// <summary>Version 1</summary>
        /// <param name="password">password</param>
        /// <returns>hashPassword</returns>
        private string V1HashAlgorithm(string password)
        {
            // $1$ バージョンの実装
            // - ver 01-20以前のPasswordHashを使用する場合は、GetPasswordHashV1を使用して下さい。
            // - 以降、新規でPasswordHashを生成する場合は、GetPasswordHashV2を使用して下さい。
            return "$1$" + "." +
                GetPasswordHashV1.GetSaltedPassword(
                    password,                            // password
                    EnumKeyedHashAlgorithm.MACTripleDES, // algorithm
                    GetPassword.Generate(10, 3),         // key(pwd)
                    10,                                  // salt length
                    Config.StretchCount    // stretch count
                );
        }
#endif

        /// <summary>Version 2</summary>
        /// <param name="password">password</param>
        /// <returns>hashPassword</returns>
        private string V2HashAlgorithm(string password)
        {
            // $2$ バージョンの実装
            return "$2$" + "." +
                GetPasswordHashV2.GetSaltedPassword(
                    password,                            // password
                    EnumKeyedHashAlgorithm.HMACSHA512,   // algorithm
                    GetPassword.Generate(10, 3),         // key(pwd)
                    10,                                  // salt length
                    Config.StretchCount    // stretch count
                );
        }

        #endregion

        /// <summary>
        /// providedPasswordとhashedPasswordを比較検証する。
        /// </summary>
#if NETFX
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        public PasswordVerificationResult VerifyHashedPassword(
            string hashedPassword, string providedPassword)
#else
        /// <param name="user">ApplicationUser</param>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        public override PasswordVerificationResult VerifyHashedPassword(
            TUser user, string hashedPassword, string providedPassword)
#endif  
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
#if NETFX
                else if (hashedPassword.IndexOf("$1$") == 0)
                {
                    return this.V1VerifyHashAlgorithm(hashedPassword, providedPassword);
                }
#endif
                else if (hashedPassword.IndexOf("$2$") == 0)
                {
                    return this.V2VerifyHashAlgorithm(hashedPassword, providedPassword);
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

#if NETFX
        /// <summary>Version 1</summary>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        private PasswordVerificationResult V1VerifyHashAlgorithm(
            string hashedPassword, string providedPassword)
        {
            if (GetPasswordHashV1.EqualSaltedPassword(
                providedPassword,
                hashedPassword.Substring(4),
                EnumKeyedHashAlgorithm.MACTripleDES))
            {
                return PasswordVerificationResult.Success;
            }
            else
            {
                return PasswordVerificationResult.Failed;
            }
        }
#endif

        /// <summary>Version 2</summary>
        /// <param name="hashedPassword">hashedPassword</param>
        /// <param name="providedPassword">providedPassword</param>
        /// <returns>検証結果</returns>
        private PasswordVerificationResult V2VerifyHashAlgorithm(
            string hashedPassword, string providedPassword)
        {   
            if(GetPasswordHashV2.EqualSaltedPassword(
                providedPassword,
                hashedPassword.Substring(4),
                EnumKeyedHashAlgorithm.HMACSHA512))
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