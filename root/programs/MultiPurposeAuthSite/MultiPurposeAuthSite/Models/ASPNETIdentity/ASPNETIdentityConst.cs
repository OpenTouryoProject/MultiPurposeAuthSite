//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：ASPNETIdentityConst
//* クラス日本語名  ：ASP.NET IdentityのConstクラス（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity
{
    /// <summary>ASPNETIdentityConst</summary>
    public class ASPNETIdentityConst
    {
        #region Max

        /// <summary>UriのMaxLength</summary>
        public const int MaxLengthOfUri = 512;

        /// <summary>ClientNameのMaxLength</summary>
        public const int MaxLengthOfClientName = 64;

        /// <summary>RoleNameのMaxLength</summary>
        public const int MaxLengthOfRoleName = 64;

        /// <summary>UserNameのMaxLength</summary>
        public const int MaxLengthOfUserName = 64;

        /// <summary>PasswordのMaxLength</summary>
        public const int MaxLengthOfPassword = 100;

        /// <summary>FirstNameのMaxLength</summary>
        public const int MaxLengthOfFirstName = 64;

        /// <summary>LastNameのMaxLength</summary>
        public const int MaxLengthOfLastName = 64;

        #endregion

        #region Idp

        #region Roles

        /// <summary>SystemAdministratorのrole</summary>
        public static readonly string Role_SystemAdmin = "SystemAdmin";

        /// <summary>Administratorのrole</summary>
        public static readonly string Role_Admin = "Admin";

        /// <summary>Userのrole</summary>
        public static readonly string Role_User = "User";

        #endregion

        #endregion

        #region STS

        /// <summary>issuerクレームのurn</summary>
        public static readonly string Claim_Issuer = "urn:oauth:issuer";
        /// <summary>audienceクレームのurn</summary>
        public static readonly string Claim_Audience = "urn:oauth:audience";
        /// <summary>nonceクレームのurn</summary>
        public static readonly string Claim_Nonce = "urn:oauth:nonce";

        #region Scope

        /// <summary>scopeクレームのurn</summary>
        public static readonly string Claim_Scope = "urn:oauth:scope";

        /// <summary>標準的なscope</summary>
        public static readonly string StandardScopes =
            Scope_Profile + " "
            + Scope_Email + " "
            + Scope_Phone + " "
            + Scope_Address + " "
            + Scope_Userid;
            // + Scope_Userid; //authは他のscopeをフィルタするので。

        #region id_token用のscope
        /// <summary>profileを要求するscope</summary>
        public const string Scope_Profile = "profile";
        /// <summary>emailを要求するscope</summary>
        public const string Scope_Email = "email";
        /// <summary>phoneを要求するscope</summary>
        public const string Scope_Phone = "phone";
        /// <summary>addressを要求するscope</summary>
        public const string Scope_Address = "address";
        #endregion

        #region カスタムのscope
        /// <summary>useridを要求するscope</summary>
        public const string Scope_Userid = "userid";
        /// <summary>認証を要求するscope</summary>
        public const string Scope_Auth = "auth";
        #endregion

        #endregion
        
        #endregion
    }
}