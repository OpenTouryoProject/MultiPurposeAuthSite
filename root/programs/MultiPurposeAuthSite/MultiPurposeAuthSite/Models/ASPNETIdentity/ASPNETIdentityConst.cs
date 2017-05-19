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
        /// <summary>scopeクレームのurn</summary>
        public static readonly string Claim_Scope = "urn:oauth:scope";
        /// <summary>nonceクレームのurn</summary>
        public static readonly string Claim_Nonce = "urn:oauth:nonce";
        
        #endregion
    }
}