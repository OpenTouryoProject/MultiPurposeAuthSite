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
//* クラス名        ：Const
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

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Const</summary>
    public class Const
    {
        #region MaxLength

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

        #endregion

        #region Roles

        /// <summary>SystemAdministrator or Administratorのrole</summary>
        public const string Role_SystemAdminOrAdmin
            = Role_SystemAdmin + ", " + Role_Admin;

        /// <summary>SystemAdministrator or Administrator or Userのrole</summary>
        public const string Role_SystemAdminOrAdminOrUser
            = Role_SystemAdmin + ", " + Role_Admin + ", " + Role_User;

        /// <summary>SystemAdministratorのrole</summary>
        public const string Role_SystemAdmin = "SystemAdmin";

        /// <summary>Administratorのrole</summary>
        public const string Role_Admin = "Admin";

        /// <summary>Userのrole</summary>
        public const string Role_User = "User";    

        #endregion

        #region Scope

        #region ScopeSet

        /// <summary>標準的なscope</summary>
        public static readonly string StandardScopes =
            OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address + " "
            + OAuth2AndOIDCConst.Scope_UserID;

        /// <summary>OIDCのscope</summary>
        public static readonly string OidcScopes =
            OAuth2AndOIDCConst.Scope_Openid + " "
            + OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address + " "
            + OAuth2AndOIDCConst.Scope_UserID;
        
        /// <summary>ID連携 scope</summary>
        public static readonly string IdFederationScopes =
            OAuth2AndOIDCConst.Scope_Openid + " "
            + OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address + " "
            + OAuth2AndOIDCConst.Scope_UserID + " "
            + OAuth2AndOIDCConst.Scope_Roles;

        #endregion

        #endregion
    }
}