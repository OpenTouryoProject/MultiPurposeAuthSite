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

        #endregion

        #region Idp

        #region Roles

        /// <summary>SystemAdministrator or Administratorのrole</summary>
        public const string Role_SystemAdminOrAdmin = "SystemAdmin, Admin";

        /// <summary>SystemAdministratorのrole</summary>
        public const string Role_SystemAdmin = "SystemAdmin";

        /// <summary>Administratorのrole</summary>
        public const string Role_Admin = "Admin";

        /// <summary>Userのrole</summary>
        public const string Role_User = "User";

        #endregion

        #endregion

        #region STS

        #region GrantType

        /// <summary>Authorization Codeグラント種別</summary>
        public const string AuthorizationCodeGrantType = "authorization_code";

        /// <summary>Implicitグラント種別</summary>
        public const string ImplicitGrantType = "-"; // Implicitには無い。

        /// <summary>Resource Owner Password Credentialsグラント種別</summary>
        public const string ResourceOwnerPasswordCredentialsGrantType = "password";

        /// <summary>Client Credentialsグラント種別</summary>
        public const string ClientCredentialsGrantType = "client_credentials";

        /// <summary>Refresh Tokenグラント種別</summary>
        public const string RefreshTokenGrantType = "refresh_token";

        /// <summary>JWT bearer token authorizationグラント種別</summary>
        public const string JwtBearerTokenFlowGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

        #endregion

        #region Claimのurn

        /// <summary>ベース部分</summary>
        public static readonly string Claim_Base = "urn:oauth:";

        #region 標準Claim

        /// <summary>issuerクレームのurn</summary>
        public static readonly string Claim_Issuer = Claim_Base + "iss";

        /// <summary>audienceクレームのurn</summary>
        public static readonly string Claim_Audience = Claim_Base + "aud";

        /// <summary>scopeクレームのurn</summary>
        public static readonly string Claim_Scope = Claim_Base + "scope";

        #endregion

        #region 拡張Claim

        #region JWT

        /// <summary>expクレームのurn</summary>
        public static readonly string Claim_ExpirationTime = Claim_Base + "exp";

        /// <summary>nbfクレームのurn</summary>
        public static readonly string Claim_NotBefore = Claim_Base + "nbf";

        /// <summary>iatクレームのurn</summary>
        public static readonly string Claim_IssuedAt = Claim_Base + "iat";

        /// <summary>jtiクレームのurn</summary>
        public static readonly string Claim_JwtId = Claim_Base + "jti";

        #region OIDC

        /// <summary>nonceクレームのurn</summary>
        public static readonly string Claim_Nonce = Claim_Base + "nonce";

        #endregion

        #endregion

        #endregion

        #endregion

        #region Scope

        #region Scopes

        /// <summary>標準的なscope</summary>
        public static readonly string StandardScopes =
            Scope_Profile + " "
            + Scope_Email + " "
            + Scope_Phone + " "
            + Scope_Address + " "
            + Scope_Userid;
        // authは他のscopeをフィルタするので。

        /// <summary>ID連携 scope</summary>
        public static readonly string IdFederationScopes =
            Scope_Openid + " "
            + Scope_Profile + " "
            + Scope_Email + " "
            + Scope_Phone + " "
            + Scope_Address + " "
            + Scope_Userid + " "
            + Scope_Roles;
        // authは他のscopeをフィルタするので。

        #endregion

        #region id_token用のscope

        /// <summary>id_tokenを要求するscope</summary>
        public const string Scope_Openid = "openid";

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
        /// <remarks>OAuth2用のprompt=none(@OIDC)的な</remarks>
        public const string Scope_Auth = "auth";
        
        /// <summary>rolesを要求するscope</summary>
        public const string Scope_Roles = "roles";
        
        #endregion

        #endregion

        #endregion
    }
}