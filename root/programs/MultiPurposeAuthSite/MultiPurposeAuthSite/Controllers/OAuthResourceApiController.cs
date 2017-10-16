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
//* クラス名        ：OAuthResourceApiController
//* クラス日本語名  ：OAuthResourceServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ASPNETIdentity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuthResourceServerのApiController（ライブラリ）</summary>
    [Authorize]
    [EnableCors(
        // リソースへのアクセスを許可されている発生元
        origins: "*",
        // リソースによってサポートされているヘッダー
        headers: "*",
        // リソースによってサポートされているメソッド
        methods: "*",
        // 
        SupportsCredentials = true)]
    public class OAuthResourceApiController : ApiController
    {
        #region constructor

        /// <summary>constructor</summary>
        public OAuthResourceApiController()
        {
        }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        public ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        #endregion

        #region WebAPI

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>OAuthAuthenticatedUsersClaimViewModel</returns>
        [HttpGet]
        [Route("userinfo")] // OpenID Connectライクなインターフェイスに変更した。
        public async Task<Dictionary<string, object>> GetUserClaims()
        {
            // Claim情報を参照する。
            // iss, aud, expのチェックは、AccessTokenFormatJwt.Unprotectで実施済。
            ClaimsIdentity id = (ClaimsIdentity)User.Identity;
            Claim claim_aud = id.FindFirst(ASPNETIdentityConst.Claim_Audience);
            
            // ユーザ認証を行なう。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            
            string subject = "";

            if (user == null)
            {
                // ここは、現在の実装では通らない。
                // Client Credentialsグラント種別で、*.configに定義したclient_id（ClientName）
                // を使用して、UserStoreに存在しないClaimsIdentityを偽装する場合にココを通る。
                subject = OAuth2Helper.GetInstance().GetClientName(claim_aud.Value);
            }
            else
            {
                subject = user.UserName;
            }

            Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
            userinfoClaimSet.Add("sub", subject);

            // Scope
            IEnumerable<Claim> claimScope = id.FindAll(ASPNETIdentityConst.Claim_Scope).AsEnumerable();

            // scope値によって、返す値を変更する。
            foreach (Claim scope in claimScope)
            {
                switch (scope.Value.ToLower())
                {
                    #region OpenID Connect
                    case ASPNETIdentityConst.Scope_Profile:
                        // ・・・
                        break;
                    case ASPNETIdentityConst.Scope_Email:
                        userinfoClaimSet.Add("email", user.Email);
                        userinfoClaimSet.Add("email_verified", user.EmailConfirmed.ToString());
                        break;
                    case ASPNETIdentityConst.Scope_Phone:
                        userinfoClaimSet.Add("phone_number", user.PhoneNumber);
                        userinfoClaimSet.Add("phone_number_verified", user.PhoneNumberConfirmed.ToString());
                        break;
                    case ASPNETIdentityConst.Scope_Address:
                        // ・・・
                        break;
                    #endregion

                    #region Else
                    case ASPNETIdentityConst.Scope_Userid:
                        userinfoClaimSet.Add(ASPNETIdentityConst.Scope_Userid, user.Id);
                        break;
                    case ASPNETIdentityConst.Scope_Roles:
                        IList<string> roles = await UserManager.GetRolesAsync(user.Id);
                        userinfoClaimSet.Add(ASPNETIdentityConst.Scope_Roles, roles);
                        break;
                        #endregion
                }
            }

            return userinfoClaimSet;
        }
        
        #endregion
    }
}