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
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokensClaimSet;

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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Util.JWT;

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
        /// POST: /api/OAuthResourceApi/GetUserClaim
        /// </summary>
        /// <returns>OAuthAuthenticatedUsersClaimViewModel</returns>
        [HttpGet]
        // [System.Web.Mvc.Route("api/・・・")] // 後で実行したMapHttpRouteが優先になる？
        public async Task<OAuthMultiPurposeUsersClaimViewModel> GetUserClaim()
        {
            // Claim情報を参照する。
            // iss, aud, expのチェックは、AccessTokenFormatJwt.Unprotectで実施済。
            ClaimsIdentity id = (ClaimsIdentity)User.Identity;
            Claim claim_aud = id.FindFirst(ASPNETIdentityConst.Claim_Audience);
            
            // ユーザ認証を行なう。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            string subject = "";
            string email = "";

            if (user == null)
            {
                // Client Credentialsグラント種別
                subject = OAuthProviderHelper.GetInstance().GetClientName(claim_aud.Value);
                email = subject;
            }
            else
            {
                // その他のグラント種別
                subject = user.UserName;
                email = user.Email;
            }

            #region ID Token

            IDTokensClaimSet idToken = new IDTokensClaimSet()
            {
                Issuer = ASPNETIdentityConfig.OAuthIssuerId,
                Audience = claim_aud.Value,
                Subject = subject, //user.UserName,
                IssuedAt = DateTimeOffset.Now.ToUnixTimeSeconds().ToString(),
                ExpirationTime = DateTimeOffset.Now.Add(ASPNETIdentityConfig.OAuthAccessTokenExpireTimeSpanFromMinutes).ToUnixTimeSeconds().ToString(),
                Nonce = id.FindFirst(ASPNETIdentityConst.Claim_Nonce).Value,
                Email = email //user.Email
            };

            string json = JsonConvert.SerializeObject(idToken);
            JWT_RS256 jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_pfx, ASPNETIdentityConfig.OAuthJWTPassword);
            string idTokenJwt = jwtRS256.Create(json);

            #endregion

            // Scope
            IEnumerable<Claim> claims = id.FindAll(ASPNETIdentityConst.Claim_Scope).AsEnumerable();

            // scope値によって、返す値を変更する。
            Dictionary<string, string> additionalInfo = new Dictionary<string, string>();
            foreach (Claim scope in claims)
            {
                switch (scope.Value)
                {
                    case "username":
                        additionalInfo.Add(scope.Value, subject);
                        break;
                    case "email":
                        additionalInfo.Add(scope.Value, email);
                        break;
                    case "telno":
                        additionalInfo.Add(scope.Value, user.PhoneNumber);
                        break;
                    default:
                        additionalInfo.Add(scope.Value, scope.Value.ToUpper());
                        break;
                }
            }

            // OAuthAuthenticatedUsersClaimViewModelを生成して返す。
            return new OAuthMultiPurposeUsersClaimViewModel()
            {
                APIName = "GetAuthorizedUserClaim",
                JwtToken = idTokenJwt,
                AdditionalInfo = additionalInfo
            };
        }
        
        #endregion
    }
}