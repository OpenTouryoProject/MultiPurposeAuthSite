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
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http.Formatting;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuthResourceServerのApiController（ライブラリ）</summary>
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
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        #endregion

        #region WebAPI

        #region /userinfo

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>Dictionary(string, object)</returns>
        [HttpGet]
        [Route("userinfo")] // OpenID Connectライクなインターフェイスに変更した。
        [Authorize]
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
                        userinfoClaimSet.Add(
                            ASPNETIdentityConst.Scope_Roles,
                            await UserManager.GetRolesAsync(user.Id));
                        break;

                    #endregion
                }
            }

            return userinfoClaimSet;
        }

        #endregion

        #region /revoke 

        /// <summary>
        /// AccessTokenとRefreshTokenの取り消し
        /// POST: /revoke
        /// </summary>
        /// <param name="formData">
        /// token
        /// token_type_hint
        /// </param>
        /// <returns>Dictionary(string, object)</returns>
        [HttpPost]
        [Route("revoke")]
        //[Authorize]
        public Dictionary<string, object> RevokeOAuthToken(FormDataCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            // 変数
            string[] temp = null;
            string token = formData["token"];
            string token_type_hint = formData["token_type_hint"];

            // クライアント認証

            // クライアント識別子
            string authHeader = HttpContext.Current.Request.Headers["Authorization"];
            
            temp = authHeader.Split(' ');

            if (temp[0].ToLower() == "basic")
            {
                temp = CustomEncode.ByteToString(
                    CustomEncode.FromBase64String(temp[1]), CustomEncode.us_ascii).Split(':');

                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了

                        if (token_type_hint == "access_token")
                        {
                            // 検証
                            AccessTokenFormatJwt verifier = new AccessTokenFormatJwt();
                            AuthenticationTicket ticket = verifier.Unprotect(token);

                            if (ticket == null)
                            {
                                // 検証失敗
                                // 検証エラー
                            }
                            else
                            {
                                // 検証成功

                                // jtiの取り出し
                                Claim claim = ticket.Identity.Claims.Where(
                                    x => x.Type == ASPNETIdentityConst.Claim_Jti).FirstOrDefault<Claim>();

                                // access_token取消
                                OAuth2RevocationProvider.GetInstance().Create(claim.Value);
                            }
                        }
                        else if (token_type_hint == "refresh_token")
                        {
                            // refresh_token取消
                            RefreshTokenProvider.DeleteDirectly(token);
                        }
                        else
                        {
                            // token_type_hint パラメタ・エラー
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential不正
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
            }

            return null;
        }

        #endregion

        #endregion
    }
}