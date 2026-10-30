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
//* クラス名        ：OAuth2EndpointController
//* クラス日本語名  ：OAuth2EndpointController の UserInfo（/userinfo）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Util;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;   // ETag / Cache-Control（#303）

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（UserInfo（/userinfo））</summary>
    public partial class OAuth2EndpointController
    {
        #region /userinfo

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>成功は 200、エラーは 401 と WWW-Authenticate: Bearer（RFC 6750 3）（#196）</returns>
        [HttpGet]
        [MpasBrowserApiCors]   // ブラウザから読む口
        public async Task<IHttpActionResult> GetUserClaims()
        {
            // **資格情報・属性を返すので、キャッシュに残さない**（#218）。
            //   RFC は MUST としていないが、困る性質は /token と同じ。
            this.SetNoStore();

            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            // クライアント認証
            if (AuthenticationHeader.GetAccessToken(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken, out string authScheme))
            {
                if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity))
                {
                    // **証明書に紐づくトークンは、その証明書を提示した要求でしか使えない**（RFC 8705 3）。
                    //   紐づいていないトークン（cnf 無し）は、これまでどおり bearer として扱う。
                    if (!Token.CmnAccessToken.VerifyCertificateBinding(identity, Request.GetClientCertificate()))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                        err.Add(OAuth2AndOIDCConst.error_description,
                            "The access token is bound to a client certificate.");

                        return this.UserInfoError(err);
                    }

                    //  **DPoP に縛られたトークンは、その鍵の証明と一緒でしか使えない**
                    //    （RFC 9449 §7.1。#311 の段階 2）。
                    //    **縛っていないトークンは、これまでどおり通る。**
                    if (!this.VerifyDPoP(identity, bearerToken, authScheme == OAuth2AndOIDCConst.DPoP, out string dpopError))
                    {
                        //  **nonce を貰い直させる断りは、区別して返す**
                        //    （RFC 9449 §9。#311 の段階 4）。
                        err.Add(OAuth2AndOIDCConst.error,
                            dpopError ?? OAuth2AndOIDCConst.invalid_token);
                        err.Add(OAuth2AndOIDCConst.error_description,
                            (dpopError == OAuth2AndOIDCConst.use_dpop_nonce)
                                ? "A DPoP proof with a new nonce is required."
                                : "The access token is bound to a DPoP key.");

                        return this.UserInfoError(err);
                    }

                    // ClientIdの取り出し
                    Claim ClientId = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                    ApplicationUser user =
                        //CmnUserStore.FindByName(identity.Name);
                        PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);

                    // Client認証、Resource Owner認証、何れの場合も...
                    string sub = identity.Name;

                    Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
                    userinfoClaimSet.Add(OAuth2AndOIDCConst.sub, sub);

                    // scope
                    IEnumerable<Claim> scopes = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnScopesClaim);

                    // scope値によって、返す値を変更する。
                    foreach (Claim claim in scopes)
                    {
                        string scope = claim.Value;
                        if (user != null)
                        {
                            switch (scope.ToLower())
                            {
                                #region OpenID Connect

                                case OAuth2AndOIDCConst.Scope_Profile:
                                    // **返す項目は設定で決まる**（#230。UserClaims）。
                                    Sts.UserClaims.AddClaims(
                                        userinfoClaimSet, user, OAuth2AndOIDCConst.Scope_Profile);
                                    break;
                                case OAuth2AndOIDCConst.Scope_Email:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.Scope_Email, user.Email);
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed);
                                    break;
                                case OAuth2AndOIDCConst.Scope_Phone:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed);
                                    break;
                                case OAuth2AndOIDCConst.Scope_Address:
                                    // **返す項目は設定で決まる**（#230。UserClaims）。
                                    Sts.UserClaims.AddClaims(
                                        userinfoClaimSet, user, OAuth2AndOIDCConst.Scope_Address);
                                    break;

                                #endregion

                                #region Else

                                case OAuth2AndOIDCConst.Scope_Roles:
                                    userinfoClaimSet.Add(
                                        OAuth2AndOIDCConst.Scope_Roles,
                                        await UserManager.GetRolesAsync(user.Id));
                                    break;

                                #endregion
                            }
                        }
                    }

                    // claims
                    if (claims != null)
                    {
                        foreach (KeyValuePair<string, JToken> item in claims)
                        {
                            if (item.Key == OAuth2AndOIDCConst.claims_userinfo)
                            {
                                // userinfoで追加する値
                            }
                            else if (item.Key == OAuth2AndOIDCConst.claims_id_token)
                            {
                                // ...
                            }
                        }
                    }

                    return this.Ok(userinfoClaimSet);

                }
                else
                {
                    // 無効なトークン（JWT でない、改竄・失効・期限切れなど）。
                    // RFC 6750 3.1 : invalid_token（401）。以前は invalid_request（400 に当たる）だった（#196）。
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                }
            }

            // Bearer トークンが無い（Authorization ヘッダ無し、または他の方式）場合、err は空のまま。
            // RFC 6750 3.1 : エラー情報を付けず、Bearer が要ることだけを示す（#196）。

            return this.UserInfoError(err); // 失敗（RFC 6750 3 : 401 ＋ WWW-Authenticate）（#196）
        }

        /// <summary>/userinfo のエラー応答を作る（RFC 6750 3 / OIDC Core 5.3.3）</summary>
        /// <param name="err">error / error_description を持つ辞書（トークンが無かった場合は空）</param>
        /// <returns>401 と WWW-Authenticate: Bearer</returns>
        /// <remarks>
        /// 以前は Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// トークンが無かった場合は、本文を返さない（RFC 6750 3.1 : エラー情報を含めない）。
        /// </remarks>
        private IHttpActionResult UserInfoError(Dictionary<string, string> err)
        {
            this.TraceErrorResponse(
                (err.Count == 0) ? 401 : Token.CmnEndpoints.GetResourceErrorStatusCode(err), err);

            HttpResponseMessage res = (err.Count == 0)
                ? this.Request.CreateResponse(HttpStatusCode.Unauthorized)
                : this.Request.CreateResponse(
                    (HttpStatusCode)Token.CmnEndpoints.GetResourceErrorStatusCode(err), err);

            //  **`DPoP` スキームで来た要求には、`DPoP` で答える**（RFC 9449 §7.1。#311 の段階 4）。
            string scheme = AuthenticationHeader.GetChallengeScheme(HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization]);

            res.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue(
                scheme, Token.CmnEndpoints.GetChallengeParameter(scheme, Const.EndpointUserInfo, err)));

            //  **nonce を要求する配備では、新しい値を渡す**（§9）。
            //    **これが無いと、クライアントは出し直せない。**
            string nonce = Token.CmnDPoP.NonceForChallenge(scheme == OAuth2AndOIDCConst.DPoP);

            if (nonce != null)
            {
                res.Headers.Add(OAuth2AndOIDCConst.HttpHeader_DPoPNonce, nonce);
            }

            return this.ResponseMessage(res);
        }

        #endregion
    }
}