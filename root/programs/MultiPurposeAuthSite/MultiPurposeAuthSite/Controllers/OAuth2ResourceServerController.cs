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
//* クラス名        ：OAuth2ResourceServerController
//* クラス日本語名  ：OAuth2ResourceServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2018/12/26  西野 大介         分割
//*  2020/02/27  西野 大介         課金エンドポイント（テスト用→解放）
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2026/10/04  玄人 幸道         CORSを口ごとの属性にし、資格情報付きを止めた
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Network;

using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http.Formatting;

using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2ResourceServerのApiController（ライブラリ）</summary>
    //  **CORS はクラスに付けない。** **口ごとに属性で選ぶ**（net10.0 版の #265 と揃える）。
    //    ChageToUser は**サーバ間で呼ぶ**（Helper.CallOAuth2ChageToUserWebAPIAsync）ので、
    //    **CORS は要らない。**
    //  以前はここに origins: "*" ＋ SupportsCredentials = true が付いていた
    //    （**任意のオリジンから、利用者の Cookie を伴った要求が許されていた**）。
    [MyBaseAsyncApiController(httpAuthHeader:
        EnumHttpAuthHeader.None // 認証無くても通すので、
        | EnumHttpAuthHeader.Bearer)] // Bearer認証の結果をGetClaimsで検証。
    public class OAuth2ResourceServerController : ApiController
    {
        #region constructor

        /// <summary>constructor</summary>
        public OAuth2ResourceServerController() { }

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

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }
        #endregion

        #region テスト用

        #region Hybrid Flow

        /// <summary>
        /// Hybrid Flowのテスト用エンドポイント
        /// POST: /TestHybridFlow
        /// </summary>
        /// <param name="formData">code</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        // **自己テストの画面（OAuth2ImplicitGrantClient）が jQuery で叩く。**
        //   **既定では同一オリジン**（OAuth2AuthorizationServerEndpointsRootURI と
        //   OAuth2ClientEndpointsRootURI が同じ値）なので、本来 CORS は要らない。
        //   **2 つを別ホストにした配備では、クロス オリジンになる**ので開けておく。
        //   **この口は IsLockedDownTestEndpoints で経路ごと閉じる**（WebApiConfig）ため、
        //   **本番では、このポリシーも届かない。**
        //   **資格情報は許さない**（SupportsCredentials を付けない）。
        [EnableCors(origins: "*", headers: "*", methods: "*")]
        public async Task<Dictionary<string, object>> TestHybridFlow(FormDataCollection formData)
        {
            // 変数
            string code = formData[OAuth2AndOIDCConst.code];

            // Tokenエンドポイントにアクセス
            Uri tokenEndpointUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            // 結果を格納する変数。
            Dictionary<string, object> dic = null;

            //  client_Idから、client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            // Hybridは、Implicitのredirect_uriを使用
            string redirect_uri 
                = Config.OAuth2ClientEndpointsRootURI
                + Config.OAuth2ImplicitGrantClient_Account;

            // Tokenエンドポイントにアクセス
            string response = await Helper.GetInstance()
            .GetAccessTokenByCodeAsync(tokenEndpointUri, client_id, client_secret, redirect_uri, code, "");
            dic = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);

            // UserInfoエンドポイントにアクセス
            dic = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                await Helper.GetInstance().GetUserInfoAsync((string)dic[OAuth2AndOIDCConst.AccessToken]));

            return dic;
        }

        #endregion

        #endregion

        #region 機能

        #region Chage

        /// <summary>
        /// 課金エンドポイント
        /// POST: /ChageToUser
        /// </summary>
        /// <param name="formData">
        /// - currency
        /// - amount
        /// </param>
        /// <returns>string</returns>
        [HttpPost]
        public async Task<string> ChageToUser(FormDataCollection formData)
        {
            // Claimを取得する。
            string userName, roles, scopes, ipAddress;
            MyBaseAsyncApiController.GetClaims(out userName, out roles, out scopes, out ipAddress);

            // ユーザの検索
            ApplicationUser user = await UserManager.FindByNameAsync(userName);

            if (user != null)
            {
                // 変数
                string currency = formData["currency"];
                string amount = formData["amount"];

                if (Config.CanEditPayment
                    && Config.EnableEditingOfUserAttribute)
                {
                    // 課金の処理
                    JObject jobj = await WebAPIHelper.GetInstance()
                        .ChargeToOnlinePaymentCustomersAsync(user.PaymentInformation, currency, amount);

                    return "OK";
                }
            }

            return "NG";
        }

        #endregion

        #endregion
    }
}