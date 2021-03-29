﻿//**********************************************************************************
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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;

using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2ResourceServerのApiController（ライブラリ）</summary>
    [EnableCors]
    //[ApiController]
    [MyBaseAsyncApiController(httpAuthHeader:
        EnumHttpAuthHeader.None // 認証無くても通すので、
        | EnumHttpAuthHeader.Bearer)] // Bearer認証の結果をGetClaimsで検証。
    public class OAuth2ResourceServerController : ControllerBase
    {
        #region DI(CA)対応
        #region members & constructor

        #region members

        #region OwinContext
        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        public OAuth2ResourceServerController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
        }
        #endregion

        #endregion

        #region property

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        #endregion

        #endregion        
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
        public async Task<Dictionary<string, object>> TestHybridFlow(IFormCollection formData)
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
        /// 課金用エンドポイント
        /// POST: /ChageToUser
        /// </summary>
        /// <param name="formData">
        /// - currency
        /// - amount
        /// </param>
        /// <returns>string</returns>
        [HttpPost]
        public async Task<string> ChageToUser(IFormCollection formData)
        {
            // Claimを取得する。
            MyBaseAsyncApiController.GetClaims(
                out string userName, out string roles, out string scopes, out string ipAddress);

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