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
//* クラス名        ：ExternalLoginStarter
//* クラス日本語名  ：ExternalLoginStarter（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Web;
using System.Web.Mvc;
using System.Net.Http;

using Microsoft.Owin.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.ExternalLoginHelper
{
    /// <summary>
    /// ExternalLoginStarter
    /// 外部ログインを開始するためのHttpUnauthorizedResult派生のActionResult。
    /// </summary>
    /// <see cref="https://msdn.microsoft.com/ja-jp/magazine/dn745860.aspx"/>
    public class ExternalLoginStarter : HttpUnauthorizedResult
    {
        #region propertys & member values

        /// <summary>外部ログイン・プロバイダー</summary>
        public string LoginProvider { get; set; }
        /// <summary>外部ログイン・プロバイダーからリダイレクトで戻る先のURL</summary>
        public string RedirectUri { get; set; }
        /// <summary>ユーザーID</summary>
        public string UserId { get; set; }

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        /// <param name="provider">string</param>
        /// <param name="redirectUri">string</param>
        public ExternalLoginStarter(string provider, string redirectUri)
            : this(provider, redirectUri, null)
        {
        }

        /// <summary>constructor</summary>
        /// <param name="provider">string</param>
        /// <param name="redirectUri">string</param>
        /// <param name="userId">string</param>
        public ExternalLoginStarter(string provider, string redirectUri, string userId)
        {
            LoginProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
        }

        #endregion

        #region ExecuteResult

        /// <summary>ExecuteResult</summary>
        /// <param name="context">context</param>
        public override void ExecuteResult(ControllerContext context)
        {
            // 外部ログイン・プロバイダからリダイレクトで戻る先
            AuthenticationProperties properties = new AuthenticationProperties
            {
                RedirectUri = this.RedirectUri
            };

            // DictionaryのXsrfKeyにUserIdを格納
            if (UserId != null)
            {
                properties.Dictionary[ASPNETIdentityConfig.XsrfKey] = UserId;
            }

            // 認証を実行するタスクを、OWIN ミドルウェアにデリゲート
            context.HttpContext.GetOwinContext().Authentication.Challenge(
                    properties,     // 上記で設定したプロパティ
                    LoginProvider   // 外部ログインのプロバイダ
                );
        }

        #endregion
    }
}