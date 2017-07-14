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
//* クラス名        ：OpenIDConnectModule
//* クラス日本語名  ：OpenIDConnectModule（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/07/14  西野 大介         新規
//**********************************************************************************

using System;
using System.Web;
using MultiPurposeAuthSite.Models.ASPNETIdentity;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Filter
{
    /// <summary>
    /// モジュールを使用するには、Web の Web.config ファイルでこの
    /// モジュールを設定し、IIS に登録する必要があります。詳細については、
    /// 次のリンクを参照してください: http://go.microsoft.com/?linkid=8101007
    /// </summary>
    public class OpenIDConnectModule : IHttpModule
    {

        #region IHttpModule Members

        /// <summary>Constructor</summary>
        public OpenIDConnectModule() { }

        /// <summary>Dispose</summary>
        public void Dispose()
        {
            //後処理用コードはここに追加します。
        }

        /// <summary>Init</summary>
        /// <param name="context">HttpApplication</param>
        public void Init(HttpApplication context)
        {
            //context.LogRequest += new EventHandler(OnLogRequest);
            context.BeginRequest += new EventHandler(OnBeginRequest);
            //context.EndRequest += new EventHandler(OnEndRequest);
        }

        #endregion

        /// <summary>OnLogRequest</summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        private void OnLogRequest(Object source, EventArgs e)
        {
            // LogRequestのロジックはここに挿入
        }

        /// <summary>OnBeginRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnBeginRequest(Object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入

            HttpApplication application = (HttpApplication)sender;
            HttpContext context = application.Context;
            if (context.Request.Url.AbsolutePath.IndexOf(ASPNETIdentityConfig.OAuthBearerTokenEndpoint) != -1)
            {
                //レスポンス内容を参照して書き換え
                HttpResponse response = context.Response;
                response.Filter = new OpenIDConnectFilter(context);
            }
        }

        /// <summary>OnEndRequest</summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnEndRequest(object sender, EventArgs e)
        {
            // EndRequestのロジックはここに挿入
        }
    }
}
