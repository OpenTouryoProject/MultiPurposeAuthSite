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
//* クラス名        ：CreateProxy
//* クラス日本語名  ：CreateProxy（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using System.Net;
using MultiPurposeAuthSite.Co;

namespace MultiPurposeAuthSite.Network
{
    /// <summary>ProxyType</summary>
    public enum EnumProxyType
    {
        /// <summary>Internet用プロキシ</summary>
        Internet,
        /// <summary>Intranet用プロキシ</summary>
        Intranet,
        /// <summary>Debug用プロキシ</summary>
        Debug
    }

    /// <summary>プロキシ生成クラス</summary>
    public class CreateProxy
    {
        /// <summary>GetInternetProxy</summary>
        /// <returns>IWebProxy</returns>
        public static IWebProxy GetInternetProxy()
        {
            IWebProxy proxy = null;
            NetworkCredential proxyCredentials = null;

            if (Config.UseInternetProxy)
            {
                proxy = new WebProxy(new Uri(Config.InternetProxyURL));

                if (!string.IsNullOrEmpty(Config.InternetProxyUID))
                {
                    proxyCredentials = new NetworkCredential(
                                                Config.InternetProxyUID,
                                                Config.InternetProxyPWD);

                    proxy.Credentials = proxyCredentials;
                }
                return proxy;
            }
            else
            {
                return null;
            }
        }

        /// <summary>GetIntranetProxy</summary>
        /// <returns>IWebProxy</returns>
        public static IWebProxy GetIntranetProxy()
        {
            IWebProxy proxy = null;
            NetworkCredential proxyCredentials = null;

            if (Config.UseIntranetProxy)
            {
                proxy = new WebProxy(new Uri(Config.IntranetProxyURL));

                if (!string.IsNullOrEmpty(Config.IntranetProxyUID))
                {
                    proxyCredentials = new NetworkCredential(
                                                Config.IntranetProxyUID,
                                                Config.IntranetProxyPWD);

                    proxy.Credentials = proxyCredentials;
                }
                return proxy;
            }
            else
            {
                return null;
            }
        }

        /// <summary>GetDebugProxy</summary>
        /// <returns>IWebProxy</returns>
        public static IWebProxy GetDebugProxy()
        {
            IWebProxy proxy = null;
            NetworkCredential proxyCredentials = null;

            if (Config.UseDebugProxy)
            {
                proxy = new WebProxy(new Uri(Config.DebugProxyURL));

                if (!string.IsNullOrEmpty(Config.DebugProxyUID))
                {
                    proxyCredentials = new NetworkCredential(
                                                Config.DebugProxyUID,
                                                Config.DebugProxyPWD);

                    proxy.Credentials = proxyCredentials;
                }
                return proxy;
            }
            else
            {
                return null;
            }
        }
    }
}