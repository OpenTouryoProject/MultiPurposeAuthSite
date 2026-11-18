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
//*  2026/11/18  玄人 幸道         要求先の分類ごとにプロキシの組を選ぶ口（ParseProxyType・GetProxy・UsesProxy・For*）と None を足した（#406）
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
        Debug,
        /// <summary>プロキシを使わない（OS の既定のプロキシも使わない。#406）</summary>
        None
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

        #region 要求先の分類ごとのプロキシ（#406）

        /// <summary>分類の設定の値を、プロキシの組に直す（#406）</summary>
        /// <param name="value">設定の値（`Internet`・`Intranet`・`Debug`・`None`。大文字小文字を問わない）</param>
        /// <param name="defaultType">無い・読めないときの組</param>
        /// <returns>プロキシの組</returns>
        public static EnumProxyType ParseProxyType(string value, EnumProxyType defaultType)
        {
            if (!string.IsNullOrWhiteSpace(value)
                && Enum.TryParse(value.Trim(), true, out EnumProxyType parsed)
                && Enum.IsDefined(typeof(EnumProxyType), parsed))
            {
                return parsed;
            }

            return defaultType;
        }

        /// <summary>組のプロキシを作る（#406）</summary>
        /// <param name="type">プロキシの組</param>
        /// <returns>
        /// プロキシ。**`null` は「設定のプロキシは無い」**（その組の `Use*Proxy` が false か、`None`）。
        /// **`None` かどうかは `UsesProxy` で見る**（`None` は OS の既定のプロキシも使わない）
        /// </returns>
        public static IWebProxy GetProxy(EnumProxyType type)
        {
            switch (type)
            {
                case EnumProxyType.Internet:
                    return CreateProxy.GetInternetProxy();
                case EnumProxyType.Intranet:
                    return CreateProxy.GetIntranetProxy();
                case EnumProxyType.Debug:
                    return CreateProxy.GetDebugProxy();
                default:
                    return null;
            }
        }

        /// <summary>HttpClient の handler の `UseProxy` に入れる値（#406）</summary>
        /// <param name="type">プロキシの組</param>
        /// <returns>`None` なら false（OS の既定のプロキシも使わない）。ほかは true（設定のプロキシが無ければ OS の既定）</returns>
        /// <remarks>**以前どおりの振る舞い**：組の `Use*Proxy` が false なら、`Proxy` は `null` で `UseProxy` は true（OS の既定のプロキシ）。</remarks>
        public static bool UsesProxy(EnumProxyType type)
        {
            return type != EnumProxyType.None;
        }

        /// <summary>ID 連携の上流・自己テスト（共有の HttpClient。#405 までは `jwks_uri` も）の組（既定 `Intranet`）</summary>
        public static EnumProxyType ForIdFederation
        {
            get { return CreateProxy.ParseProxyType(Config.ProxyForIdFederation, EnumProxyType.Intranet); }
        }

        /// <summary>RP が登録した URL（`sector_identifier_uri`。#405 の後は `jwks_uri` も）の組（既定 `Intranet`）</summary>
        public static EnumProxyType ForClientRegisteredUrls
        {
            get { return CreateProxy.ParseProxyType(Config.ProxyForClientRegisteredUrls, EnumProxyType.Intranet); }
        }

        /// <summary>Back-Channel Logout の POST の組（既定 `Intranet`）</summary>
        public static EnumProxyType ForBackChannelLogout
        {
            get { return CreateProxy.ParseProxyType(Config.ProxyForBackChannelLogout, EnumProxyType.Intranet); }
        }

        /// <summary>外部ログイン（Google・Microsoft）の組（既定 `Internet`）</summary>
        public static EnumProxyType ForExternalLogin
        {
            get { return CreateProxy.ParseProxyType(Config.ProxyForExternalLogin, EnumProxyType.Internet); }
        }

        #endregion
    }
}