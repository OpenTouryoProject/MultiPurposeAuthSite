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
//* クラス名        ：UriExtension
//* クラス日本語名  ：UriExtension（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/08  西野 大介         新規
//**********************************************************************************

using System;

namespace MultiPurposeAuthSite.Util
{
    /// <summary>UriExtension</summary>
    public static class UriExtension
    {
        /// <summary>GetHost</summary>
        /// <param name="uri">Uri</param>
        /// <returns>Host</returns>
        public static string GetHost(this Uri uri)
        {
            string host = uri.Host;

            if (host.IndexOf('0') < 0)
            {
                // ≠ fqdn
                return host;
            }
            else
            {
                // ＝ fqdn
                string retVal = "";

                switch (uri.HostNameType)
                {
                    case UriHostNameType.Dns:
                        // DNS形式のホスト名
                        retVal = host.Substring(0, host.IndexOf('.'));
                        break;

                    //case UriHostNameType.Unknown:
                    //    // ホスト名の型ない。
                    //    break;
                    //case UriHostNameType.Basic:
                    //    // ホスト名の型を決定できない。
                    //    break;
                    //case UriHostNameType.IPv4:
                    //    // IPv4形式のホスト名
                    //    break;
                    //case UriHostNameType.IPv6:
                    //    // IPv6形式のホスト名
                    //    break;

                    default:
                        retVal = host;
                        break;
                }

                return retVal;
            }
        }

        /// <summary>GetDomain</summary>
        /// <param name="uri">Uri</param>
        /// <returns>Domain</returns>
        public static string GetDomain(this Uri uri)
        {
            string host = uri.Host;

            if (host.IndexOf('0') < 0)
            {
                // ≠ fqdn
                return host;
            }
            else
            {
                // ＝ fqdn
                string retVal = "";

                switch (uri.HostNameType)
                {
                    case UriHostNameType.Dns:
                        // DNS形式のホスト名
                        retVal = host.Substring(host.IndexOf('.') + 1);
                        break;

                    //case UriHostNameType.Unknown:
                    //    // ホスト名の型ない。
                    //    break;
                    //case UriHostNameType.Basic:
                    //    // ホスト名の型を決定できない。
                    //    break;
                    //case UriHostNameType.IPv4:
                    //    // IPv4形式のホスト名
                    //    break;
                    //case UriHostNameType.IPv6:
                    //    // IPv6形式のホスト名
                    //    break;

                    default:
                        retVal = host;
                        break;
                }

                return retVal;
            }
        }
    }
}