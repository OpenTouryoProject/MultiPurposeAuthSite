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
//* クラス名        ：OutboundHttpLimits
//* クラス日本語名  ：OP が外へ出す要求の、時間と大きさの上限（#375）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規（#375）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Net.Http;

namespace MultiPurposeAuthSite.Network
{
    /// <summary>
    /// **OP が外へ出す要求の、時間と大きさの上限**（#375）
    /// </summary>
    /// <remarks>
    /// **共有の `OAuth2AndOIDCClient.HttpClient` に掛ける。** Open棟梁 の部品（`RemoteJwkSetStore`・`OAuth2AndOIDCClient`・`SAML2Metadata`）は、
    /// **要求ごとの上限を持たず、この HttpClient の設定に任せる。**
    /// **以前は何も設定しておらず、.NET の既定（100 秒・大きさは 2GB 近く）だった**ので、
    /// 応答の遅い `jwks_uri` を登録されると、登録の要求や起動のときの温めが長く待たされた。
    ///
    /// | | 既定 | 設定 |
    /// |---|---|---|
    /// | **時間** | **30 秒** | `OutboundHttpTimeoutSeconds` |
    /// | **大きさ**（応答の本文を読み込む上限） | **1MB** | `OutboundHttpMaxResponseBytes` |
    ///
    /// - **掛ける所**：起動のとき（`Program.Main`・`Global.asax`。**設定を読む前なので既定の値**）、`Helper` が作り直すとき（設定の値）、
    ///   クライアントが登録した URL を取りに行く専用の HttpClient（`OutboundUrlPolicy.HttpClient`。#376）
    /// - **要求ごとに短い上限を持つ口は、そちらが先に効く**（Back-Channel Logout・`sector_identifier_uri` は 10 秒）
    /// - **HttpClient の `Timeout`・`MaxResponseContentBufferSize` は、最初の要求の後には変えられない**ので、作った直後に掛ける
    /// </remarks>
    public static class OutboundHttpLimits
    {
        /// <summary>時間の既定（秒）</summary>
        public const int DefaultTimeoutSeconds = 30;

        /// <summary>大きさの既定（バイト）</summary>
        public const long DefaultMaxResponseBytes = 1024 * 1024;

        /// <summary>HttpClient に、既定の上限を掛ける（設定を読む前の起動のとき）</summary>
        /// <param name="client">作った直後の HttpClient</param>
        /// <returns>同じ HttpClient</returns>
        public static HttpClient ApplyDefaults(HttpClient client)
        {
            return OutboundHttpLimits.Apply(
                client, OutboundHttpLimits.DefaultTimeoutSeconds, OutboundHttpLimits.DefaultMaxResponseBytes);
        }

        /// <summary>HttpClient に、設定の上限を掛ける</summary>
        /// <param name="client">作った直後の HttpClient</param>
        /// <returns>同じ HttpClient</returns>
        public static HttpClient ApplyConfigured(HttpClient client)
        {
            return OutboundHttpLimits.Apply(
                client, Config.OutboundHttpTimeoutSeconds, Config.OutboundHttpMaxResponseBytes);
        }

        /// <summary>HttpClient に上限を掛ける</summary>
        /// <param name="client">作った直後の HttpClient</param>
        /// <param name="timeoutSeconds">時間（秒。1 未満なら既定）</param>
        /// <param name="maxResponseBytes">大きさ（バイト。1 未満なら既定）</param>
        /// <returns>同じ HttpClient</returns>
        public static HttpClient Apply(HttpClient client, int timeoutSeconds, long maxResponseBytes)
        {
            if (client == null)
            {
                return null;
            }

            client.Timeout = TimeSpan.FromSeconds(
                timeoutSeconds < 1 ? OutboundHttpLimits.DefaultTimeoutSeconds : timeoutSeconds);

            client.MaxResponseContentBufferSize =
                maxResponseBytes < 1 ? OutboundHttpLimits.DefaultMaxResponseBytes : maxResponseBytes;

            return client;
        }
    }
}
