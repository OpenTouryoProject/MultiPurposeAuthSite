//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：MpasCorsPolicies
//* クラス日本語名  ：CORS のポリシー（net48 版）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/04  玄人 幸道         新規
//**********************************************************************************

using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Web.Cors;
using System.Web.Http.Cors;

/// <summary>MultiPurposeAuthSite</summary>
namespace MultiPurposeAuthSite
{
    /// <summary>公開情報の口の CORS（net48 版）</summary>
    /// <remarks>
    /// **誰でも読んでよい**（RP の検出に使う）。
    /// `.well-known/openid-configuration` / `jwkcerts` / `samlmetadata`。
    ///
    /// **`SupportsCredentials` は付けない**（下記）。
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class MpasPublicDocsCorsAttribute : Attribute, ICorsPolicyProvider
    {
        /// <summary>ポリシーを返す</summary>
        /// <param name="request">要求</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ポリシー</returns>
        public Task<CorsPolicy> GetCorsPolicyAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CorsPolicy policy = new CorsPolicy()
            {
                AllowAnyOrigin = true,
                AllowAnyHeader = true,

                // **読むだけの口**なので GET に限る。
                AllowAnyMethod = false,

                // **資格情報は許さない。** 既定も false だが、明示する。
                SupportsCredentials = false
            };

            policy.Methods.Add("GET");

            return Task.FromResult(policy);
        }
    }

    /// <summary>ブラウザから叩く口の CORS（net48 版）</summary>
    /// <remarks>
    /// **許すオリジンだけ。**
    /// `/token` / `/userinfo` / `/SetDeviceToken` / `/ciba_result` / `/2fa_result`。
    ///
    /// **オリジンは net10.0 版と同じ計算で決める**（`CmnEndpoints.GetCorsAllowedOrigins`）。
    /// **構成ファイルの public クライアントの `redirect_uri_*`** から導き、
    /// **追加分は `CorsAllowedOrigins`**（空でよい）。
    ///
    /// | | 直す前 | 直した後 |
    /// |---|---|---|
    /// | `origins` | **`*`** | **登録から導いたオリジンだけ** |
    /// | `SupportsCredentials` | **`true`** | **`false`** |
    ///
    /// **`origins: "*"` と `SupportsCredentials = true` を同時に指定すると、
    /// `System.Web.Http.Cors` は `Access-Control-Allow-Origin` に `*` ではなく
    /// 要求の `Origin` をそのまま反映し、`Access-Control-Allow-Credentials: true` を付ける。**
    /// **任意のオリジンから、利用者の Cookie を伴った要求が許されていた**（実測）。
    ///
    /// **1 件も無ければ、どのオリジンも通さない**（安全側の既定）。
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class MpasBrowserApiCorsAttribute : Attribute, ICorsPolicyProvider
    {
        /// <summary>ポリシーを返す</summary>
        /// <param name="request">要求</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ポリシー</returns>
        public Task<CorsPolicy> GetCorsPolicyAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CorsPolicy policy = new CorsPolicy()
            {
                AllowAnyOrigin = false,
                AllowAnyHeader = true,
                AllowAnyMethod = true,

                // **資格情報は許さない。**
                //   **Cookie で通る口をこの範囲に入れない**ためである
                //   （入れると、他オリジンの JS から利用者の資格情報で呼べる）。
                SupportsCredentials = false
            };

            foreach (string origin in CmnEndpoints.GetCorsAllowedOrigins())
            {
                policy.Origins.Add(origin);
            }

            return Task.FromResult(policy);
        }
    }
}
