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
//* クラス名        ：DynamicClientRegistration
//* クラス日本語名  ：動的クライアント登録（RFC 7591）の口を駆動する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/18  玄人 幸道         新規（#307 の段階 1）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using Xunit;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 動的クライアント登録（RFC 7591）の口を駆動する。
    /// </summary>
    /// <remarks>
    /// **段階 1 の流れ**（#307）。
    ///
    /// 1. **専用 scope（`client_registration`）を登録したクライアント**で、
    ///    **ROPC のアクセス トークンを取る**（所有者は、そのトークンの `sub` の利用者）
    /// 2. **そのトークンを Bearer に付けて `registration_endpoint` へ `POST`**
    ///
    /// **口は `EnableDynamicClientRegistration` が true の配備にしか無い。**
    /// **無い配備では Skip する**（`SkipIfNotSupportedAsync`）。
    /// </remarks>
    public static class DynamicClientRegistration
    {
        /// <summary>管理 API 専用の scope（`Const.ScopeClientRegistration` と同じ値）</summary>
        public const string Scope = "client_registration";

        /// <summary>registration_endpoint を Discovery から引く（広告が無ければ null）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>registration_endpoint（無ければ null）</returns>
        public static async Task<string> EndpointAsync(IdPClient client)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

            return discovery.String("registration_endpoint");
        }

        /// <summary>この配備で動的登録が開いていなければ Skip する</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>registration_endpoint</returns>
        /// <remarks>
        /// **雛形の既定は無効**（`EnableDynamicClientRegistration`）。
        /// **E2E は `test.ps1 -Launch` が有効にして起動する**ので、
        /// **既に動いているサイトへ向けたときだけ Skip になる。**
        /// </remarks>
        public static async Task<string> SkipIfNotSupportedAsync(IdPClient client)
        {
            string endpoint = await DynamicClientRegistration.EndpointAsync(client);

            Skip.If(string.IsNullOrEmpty(endpoint),
                "registration_endpoint が広告されていません"
                + "（EnableDynamicClientRegistration が無効です）。");

            //  **コンテナ化・配備で絶対 URL が変わる**ので、このホストへ向け直す。
            return client.ToLocalUrl(endpoint);
        }

        /// <summary>ROPC で、管理 API 専用のアクセス トークンを取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id（専用 scope を登録したクライアント）</param>
        /// <param name="clientSecret">client_secret（出力しないこと）</param>
        /// <param name="userName">利用者名（この利用者が、登録の所有者になる）</param>
        /// <param name="password">パスワード（出力しないこと）</param>
        /// <param name="scope">要求する scope</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> TokenAsync(
            IdPClient client, string clientId, string clientSecret,
            string userName, string password, string scope = DynamicClientRegistration.Scope)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "password" },
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "username", userName },
                { "password", password },
                { "scope", scope }
            });
        }

        /// <summary>登録する（RFC 7591 §3.1）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="endpoint">registration_endpoint</param>
        /// <param name="accessToken">アクセス トークン（null なら Bearer を付けない）</param>
        /// <param name="metadata">クライアント メタデータ</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> RegisterAsync(
            IdPClient client, string endpoint, string accessToken, string metadata)
        {
            return client.PostJsonBodyWithAuthorizationAsync(endpoint, metadata,
                (accessToken == null) ? null : "Bearer " + accessToken);
        }

        /// <summary>`redirect_uris` だけのメタデータを作る</summary>
        /// <param name="redirectUris">折り返し先</param>
        /// <returns>JSON の文字列</returns>
        public static string Metadata(params string[] redirectUris)
        {
            return "{\"redirect_uris\":" + JsonSerializer.Serialize(redirectUris) + "}";
        }
    }
}
