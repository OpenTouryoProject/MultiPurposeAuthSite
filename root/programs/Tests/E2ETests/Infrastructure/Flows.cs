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
//* クラス名        ：Flows, KnownClients
//* クラス日本語名  ：よく使うフローの組み立て
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         JWK Set の取得を追加（拡張仕様のテスト）
//*  2026/09/11  玄人 幸道         scope を登録した TestClient5 を追加（#198 の後半）
//*  2026/09/11  玄人 幸道         トークンの更新・失効・問い合わせ（RefreshAsync / RevokeAsync / IntrospectAsync）を、テスト クラスから移す
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 構成ファイルに登録済みのクライアント。
    /// client_id は環境ごとに違う（CreateClientsIdentity.exe で生成する）ため、
    /// テストでは client_id を直書きせず client_name から引く。
    /// </summary>
    public static class KnownClients
    {
        /// <summary>redirect_uri が絶対URLで登録された、コンフィデンシャル クライアント</summary>
        public const string MvcSample = "MVC_Sample";

        /// <summary>自己テスト用（redirect_uri は test_self_code / test_self_token）</summary>
        public const string TestClient = "TestClient";

        /// <summary>FAPI1 用</summary>
        public const string TestClient1 = "TestClient1";

        /// <summary>FAPI2 用（Request Object を使う）</summary>
        public const string TestClient2 = "TestClient2";

        /// <summary>Device Authorization Grant 用（client_secret 無し ＝ パブリック）</summary>
        public const string TestClient3 = "TestClient3";

        /// <summary>CIBA 用</summary>
        public const string TestClient4 = "TestClient4";

        /// <summary>登録の scope で、要求してよいスコープを制限したクライアント（#198）</summary>
        public const string TestClient5 = "TestClient5";
    }

    /// <summary>クライアントの登録内容（テストから参照する分だけ）</summary>
    public sealed class ClientRegistration
    {
        /// <summary>client_id</summary>
        public string ClientId { get; set; }

        /// <summary>client_secret（出力しないこと）</summary>
        public string ClientSecret { get; set; }

        /// <summary>redirect_uri（response_type=code 用・解決済み）</summary>
        public string RedirectUri { get; set; }

        /// <summary>redirect_uri（response_type=token 用・解決済み）</summary>
        public string RedirectUriToken { get; set; }
    }

    /// <summary>よく使うフローの組み立て</summary>
    public static class Flows
    {
        /// <summary>client_name から登録内容を引く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <returns>ClientRegistration</returns>
        public static ClientRegistration Registration(IdPClient client, string clientName)
        {
            string clientId = client.Config.FindClientIdByName(clientName);

            if (string.IsNullOrEmpty(clientId))
            {
                throw new InvalidOperationException(
                    "client_name=" + clientName + " が構成ファイルに登録されていません: "
                    + client.Config.Path);
            }

            return new ClientRegistration()
            {
                ClientId = clientId,
                ClientSecret = client.Config.GetClientAttribute(clientId, "client_secret"),
                RedirectUri = ResolveRedirectUri(
                    client, client.Config.GetClientAttribute(clientId, "redirect_uri_code")),
                RedirectUriToken = ResolveRedirectUri(
                    client, client.Config.GetClientAttribute(clientId, "redirect_uri_token"))
            };
        }

        /// <summary>
        /// 登録された redirect_uri を、実際のURLに解決する。
        ///
        /// 自己テスト用のクライアントは、絶対URLではなく
        /// test_self_code / test_self_token という記号で登録されている。
        /// サーバは、これを構成ファイルの画面パスと突き合わせて実URLにする。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="value">登録値</param>
        /// <returns>解決したURL</returns>
        public static string ResolveRedirectUri(IdPClient client, string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }

            // サーバ側（CmnEndpoints.GetRedirectUriFromConstr）は
            // OAuth2ClientEndpointsRootURI を使う。ここも合わせる。
            string root = client.Config.Get("OAuth2ClientEndpointsRootURI");

            if (string.IsNullOrEmpty(root))
            {
                return value;
            }

            root = root.TrimEnd('/');

            if (value == "test_self_code")
            {
                return client.ToLocalUrl(
                    root + client.Config.Get("OAuth2AuthorizationCodeGrantClient_Account"));
            }

            if (value == "test_self_token")
            {
                return client.ToLocalUrl(
                    root + client.Config.Get("OAuth2ImplicitGrantClient_Account"));
            }

            // test_self_saml やカスタム スキーム（myapp:/oauthredirect）は、そのまま。
            return value;
        }

        /// <summary>
        /// 認可コードを取得する（サインイン済みであること）。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="scope">スコープ</param>
        /// <param name="state">state（null なら送らない）</param>
        /// <param name="nonce">nonce（null なら送らない）</param>
        /// <param name="redirectUri">redirect_uri（null なら送らない）</param>
        /// <param name="extra">追加パラメタ</param>
        /// <returns>AuthZResponse</returns>
        public static Task<AuthZResponse> AuthorizeCodeAsync(
            IdPClient client, ClientRegistration registration,
            string scope = "openid email", string state = "state1", string nonce = "nonce1",
            string redirectUri = null, IDictionary<string, string> extra = null)
        {
            Dictionary<string, string> q = new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "client_id", registration.ClientId },
                { "scope", scope },
                { "state", state },
                { "nonce", nonce },
                { "redirect_uri", redirectUri },

                // 同意画面を挟まず、サインイン済みのセッションでそのまま認可させる。
                { "prompt", "none" }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> p in extra)
                {
                    q[p.Key] = p.Value;
                }
            }

            return client.AuthorizeAsync(q);
        }

        /// <summary>
        /// 認可コードをトークンに交換する。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="code">認可コード</param>
        /// <param name="redirectUri">redirect_uri（null なら送らない）</param>
        /// <param name="extra">追加パラメタ</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> ExchangeCodeAsync(
            IdPClient client, ClientRegistration registration,
            string code, string redirectUri = null, IDictionary<string, string> extra = null)
        {
            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret },
                { "redirect_uri", redirectUri }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> p in extra)
                {
                    form[p.Key] = p.Value;
                }
            }

            return client.TokenAsync(form);
        }

        /// <summary>
        /// 認可コード フローを最後まで通し、トークン応答を返す。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <param name="scope">スコープ</param>
        /// <param name="nonce">nonce（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static async Task<JsonResponse> RunAuthorizationCodeFlowAsync(
            IdPClient client, string clientName = KnownClients.MvcSample,
            string scope = "openid email", string nonce = "nonce1")
        {
            ClientRegistration registration = Registration(client, clientName);

            AuthZResponse authz = await AuthorizeCodeAsync(
                client, registration, scope, "state1", nonce, registration.RedirectUri);

            if (string.IsNullOrEmpty(authz.Code))
            {
                throw new InvalidOperationException(
                    "認可コードを取得できませんでした: " + authz.ToString());
            }

            return await ExchangeCodeAsync(client, registration, authz.Code, registration.RedirectUri);
        }

        /// <summary>grant_type=refresh_token でトークンを取り直す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> RefreshAsync(
            IdPClient client, ClientRegistration registration, string refreshToken)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret }
            });
        }

        /// <summary>トークンを失効させる（POST /revoke）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント</param>
        /// <param name="token">失効させるトークン</param>
        /// <param name="tokenTypeHint">token_type_hint（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> RevokeAsync(
            IdPClient client, ClientRegistration registration, string token, string tokenTypeHint)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenTypeHint },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret }
            });
        }

        /// <summary>トークンを問い合わせる（POST /introspect）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント（null なら認証しない）</param>
        /// <param name="token">問い合わせるトークン</param>
        /// <param name="tokenTypeHint">token_type_hint（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> IntrospectAsync(
            IdPClient client, ClientRegistration registration, string token, string tokenTypeHint)
        {
            return client.IntrospectAsync(new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenTypeHint },
                { "client_id", registration == null ? null : registration.ClientId },
                { "client_secret", registration == null ? null : registration.ClientSecret }
            });
        }

        /// <summary>
        /// Discovery の jwks_uri から JWK Set を取得する。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <returns>JWK Set（keys 配列を持つ JSON）</returns>
        public static async Task<JsonElement> JwkSetAsync(IdPClient client)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            string jwksUri = discovery.String("jwks_uri");

            if (string.IsNullOrEmpty(jwksUri))
            {
                throw new InvalidOperationException(
                    "Discovery に jwks_uri がありません: " + discovery.ToString());
            }

            JsonResponse jwks = await client.GetJsonAsync(client.ToLocalUrl(jwksUri));

            if (!jwks.IsJson)
            {
                throw new InvalidOperationException(
                    "JWK Set を取得できませんでした: " + jwks.ToString());
            }

            return jwks.Json;
        }
    }
}
