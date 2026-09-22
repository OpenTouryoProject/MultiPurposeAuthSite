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
//*  2026/09/18  玄人 幸道         既定で無効な機能を Skip する口を追加（#220）
//*  2026/09/18  玄人 幸道         TestClient6 と、未登録なら Skip する口を追加（#221）
//*  2026/09/22  玄人 幸道         環境変数で差し込む TestClient4_2 と、その登録を引く口を追加（#224）
//*  2026/09/22  玄人 幸道         登録値が不正な TestClient4_3 を追加（#224 の段階 2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using Xunit;

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

        /// <summary>クライアント単位で PKCE を必須にしたクライアント（#221）</summary>
        public const string TestClient6 = "TestClient6";

        /// <summary>
        /// TestClient4（fapi_ciba）を写し、登録種別だけ normal にしたクライアント（#224）。
        /// **構成ファイルには無い。** test.ps1 -Launch が環境変数でサイトへ差し込む
        /// （Flows.InjectedRegistration で引く）。
        /// </summary>
        public const string TestClient4_2 = "TestClient4_2";

        /// <summary>
        /// TestClient4（fapi_ciba）を写し、登録種別を既知でない値（fapi_1）にしたクライアント（#224 の段階 2）。
        /// **構成ファイルには無い。** TestClient4_2 と同じく test.ps1 -Launch が差し込む。
        /// </summary>
        public const string TestClient4_3 = "TestClient4_3";
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

        #region 既定で無効な機能の Skip（#220）

        /// <summary>
        /// discovery に広告されていない grant_type なら Skip する（#220）
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="grantType">grant_type</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **OAuth 2.1 に寄せて、Implicit / ROPC は雛形の既定で無効にした（#220）。**
        /// 有効にしている環境では従来どおり測り、無効な環境では Skip する。
        /// discovery は設定を反映するので、そこを見れば分かる。
        /// </remarks>
        public static async Task SkipIfGrantTypeNotSupportedAsync(IdPClient client, string grantType)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

            Skip.IfNot(discovery.ArrayContains("grant_types_supported", grantType),
                "grant_type=" + grantType + " が無効です（#220 で既定を無効にした）。");
        }

        /// <summary>
        /// そのクライアントが構成ファイルに登録されていなければ Skip する（#221）
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <remarks>
        /// **雛形に足したクライアントは、既存の環境の実設定には無い。**
        /// 実設定は各自のものなので、雛形を当て直すまでは登録されていない。
        /// その間は測れないので Skip する（**登録すれば、そのまま測れる**）。
        /// </remarks>
        public static void SkipIfClientNotRegistered(IdPClient client, string clientName)
        {
            Skip.If(string.IsNullOrEmpty(client.Config.FindClientIdByName(clientName)),
                "client_name=" + clientName + " が構成ファイルに登録されていません（#221 で雛形に追加）。");
        }

        /// <summary>
        /// test.ps1 が環境変数で差し込んだクライアントの登録内容を引く（#224）。差し込まれていなければ Skip する
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name（TestClient4_2 / TestClient4_3）</param>
        /// <returns>ClientRegistration（client_id と client_secret だけ）</returns>
        /// <remarks>
        /// **構成ファイルには無いクライアント**なので、Registration では引けない。
        /// 差し込むのは `test.ps1 -Launch` だけで、既に動いているサイトへ向けたときは Skip する。
        /// </remarks>
        public static ClientRegistration InjectedRegistration(IdPClient client, string clientName)
        {
            // test.ps1 -Launch が、起動したサイトに差し込んだ client_id を渡してくる（MPAS_<client_name の大文字>）。
            bool known = clientName == KnownClients.TestClient4_2 || clientName == KnownClients.TestClient4_3;
            string clientId = known
                ? Environment.GetEnvironmentVariable("MPAS_" + clientName.ToUpperInvariant()) : null;

            Skip.If(string.IsNullOrEmpty(clientId),
                "client_name=" + clientName + " は差し込まれていません"
                + "（test.ps1 -Launch のときだけサイトへ差し込む。#224）。");

            // client_secret と公開鍵は TestClient4 の写しなので、構成ファイルの TestClient4 から引ける。
            ClientRegistration source = Flows.Registration(client, KnownClients.TestClient4);

            return new ClientRegistration()
            {
                ClientId = clientId,
                ClientSecret = source.ClientSecret
            };
        }

        #endregion
    }
}
