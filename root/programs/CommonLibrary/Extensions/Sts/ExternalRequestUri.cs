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
//* クラス名        ：ExternalRequestUri
//* クラス日本語名  ：外部の request_uri を取りに行き、預けた request_uri（urn:）に置き換える（#374）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/19  玄人 幸道         新規（#374）
//**********************************************************************************

using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **外部の `request_uri`（RP が置いた Request Object。OIDC Core 1.0 §6.2）を取りに行き、預けた `request_uri`（`urn:`）に置き換える**（#374）
    /// </summary>
    /// <remarks>
    /// | 順 | 確かめること | 合わなければ |
    /// |---|---|---|
    /// | 1 | **この OP の `urn:` なら、そのまま**（PAR・`/ros` で預けたもの） | — |
    /// | 2 | **`client_id` が在ること** | `invalid_request` |
    /// | 3 | **登録の `request_uris` に在ること**（`#` から後ろを除いて完全一致。OIDC Registration 1.0 §2） | **`request_uri_not_supported`**（#362 のまま。登録の無いクライアントは、以前どおり断る） |
    /// | 4 | **行き先のアドレス**（`OutboundUrlPolicy`。#376。登録の後で名前解決の結果が変わっていれば取りに行かない） | `invalid_request_uri` |
    /// | 5 | **取りに行く**（専用の HttpClient。リダイレクトを追わない。`Timeout`・`MaxResponseBytes`） | `invalid_request_uri`（OIDC Core 1.0 §3.1.2.6） |
    /// | 6 | **署名した Request Object であること**（`/ros` と同じ検証。`alg=none` は受けない。CIBA の要求は受けない） | `invalid_request_object` |
    ///
    /// **通れば `/ros` と同じく `urn:` に預け、以後はその `urn:` で続ける**（**呼び出し元の GET の `/authorize` は、その `urn:` の認可の URL へ送り直す**ので、未サインイン・再認証の往復で、取りに行き直さない）。
    /// **#346 の経路の印は「PAR ではない・署名を検証した」**（`/ros` と同じ）。
    /// **`client_id` と Request Object の中の `client_id` の一致は、`urn:` を読む側（`AccountController`）が確かめる**（#362）。
    /// </remarks>
    public static class ExternalRequestUri
    {
        #region 定数

        /// <summary>error : request_uri_not_supported（OIDC Core 1.0 §3.1.2.6）</summary>
        public const string RequestUriNotSupported = "request_uri_not_supported";

        /// <summary>error : invalid_request_uri（OIDC Core 1.0 §3.1.2.6）</summary>
        public const string InvalidRequestUri = "invalid_request_uri";

        /// <summary>取りに行くときの時間の上限</summary>
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        /// <summary>取りに行くときの大きさの上限（Request Object は小さい）</summary>
        public const int MaxResponseBytes = 64 * 1024;

        #endregion

        #region 結果

        /// <summary>結果</summary>
        public class Result
        {
            /// <summary>使う request_uri（この OP の `urn:`。断ったときは元の値）</summary>
            public string RequestUri { get; set; }

            /// <summary>error（通れば null）</summary>
            public string Error { get; set; }

            /// <summary>error_description</summary>
            public string ErrorDescription { get; set; }
        }

        #endregion

        #region 本体

        /// <summary>外部の request_uri を取りに行き、預けた request_uri（`urn:`）に置き換える</summary>
        /// <param name="clientId">クエリの client_id</param>
        /// <param name="requestUri">クエリの request_uri</param>
        /// <returns>結果</returns>
        public static async Task<Result> ResolveAsync(string clientId, string requestUri)
        {
            //  1. **無い・この OP の `urn:` なら、そのまま**（以降は `AccountController` が扱う）。
            if (string.IsNullOrEmpty(requestUri)
                || requestUri.StartsWith(OAuth2AndOIDCConst.UrnRequestUriBase, StringComparison.Ordinal))
            {
                return new Result() { RequestUri = requestUri };
            }

            //  2. **どのクライアントの登録で見るかが要る**（OIDC Core 1.0 §6.2 も client_id を求める）。
            if (string.IsNullOrEmpty(clientId))
            {
                return ExternalRequestUri.Fail(requestUri,
                    OAuth2AndOIDCConst.invalid_request, "The client_id is required with an external request_uri.");
            }

            //  3. **登録の `request_uris` に在るものだけ**（`#` から後ろを除いて完全一致）。
            //    **無ければ、以前どおり `request_uri_not_supported`**（#362）。
            string target = ExternalRequestUri.WithoutFragment(requestUri);
            List<string> registered = Helper.GetInstance().GetClientRequestUris(clientId);

            if (!registered.Any(u => string.Equals(ExternalRequestUri.WithoutFragment(u), target, StringComparison.Ordinal)))
            {
                return ExternalRequestUri.Fail(requestUri, ExternalRequestUri.RequestUriNotSupported,
                    "The request_uri is not registered in the request_uris of the client.");
            }

            //  4. **行き先のアドレス**（#376）。**登録の後で名前解決の結果が変わっていれば、取りに行かない。**
            if (!OutboundUrlPolicy.IsAllowed(target))
            {
                return ExternalRequestUri.Fail(requestUri, ExternalRequestUri.InvalidRequestUri,
                    "The request_uri could not be retrieved.");
            }

            //  5. **取りに行く**（失敗の理由は、応答で撃ち分けない。ログに型だけ残す）。
            string requestObject = await ExternalRequestUri.GetStringAsync(target).ConfigureAwait(false);

            if (string.IsNullOrEmpty(requestObject))
            {
                return ExternalRequestUri.Fail(requestUri, ExternalRequestUri.InvalidRequestUri,
                    "The request_uri could not be retrieved.");
            }

            //  6. **署名した Request Object であること**（`/ros` と同じ検証。`alg=none` は鍵を選べずに断られる）。
            //    **CIBA の要求（`client_notification_token`）は、認可要求に使わない。**
            if (ExternalRequestUri.IsCibaRequest(requestObject)
                || !CmnRequestObjectEndpoint.RegisterRequestObject(requestObject, out Dictionary<string, object> registeredObject))
            {
                return ExternalRequestUri.Fail(requestUri, OAuth2AndOIDCConst.invalid_request_object,
                    "The request object at the request_uri is not verified.");
            }

            //  **預けた `urn:` で続ける**（送り返しても、取りに行き直さない）。
            return new Result() { RequestUri = (string)registeredObject[OAuth2AndOIDCConst.request_uri] };
        }

        #endregion

        #region private

        /// <summary>断る</summary>
        /// <param name="requestUri">元の request_uri</param>
        /// <param name="error">error</param>
        /// <param name="description">error_description</param>
        /// <returns>結果</returns>
        private static Result Fail(string requestUri, string error, string description)
        {
            return new Result() { RequestUri = requestUri, Error = error, ErrorDescription = description };
        }

        /// <summary>`#` から後ろを除く</summary>
        /// <param name="uri">URI</param>
        /// <returns>`#` から後ろを除いた URI</returns>
        public static string WithoutFragment(string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                return "";
            }

            int hash = uri.IndexOf('#');
            return (hash < 0) ? uri : uri.Substring(0, hash);
        }

        /// <summary>CIBA の要求か（`client_notification_token` が在る）</summary>
        /// <param name="requestObject">Request Object</param>
        /// <returns>CIBA の要求なら true</returns>
        private static bool IsCibaRequest(string requestObject)
        {
            Newtonsoft.Json.Linq.JObject payload = JwtUtil.TryReadPayloadAsIs(requestObject);
            return payload != null && payload.ContainsKey(OAuth2AndOIDCConst.client_notification_token);
        }

        /// <summary>URL を GET して、本文を文字列で読む（2xx でなければ・上限を超えれば null）</summary>
        /// <param name="url">URL</param>
        /// <returns>本文（前後の空白を除く）</returns>
        private static async Task<string> GetStringAsync(string url)
        {
            try
            {
                using (CancellationTokenSource cts = new CancellationTokenSource(ExternalRequestUri.Timeout))
                using (HttpResponseMessage response = await OutboundUrlPolicy.HttpClient.GetAsync(
                    new Uri(url), HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false))
                {
                    //  **リダイレクトは追わない**（専用の HttpClient）ので、3xx は 2xx でないとして読めない。
                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    using (Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                    using (MemoryStream buffer = new MemoryStream())
                    {
                        byte[] chunk = new byte[8192];
                        int read;

                        while ((read = await stream.ReadAsync(chunk, 0, chunk.Length, cts.Token).ConfigureAwait(false)) > 0)
                        {
                            if (ExternalRequestUri.MaxResponseBytes < buffer.Length + read)
                            {
                                throw new InvalidDataException("The request object is too large.");
                            }

                            buffer.Write(chunk, 0, read);
                        }

                        return Encoding.UTF8.GetString(buffer.ToArray()).Trim();
                    }
                }
            }
            catch (Exception ex)
            {
                //  **URL は出さない**（RP の情報）。**型だけ残す。**
                Logging.MyOperationTrace(string.Format(
                    "The external request_uri could not be retrieved. ({0})", ex.GetType().Name));

                return null;
            }
        }

        #endregion
    }
}
