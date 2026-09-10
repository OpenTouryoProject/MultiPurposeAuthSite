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
//* クラス名        ：AuthZResponse, TokenResponse
//* クラス日本語名  ：各エンドポイントの応答
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>パラメタの返却位置</summary>
    public enum ParameterLocation
    {
        /// <summary>リダイレクトしなかった（エラー画面など）</summary>
        None,

        /// <summary>クエリ文字列（?）</summary>
        Query,

        /// <summary>フラグメント（#）</summary>
        Fragment
    }

    /// <summary>認可エンドポイントの応答</summary>
    public sealed class AuthZResponse
    {
        /// <summary>HTTPステータス</summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>Locationヘッダ（無ければ null）</summary>
        public string Location { get; set; }

        /// <summary>リダイレクト先のパス部（クエリ・フラグメントを除く）</summary>
        public string RedirectTo { get; set; }

        /// <summary>パラメタの返却位置</summary>
        public ParameterLocation Where { get; set; }

        /// <summary>返却されたパラメタ</summary>
        public Dictionary<string, string> Parameters { get; set; }

        /// <summary>本文（リダイレクトしなかった場合のみ意味を持つ）</summary>
        public string Body { get; set; }

        /// <summary>このリクエストを送ったURL（同意画面のPOST先に使う）</summary>
        public string RequestUrl { get; set; }

        /// <summary>
        /// 同意画面（OAuth2Authorize）が返ってきたか。
        /// prompt=none を付けない認可リクエストでは、ここで一度止まる。
        /// </summary>
        public bool NeedsConsent
        {
            get
            {
                return !this.Redirected
                    && !string.IsNullOrEmpty(this.Body)
                    && this.Body.Contains("submit.Grant");
            }
        }

        /// <summary>リダイレクトしたか</summary>
        public bool Redirected
        {
            get { return !string.IsNullOrEmpty(this.Location); }
        }

        /// <summary>パラメタを返す（無ければ null）</summary>
        /// <param name="name">パラメタ名</param>
        /// <returns>値</returns>
        public string Get(string name)
        {
            string value;
            return this.Parameters.TryGetValue(name, out value) ? value : null;
        }

        /// <summary>認可コード</summary>
        public string Code
        {
            get { return this.Get("code"); }
        }

        /// <summary>state</summary>
        public string State
        {
            get { return this.Get("state"); }
        }

        /// <summary>error</summary>
        public string Error
        {
            get { return this.Get("error"); }
        }

        /// <summary>error_description</summary>
        public string ErrorDescription
        {
            get { return this.Get("error_description"); }
        }

        /// <summary>診断用の要約（秘密情報を含めない）</summary>
        /// <returns>要約</returns>
        public override string ToString()
        {
            List<string> names = new List<string>(this.Parameters.Keys);
            names.Sort();

            return string.Format(
                "HTTP {0} / redirect={1} / where={2} / params=[{3}] / error={4} ({5}){6}",
                (int)this.StatusCode,
                this.Redirected ? this.RedirectTo : "(なし)",
                this.Where,
                string.Join(", ", names),
                this.Error ?? "-",
                this.ErrorDescription ?? "-",
                this.NeedsConsent ? " / 同意画面" : "");
        }
    }

    /// <summary>トークン エンドポイントなど、JSONを返すエンドポイントの応答</summary>
    public sealed class JsonResponse
    {
        /// <summary>HTTPステータス</summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>Content-Type</summary>
        public string ContentType { get; set; }

        /// <summary>
        /// 応答ヘッダ（Cache-Control / Pragma / WWW-Authenticate を見るため）。
        /// 同名が複数あるときは ", " で連結する。
        /// </summary>
        public Dictionary<string, string> Headers { get; set; }

        /// <summary>ヘッダを返す（無ければ null）</summary>
        /// <param name="name">ヘッダ名</param>
        /// <returns>値</returns>
        public string Header(string name)
        {
            if (this.Headers == null)
            {
                return null;
            }

            string value;
            return this.Headers.TryGetValue(name, out value) ? value : null;
        }

        /// <summary>JSONとして解釈できたか</summary>
        public bool IsJson { get; set; }

        /// <summary>JSON（IsJson が false のときは Undefined）</summary>
        public JsonElement Json { get; set; }

        /// <summary>
        /// 本文。access_token などを含むため、テストの出力に出さないこと。
        /// </summary>
        public string Body { get; set; }

        /// <summary>文字列プロパティを返す（無ければ null）</summary>
        /// <param name="name">プロパティ名</param>
        /// <returns>値</returns>
        public string String(string name)
        {
            if (!this.IsJson)
            {
                return null;
            }

            JsonElement value;
            if (!this.Json.TryGetProperty(name, out value))
            {
                return null;
            }

            return (value.ValueKind == JsonValueKind.String) ? value.GetString() : value.ToString();
        }

        /// <summary>プロパティの JsonValueKind を返す（無ければ Undefined）</summary>
        /// <param name="name">プロパティ名</param>
        /// <returns>JsonValueKind</returns>
        public JsonValueKind KindOf(string name)
        {
            if (!this.IsJson)
            {
                return JsonValueKind.Undefined;
            }

            JsonElement value;
            return this.Json.TryGetProperty(name, out value) ? value.ValueKind : JsonValueKind.Undefined;
        }

        /// <summary>access_token</summary>
        public string AccessToken
        {
            get { return this.String("access_token"); }
        }

        /// <summary>id_token</summary>
        public string IdToken
        {
            get { return this.String("id_token"); }
        }

        /// <summary>refresh_token</summary>
        public string RefreshToken
        {
            get { return this.String("refresh_token"); }
        }

        /// <summary>error</summary>
        public string Error
        {
            get { return this.String("error"); }
        }

        /// <summary>error_description</summary>
        public string ErrorDescription
        {
            get { return this.String("error_description"); }
        }

        /// <summary>診断用の要約（秘密情報を含めない）</summary>
        /// <returns>要約</returns>
        public override string ToString()
        {
            if (!this.IsJson)
            {
                return string.Format("HTTP {0} / 非JSON ({1}, {2} bytes)",
                    (int)this.StatusCode, this.ContentType ?? "-",
                    this.Body == null ? 0 : this.Body.Length);
            }

            List<string> names = new List<string>();
            foreach (JsonProperty p in this.Json.EnumerateObject())
            {
                names.Add(p.Name);
            }
            names.Sort();

            return string.Format("HTTP {0} / keys=[{1}] / error={2} ({3})",
                (int)this.StatusCode, string.Join(", ", names),
                this.Error ?? "-", this.ErrorDescription ?? "-");
        }
    }
}
