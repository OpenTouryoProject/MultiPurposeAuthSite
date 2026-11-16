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
//*  2026/09/10  玄人 幸道         JSON の null など、オブジェクトでない本文でも落ちないよう修正
//*  2026/09/12  玄人 幸道         本文を文字列として読む Text を追加（"OK" / "NG" で答えるエンドポイント用）（#196）
//*  2026/09/18  玄人 幸道         discovery の配列を見る ArrayContains を追加（#220）
//*  2026/10/02  玄人 幸道         配列を並びのまま返す Strings を追加（#129 の段階 2）
//*  2026/11/17  玄人 幸道         JARM の応答（response）の中のパラメタを広げて読む Unwrap を追加（#381）
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

        /// <summary>JARM の応答（`response` に JWT）なら、JWT のペイロードのパラメタを広げた写しを返す（#381）</summary>
        /// <returns>
        /// 写し（**外のパラメタが優先**。JARM でなければ、同じ中身の写し）。
        /// </returns>
        /// <remarks>
        /// **fapi1 の登録は JARM の要求だけを受ける**（#381）ので、その応答の `Code`・`State`・`Error` を読むために使う。
        /// **`Get` は変えていない**（JARM の応答で「`code` を URL に直接載せない」ことを測るテストがあるため。`EX-6`）。
        /// **署名は確かめない**（読むだけ。JARM の署名・`iss`・`aud` は JARM のテストが測る）。
        /// </remarks>
        public AuthZResponse Unwrap()
        {
            Dictionary<string, string> merged = new Dictionary<string, string>();
            Dictionary<string, string> jarm = this.JarmParameters();

            if (jarm != null)
            {
                foreach (KeyValuePair<string, string> p in jarm)
                {
                    merged[p.Key] = p.Value;
                }
            }

            foreach (KeyValuePair<string, string> p in this.Parameters)
            {
                merged[p.Key] = p.Value;
            }

            return new AuthZResponse()
            {
                StatusCode = this.StatusCode,
                Location = this.Location,
                RedirectTo = this.RedirectTo,
                Where = this.Where,
                Parameters = merged,
                Body = this.Body,
                RequestUrl = this.RequestUrl
            };
        }

        /// <summary>JARM の応答（`response`）のペイロードのパラメタ（JARM でなければ null）</summary>
        /// <returns>パラメタ</returns>
        private Dictionary<string, string> JarmParameters()
        {
            string jwt;

            if (!this.Parameters.TryGetValue("response", out jwt) || string.IsNullOrEmpty(jwt))
            {
                return null;
            }

            string[] parts = jwt.Split('.');

            if (parts.Length != 3)
            {
                return null;
            }

            try
            {
                string b64 = parts[1].Replace('-', '+').Replace('_', '/');
                b64 = b64.PadRight(b64.Length + ((4 - b64.Length % 4) % 4), '=');

                using (JsonDocument doc = JsonDocument.Parse(Convert.FromBase64String(b64)))
                {
                    Dictionary<string, string> ret = new Dictionary<string, string>();

                    foreach (JsonProperty p in doc.RootElement.EnumerateObject())
                    {
                        ret[p.Name] = (p.Value.ValueKind == JsonValueKind.String)
                            ? p.Value.GetString() : p.Value.GetRawText();
                    }

                    return ret;
                }
            }
            catch (Exception)
            {
                // 暗号化した JARM（JWE）や壊れた値は読まない
                return null;
            }
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
            // オブジェクトでない JSON（net48 の /revoke は成功時に null を返す）は、項目なしとみなす。
            if (!this.IsJson || this.Json.ValueKind != JsonValueKind.Object)
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

        /// <summary>配列のプロパティに、その文字列が入っているか（#220）</summary>
        /// <param name="name">プロパティ名（grant_types_supported など）</param>
        /// <param name="value">探す値</param>
        /// <returns>入っていれば true（配列でなければ false）</returns>
        public bool ArrayContains(string name, string value)
        {
            if (!this.IsJson || this.Json.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            JsonElement array;
            if (!this.Json.TryGetProperty(name, out array)
                || array.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (JsonElement item in array.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && item.GetString() == value)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>配列のプロパティを、その並びのまま返す（#129 の段階 2）</summary>
        /// <param name="name">プロパティ名（id_token_signing_alg_values_supported など）</param>
        /// <returns>値の配列（配列でなければ null）</returns>
        /// <remarks>
        /// **並びまで見たいとき**に使う（`ArrayContains` は「入っているか」だけ）。
        /// **文字列でない要素は ToString() で入れる**（広告の一覧は、どれも文字列のため）。
        /// </remarks>
        public string[] Strings(string name)
        {
            if (!this.IsJson || this.Json.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            JsonElement array;
            if (!this.Json.TryGetProperty(name, out array)
                || array.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            List<string> values = new List<string>();

            foreach (JsonElement item in array.EnumerateArray())
            {
                values.Add((item.ValueKind == JsonValueKind.String) ? item.GetString() : item.ToString());
            }

            return values.ToArray();
        }

        /// <summary>プロパティの JsonValueKind を返す（無ければ Undefined）</summary>
        /// <param name="name">プロパティ名</param>
        /// <returns>JsonValueKind</returns>
        public JsonValueKind KindOf(string name)
        {
            if (!this.IsJson || this.Json.ValueKind != JsonValueKind.Object)
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

        /// <summary>
        /// 本文を文字列として返す（JSON の文字列ならその値）。
        /// /SetDeviceToken・/ciba_result のように、"OK" / "NG" で答えるエンドポイント用。
        /// </summary>
        public string Text
        {
            get
            {
                if (this.IsJson && this.Json.ValueKind == JsonValueKind.String)
                {
                    return this.Json.GetString();
                }

                return (this.Body ?? "").Trim();
            }
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

            if (this.Json.ValueKind != JsonValueKind.Object)
            {
                return string.Format("HTTP {0} / JSON の {1}（オブジェクトではない）",
                    (int)this.StatusCode, this.Json.ValueKind);
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
