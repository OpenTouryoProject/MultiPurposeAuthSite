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
//* クラス名        ：IdTokenAudience
//* クラス日本語名  ：id_token の aud が自分宛かを確認する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/12  玄人 幸道         新規（#286 の段階 5）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Sts へ移した（配置の見直し。#294）
//**********************************************************************************

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using MultiPurposeAuthSite.Extensions.Sts;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>
    /// `id_token` の `aud` が、自分（クライアント役）宛かを確認する（#286 の段階 5）。
    /// </summary>
    /// <remarks>
    /// **なぜ呼び出し側で確認するのか。**
    ///
    /// **`IdToken.Verify` は、この配備では `aud` を見ない。**
    /// **「自分は認可サーバか」（`JwkSetFilePath` の有無）で分岐**しており、
    /// **設定済みの側（＝認可サーバ役の枝）では `iss` と `exp` だけで通す**
    /// （Open棟梁 [#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601)）。
    /// **この配備は認可サーバなので、クライアント役の経路でもその枝に入る。**
    ///
    /// **検証不可ではない。** **`IdToken.Verify` は `out JObject` でペイロードを返す**ので、
    /// **呼び出し側が自分で確認できる。** **Open棟梁 側の変更を待たずに済む。**
    ///
    /// **SAML2 の ID 連携では `Audience` を照合している**
    /// （`SamlProviders.CmnSaml2Response` の `expectedAcsUrl`。#276）。
    /// **OIDC 側だけが抜けていた**、という形である。
    /// </remarks>
    public static class IdTokenAudience
    {
        /// <summary>
        /// `aud` が、期待するクライアント ID と一致するかを確認する。
        /// </summary>
        /// <param name="idTokenPayload">
        /// 検証済みの `id_token` のペイロード（`IdToken.Verify` の `out JObject`）。
        /// **null なら false**（署名の検証に失敗していれば null で来る）。
        /// </param>
        /// <param name="expectedAudience">
        /// 期待する値（自分のクライアント ID）。**ID 連携では、要求の `client_id` に使った値**である。
        /// </param>
        /// <returns>一致すれば true</returns>
        /// <remarks>
        /// **`aud` は、文字列でも配列でもよい**（RFC 7519 4.1.3 / OIDC Core 2）。
        /// **どちらでも読む。** **複数入っていれば、その中に在ればよい。**
        ///
        /// **`azp` は見ない。** **`azp` が要るのは「`aud` が複数あるとき、
        /// どのクライアントのために出したか」を言う場合**であり、
        /// **この ID 連携は上流に 1 つのクライアントとして登録される**ので、
        /// **`aud` が自分を含むことだけを確認する。**
        ///
        /// **無い / 空は false**（通さない）。
        /// **「返さない上流がある」ことを理由に通す作りにはしない** —
        /// **`aud` は OIDC Core が必須としているクレーム**である。
        /// </remarks>
        public static bool Matches(JObject idTokenPayload, string expectedAudience)
        {
            if (idTokenPayload == null || string.IsNullOrEmpty(expectedAudience))
            {
                return false;
            }

            JToken aud = idTokenPayload[OAuth2AndOIDCConst.aud];

            if (aud == null)
            {
                return false;
            }

            if (aud.Type == JTokenType.Array)
            {
                // 配列（複数の宛先）
                foreach (JToken token in (JArray)aud)
                {
                    if (expectedAudience == (string)token)
                    {
                        return true;
                    }
                }

                return false;
            }

            // 文字列（宛先は 1 つ）
            return expectedAudience == (string)aud;
        }
    }
}
