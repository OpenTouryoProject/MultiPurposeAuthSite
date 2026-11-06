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
//*  2026/11/06  玄人 幸道         Open棟梁 が aud を照合するようになった（OpenTouryo#601・#603）後も残す理由を書いた（#337）
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
    /// **なぜ呼び出し側でも確認するのか。**
    ///
    /// **以前は、`IdToken.Verify` がこの配備では `aud` を見なかった**ので、ここで補っていた
    /// （「自分は認可サーバか」で分岐し、認可サーバ役の枝では `iss` と `exp` だけで通した。
    /// Open棟梁 [#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601)）。
    ///
    /// **いまは Open棟梁 も `aud` を照合する**（OpenTouryo#601・#603）。
    ///
    /// | `IdToken.Verify` | 照合する `aud` |
    /// |---|---|
    /// | 鍵を指定する版 | 渡した値（ID 連携では `upstream.ClientId`） |
    /// | 鍵を指定しない版（1:1 の構成の名残） | **設定の client_id（`ClientID`・`ClientIDs`）のどれか** |
    ///
    /// **それでも残す**（#337）。**鍵を指定しない版が見るのは、設定の client_id**（1:1 の構成の値。`OAuth2AndOidcClientID`）で、
    /// **n 件の構成で上流の鍵が決まらずにそちらへ進んだとき、その上流のクライアント ID（`upstream.ClientId`）とは限らない。**
    /// ここで期待値を、その上流のクライアント ID に決めて照合する。**鍵を指定する版では、Open棟梁 と同じ照合を重ねるだけ**で、受ける範囲は変わらない。
    ///
    /// **software_statement の `aud` の確認にも使う**（`SoftwareStatementProvider`。こちらは回避策ではない）。
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
