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
//* クラス名        ：IdFederationSaml2Request
//* クラス日本語名  ：ID 連携（SAML2）の AuthnRequest を、上流ごとの鍵で作る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 4-a。Open棟梁 #606 の追随）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System.Security.Cryptography;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// ID 連携（SAML2）の `AuthnRequest` を、**上流ごとの鍵で**作る（#292 の段階 4-a）。
    /// </summary>
    /// <remarks>
    /// **(2)（下流 → 上流の要求）の署名鍵を、相手ごとに替えられるようにしたもの**である。
    ///
    /// | | 鍵 |
    /// |---|---|
    /// | **行に `signing_pfx_file_path` が在る** | **その `.pfx`**（相手ごと） |
    /// | 空 | **共通設定**（`SpRp_RsaPfxFilePath`。**従来どおり**） |
    ///
    /// **Open棟梁 [#606](https://github.com/OpenTouryoProject/OpenTouryo/issues/606) で、
    /// `SAML2Client.CreateRedirectRequest` に鍵を渡せるようになった。**
    /// **それまでは、Open棟梁 が設定から 1 本だけ読んでいた**ので、相手ごとに分けられなかった。
    ///
    /// **両アプリの `AccountController` に同文で置かない**ため、`CommonLibrary` に在る
    /// （`IdFederationSaml2Metadata` と同じ理由）。
    /// </remarks>
    public static class IdFederationSaml2Request
    {
        /// <summary>
        /// その上流へ送る `AuthnRequest`（Redirect Binding）のクエリ文字列を作る。
        /// </summary>
        /// <param name="upstream">上流の登録</param>
        /// <param name="relayState">RelayState（送った state）</param>
        /// <param name="id">out 作った要求の ID（応答の `InResponseTo` と照合する）</param>
        /// <returns>クエリ文字列（`SAMLRequest` ＋ `SigAlg` ＋ `Signature`）</returns>
        /// <remarks>
        /// **`Issuer` は `http://` ＋ 上流に登録された `client_id`**
        /// （**上流はこれで SP の登録を引く**。`CmnEndpoints.VerifySamlRequest`）。
        ///
        /// **ACS URL は入れない**（**上流が登録値（`redirect_uri_saml`）から解決する**。#276）。
        ///
        /// **`NameIDFormat` は `EmailAddress`**（#286 の決め事）。
        /// </remarks>
        public static string CreateRedirectRequest(
            IdFederationUpstream upstream, string relayState, out string id)
        {
            id = "";

            if (upstream == null)
            {
                return "";
            }

            // **上流に登録された client_id**（OIDC の ID 連携と同じものを使う）。
            string issuer = "http://" + upstream.ClientId;

            DigitalSign digitalSign = IdFederationSaml2Request.SigningKeyOf(upstream);

            if (digitalSign == null)
            {
                //  **鍵を渡さない**（**Open棟梁 が共通設定から読む**。従来どおり）。
                return SAML2Client.CreateRedirectRequest(
                    SAML2Enum.RequestOrResponse.Request,
                    SAML2Enum.ProtocolBinding.HttpRedirect,
                    SAML2Enum.NameIDFormat.EmailAddress,
                    issuer, "", relayState, out id);
            }

            //  **この上流用の鍵で署名する**（Open棟梁 #606 の口）。
            return SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpRedirect,
                SAML2Enum.NameIDFormat.EmailAddress,
                issuer, "", relayState, digitalSign, out id);
        }

        /// <summary>その上流用の署名鍵（無ければ null）</summary>
        /// <param name="upstream">上流の登録</param>
        /// <returns>DigitalSign（無ければ null ＝ 共通設定に倒す）</returns>
        /// <remarks>
        /// **読めなければ null を返す**（**共通設定に倒れる**）。**理由はログに残す**（#253）。
        /// **ここで落とさない** — **鍵の設定を間違えただけで、連携の口が死ぬのを避ける。**
        /// </remarks>
        private static DigitalSign SigningKeyOf(IdFederationUpstream upstream)
        {
            if (upstream == null || string.IsNullOrEmpty(upstream.SigningPfxFilePath))
            {
                return null;
            }

            try
            {
                //  **パスワードは、行に在ればそれ。無ければ共通設定**
                //    （**同じ `.pfx` のパスワードを 2 か所に書かせない**）。
                string password = string.IsNullOrEmpty(upstream.SigningPfxPassword)
                    ? CmnClientParams.RsaPfxPassword : upstream.SigningPfxPassword;

                return new DigitalSignX509(
                    upstream.SigningPfxFilePath, password, HashAlgorithmName.SHA256);
            }
            catch (System.Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The signing key for an ID federation upstream could not be read. "
                        + "(key: {0}, {1})", upstream.Key, ex.GetType().Name));

                return null;
            }
        }
    }
}
