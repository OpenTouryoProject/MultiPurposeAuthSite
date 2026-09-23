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
//* クラス名        ：ClientModePolicy
//* クラス日本語名  ：登録種別ごとに、どの経路を許すか（表）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/22  玄人 幸道         新規（#224 の段階 1 : permittedLevel の大小比較を、表に置き換える）
//*  2026/09/22  玄人 幸道         既知でない登録値を fapi2 とみなさず、不正として扱う。MayUse を追加（#224 の段階 2）
//*  2026/09/22  玄人 幸道         表の注記 : mTLS の行を E2E（FA-6.1）で守るようにした（#226）
//**********************************************************************************

using System.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// 登録種別（oauth2_oidc_mode）ごとに、どの経路を許すか（#224）
    /// </summary>
    /// <remarks>
    /// **「経路 × 何を証明したか」から、通す登録種別を表で引く。**
    ///
    /// 以前は「この経路が認める水準（permittedLevel）」を数値で持ち、
    /// 「登録種別 &lt;= 水準」で判定していた。しかし
    /// ・device / fapi_ciba は水準ではなく種別で、fapi2 より上では「一致」に切り替えていた
    /// ・device を通すための例外がハードコードされていた
    /// ・経路の可否（refresh / ROPC などは normal だけ）まで、水準の数値で表していた
    /// ため、**1 本の順序では表せなくなっていた。**
    ///
    /// **段階 1 では、判定の結果を 1 つも変えていない。** 以前の判定を、そのまま表に展開したもの。
    /// 振る舞いを変えるときは、この表の行を書き換える（#224 の段階 2）。
    ///
    /// **表は、トークンを出す時点（証明が分かった後）の判定に使う。** それより前の段階
    /// （認可エンドポイント、/ciba_authz、refresh_token を渡すかどうか）では、
    /// 証明がまだ分からないので MayUse（その経路を、何かの証明で使えるか）で見る。
    /// </remarks>
    public static class ClientModePolicy
    {
        #region 経路と証明

        /// <summary>経路（グラント / 認可エンドポイントの応答の種類）</summary>
        public enum Flow
        {
            /// <summary>Implicit（認可エンドポイント）</summary>
            Implicit,
            /// <summary>Hybrid（認可エンドポイント）</summary>
            Hybrid,
            /// <summary>認可コード（トークン エンドポイント）</summary>
            AuthorizationCode,
            /// <summary>refresh_token</summary>
            RefreshToken,
            /// <summary>ROPC（password）</summary>
            ResourceOwnerPassword,
            /// <summary>client_credentials</summary>
            ClientCredentials,
            /// <summary>JWT Bearer（RFC 7523 の認可グラント）</summary>
            JwtBearer,
            /// <summary>CIBA</summary>
            Ciba,
            /// <summary>Device AuthZ</summary>
            DeviceAuthZ
        }

        /// <summary>クライアントが、その要求で何を証明したか</summary>
        public enum Proof
        {
            /// <summary>表の中だけで使う : 証明を問わない</summary>
            Any,
            /// <summary>証明なし（認可エンドポイント など）</summary>
            None,
            /// <summary>client_secret</summary>
            ClientSecret,
            /// <summary>client_secret と PKCE の併用（#220）</summary>
            ClientSecretAndPkce,
            /// <summary>PKCE の S256（client_secret なし）</summary>
            PkceS256,
            /// <summary>PKCE の plain（client_secret なし）</summary>
            PkcePlain,
            /// <summary>private_key_jwt（クライアント アサーション）</summary>
            PrivateKeyJwt,
            /// <summary>mTLS（クライアント証明書）</summary>
            Mtls
        }

        #endregion

        #region 表

        /// <summary>表の 1 行</summary>
        private sealed class Rule
        {
            /// <summary>経路</summary>
            public Flow Flow { get; }

            /// <summary>証明（Any なら問わない）</summary>
            public Proof Proof { get; }

            /// <summary>通す登録種別</summary>
            public OAuth2AndOIDCEnum.ClientMode[] Allowed { get; }

            /// <summary>constructor</summary>
            /// <param name="flow">経路</param>
            /// <param name="proof">証明</param>
            /// <param name="allowed">通す登録種別</param>
            public Rule(Flow flow, Proof proof, params OAuth2AndOIDCEnum.ClientMode[] allowed)
            {
                this.Flow = flow;
                this.Proof = proof;
                this.Allowed = allowed;
            }
        }

        private const OAuth2AndOIDCEnum.ClientMode Normal = OAuth2AndOIDCEnum.ClientMode.normal;
        private const OAuth2AndOIDCEnum.ClientMode Fapi1 = OAuth2AndOIDCEnum.ClientMode.fapi1;
        private const OAuth2AndOIDCEnum.ClientMode Fapi2 = OAuth2AndOIDCEnum.ClientMode.fapi2;
        private const OAuth2AndOIDCEnum.ClientMode Device = OAuth2AndOIDCEnum.ClientMode.device;
        private const OAuth2AndOIDCEnum.ClientMode FapiCiba = OAuth2AndOIDCEnum.ClientMode.fapi_ciba;

        /// <summary>
        /// **経路 × 証明 → 通す登録種別。** 表に無い組み合わせは、すべて拒否。
        /// </summary>
        /// <remarks>
        /// E2E で守られている行には、そのテストの識別子を書いた。
        /// **private_key_jwt の行は、E2E で守られていない。**
        /// mTLS の行は net10.0 版だけ E2E で守られている（net48 版は手動。#226）。
        /// </remarks>
        private static readonly Rule[] Rules = new Rule[]
        {
            // 認可エンドポイントで発行する経路
            new Rule(Flow.Implicit,              Proof.Any,                 Normal),                  // 21-1.1
            new Rule(Flow.Hybrid,                Proof.Any,                 Normal),                  // FA-1.4

            // 認可コード : 証明によって、通す登録種別が変わる
            new Rule(Flow.AuthorizationCode,     Proof.ClientSecret,        Normal),                  // FA-1.1
            new Rule(Flow.AuthorizationCode,     Proof.ClientSecretAndPkce, Normal),                  // FA-1.3
            new Rule(Flow.AuthorizationCode,     Proof.PkcePlain,           Normal),                  // RT-220.2
            new Rule(Flow.AuthorizationCode,     Proof.PkceS256,            Normal, Fapi1, Device),   // FA-1.1 / FA-3.1
            new Rule(Flow.AuthorizationCode,     Proof.PrivateKeyJwt,       Normal, Fapi1, Device),   // （E2E なし）
            new Rule(Flow.AuthorizationCode,     Proof.Mtls,                Normal, Fapi1, Fapi2),    // FA-6.1（net10.0 のみ）

            // 上記以外のグラント : 証明によらず normal だけ
            new Rule(Flow.RefreshToken,          Proof.Any,                 Normal),                  // FA-1.2
            new Rule(Flow.ResourceOwnerPassword, Proof.Any,                 Normal),                  // FA-1.1 / 21-1.1
            new Rule(Flow.ClientCredentials,     Proof.Any,                 Normal),                  // FA-1.1
            new Rule(Flow.JwtBearer,             Proof.Any,                 Normal),                  // EX-7

            // バックチャネル
            new Rule(Flow.Ciba,                  Proof.Any,                 FapiCiba),                // EX-8 / FA-5.1
            new Rule(Flow.DeviceAuthZ,           Proof.Any,                 Normal, Device)           // FA-4.1
        };

        #endregion

        #region 判定

        /// <summary>この登録種別に、この経路を許すか</summary>
        /// <param name="clientMode">登録種別</param>
        /// <param name="flow">経路</param>
        /// <param name="proof">その要求で証明したこと</param>
        /// <returns>許すなら true</returns>
        public static bool IsAllowed(OAuth2AndOIDCEnum.ClientMode clientMode, Flow flow, Proof proof)
        {
            Rule rule = ClientModePolicy.Rules.FirstOrDefault(
                x => x.Flow == flow && (x.Proof == Proof.Any || x.Proof == proof));

            return rule != null && rule.Allowed.Contains(clientMode);
        }

        /// <summary>この登録種別が、この経路を（何かの証明で）使えるか</summary>
        /// <param name="clientMode">登録種別</param>
        /// <param name="flow">経路</param>
        /// <returns>どれかの行が通すなら true</returns>
        /// <remarks>
        /// **証明が分かる前に、見込みの無い要求を断るために使う**（#224 の段階 2）。
        /// ・認可エンドポイント / /ciba_authz : 利用者に操作させた後で拒否しない
        /// ・refresh_token : 使えない資格情報を渡さない
        /// 通すかどうかの最終的な判定は、トークンを出す時点で IsAllowed が行う。
        /// </remarks>
        public static bool MayUse(OAuth2AndOIDCEnum.ClientMode clientMode, Flow flow)
        {
            return ClientModePolicy.Rules.Any(
                x => x.Flow == flow && x.Allowed.Contains(clientMode));
        }

        /// <summary>登録種別の文字列（oauth2_oidc_mode）を解釈する</summary>
        /// <param name="clientModeString">登録の値</param>
        /// <param name="clientMode">登録種別（解釈できなければ normal。使わないこと）</param>
        /// <returns>既知の値なら true</returns>
        /// <remarks>
        /// **既知のどれにも当たらない値（空・書き間違い）は、不正な登録として扱う**（#224 の段階 2）。
        /// 以前は fapi2 とみなしていた（初期値が fapi2 のまま残っていた）。
        /// 「一番厳しい種別」に倒す作りは、種別が増えると意味が変わるため、やめた。
        ///
        /// なお、**oauth2_oidc_mode を書いていない登録は normal**（Helper.GetClientMode の既定値）で、ここには来ない。
        /// </remarks>
        public static bool TryParse(string clientModeString, out OAuth2AndOIDCEnum.ClientMode clientMode)
        {
            foreach (OAuth2AndOIDCEnum.ClientMode mode in
                new OAuth2AndOIDCEnum.ClientMode[] { Normal, Fapi1, Fapi2, Device, FapiCiba })
            {
                if (clientModeString == mode.ToStringByEmit())
                {
                    clientMode = mode;
                    return true;
                }
            }

            clientMode = Normal;
            return false;
        }

        /// <summary>登録された種別で、この経路を（何かの証明で）使えるか</summary>
        /// <param name="clientModeString">登録の値（oauth2_oidc_mode）</param>
        /// <param name="flow">経路</param>
        /// <returns>使えるなら true。既知でない登録値なら false</returns>
        public static bool MayUse(string clientModeString, Flow flow)
        {
            return ClientModePolicy.TryParse(clientModeString, out OAuth2AndOIDCEnum.ClientMode clientMode)
                && ClientModePolicy.MayUse(clientMode, flow);
        }

        #endregion
    }
}
