//**********************************************************************************
//* クラス名        ：TestResource
//* クラス日本語名  ：テスト用の資源（適合性テスト・E2E 用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規作成（#425）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

using Touryo.Infrastructure.Framework.Authentication;

using Token = MultiPurposeAuthSite.TokenProviders;

/// <summary>MultiPurposeAuthSite.Util.Test</summary>
namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>テスト用の資源（`/TestResource`。#425）</summary>
    /// <remarks>
    /// **`openid` を求めない、アクセス トークンで守った資源**である。
    /// **適合性テスト（Conformance Suite）の FAPI 2.0 の `openid=plain_oauth`・client_credentials のプランは、
    /// 最後に資源（`resource.resourceUrl`）をトークンで呼び、200 を求める**。
    /// **`/userinfo` は `openid` の無いトークンを `403`（`insufficient_scope`）で断る**（OIDC Core 1.0 §5.3・RFC 6750 §3.1）ので、そこでは測れない。
    ///
    /// **トークンの照合は `/userinfo` と同じ製品の部品**（`CmnAccessToken.VerifyAccessToken`・`VerifyCertificateBinding`・`VerifyDPoPBinding`）
    /// **で行う**（**資源の側の送信者の拘束**（RFC 8705 §3・RFC 9449 §7.1）**を、外部の基準で測るため**）。
    /// **ここに置くのは、口の両版（net48・net10.0）で同じ中身にする部分だけ**である。
    ///
    /// **`IsLockedDownTestEndpoints` が true なら、口を開かない**（経路を張らず、動作も 404 を返す）。
    /// **さらに `IsDebug` でなければ開かない**（**キーを書き忘れた本番でも開かない**。#425 の別モデルのレビューの指摘。
    /// `mem` は常に `IsDebug`。適合性テスト・E2E の構成は開く）。
    /// **製品の経路から呼ばれない**（`QUALITY.md` 1 節の `Util.Test`）。
    /// </remarks>
    public static class TestResource
    {
        /// <summary>口が開いているか（`IsDebug` で、`IsLockedDownTestEndpoints` が false）</summary>
        public static bool IsOpen
        {
            get
            {
                return TestResource.IsOpenFor(Config.IsDebug, Config.IsLockedDownTestEndpoints);
            }
        }

        /// <summary>口が開くかを、設定の値から決める（単体テストで測る。#425）</summary>
        /// <param name="isDebug">`IsDebug`</param>
        /// <param name="isLockedDownTestEndpoints">`IsLockedDownTestEndpoints`</param>
        /// <returns>開くなら true（`IsDebug` で、閉じる指定が無いときだけ）</returns>
        public static bool IsOpenFor(bool isDebug, bool isLockedDownTestEndpoints)
        {
            return isDebug && !isLockedDownTestEndpoints;
        }

        /// <summary>200 の本文を作る</summary>
        /// <param name="identity">検証できた access_token の ClaimsIdentity</param>
        /// <returns>本文（`client_id`・`scope`）</returns>
        /// <remarks>**利用者の属性は返さない**（資源が「呼べた」ことだけを示す）。</remarks>
        public static Dictionary<string, object> ResponseOf(ClaimsIdentity identity)
        {
            Claim audience = identity.Claims.FirstOrDefault(
                x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim);

            return new Dictionary<string, object>()
            {
                { OAuth2AndOIDCConst.client_id, audience?.Value ?? "" },
                {
                    OAuth2AndOIDCConst.scope,
                    string.Join(" ", identity.Claims
                        .Where(x => x.Type == OAuth2AndOIDCConst.UrnScopesClaim)
                        .Select(x => x.Value))
                }
            };
        }

        /// <summary>FAPI の登録のトークンなら、応答に付ける `x-fapi-interaction-id` を決める</summary>
        /// <param name="identity">検証できた access_token の ClaimsIdentity</param>
        /// <param name="requested">要求の `x-fapi-interaction-id`（無ければ null）</param>
        /// <returns>付ける値（FAPI の登録でなければ null）</returns>
        /// <remarks>**`/userinfo` と同じ決め**（FAPI 1.0 Baseline §6.2.1 の 11・12。#384）。</remarks>
        public static string FapiInteractionIdOf(ClaimsIdentity identity, string requested)
        {
            Claim audience = identity.Claims.FirstOrDefault(
                x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim);

            if (audience == null || !Helper.GetInstance().IsFapiProfileClient(audience.Value))
            {
                return null;
            }

            string interactionId = Token.CmnEndpoints.FapiInteractionIdOf(requested);

            //  **ログにも残す**（§6.2.1 の 12。`/userinfo` と同じ。**トークン・利用者の属性は書かない**）。
            Logging.MyOperationTrace(string.Format(
                "/TestResource was called with x-fapi-interaction-id: {0} (client_id: {1})",
                interactionId, audience.Value));

            return interactionId;
        }
    }
}
