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
//* クラス名        ：Config
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の STS（防御）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//*  2026/10/28  玄人 幸道         メアド検証・パスワード リセットのメールの間隔を足した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（STS（防御））</summary>
    public partial class Config
    {
        #region 認証の失敗回数

        /// <summary>
        /// 認証の失敗を、この回数で断る（#305 の段階 2）
        /// </summary>
        /// <remarks>
        /// **クライアント認証（`client_secret` / mTLS）と、
        /// `user_code` の投入**の失敗を数える（`Extensions/Sts/AuthFailureProvider`）。
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **数えない**（従来どおり） |
        /// | 正の回数（雛形は 5） | **連続してこの回数失敗したら、`AuthFailureLockoutSeconds` の間断る** |
        ///
        /// **断っている間は、正しい資格情報でも通さない**（ロックアウトの意味）。
        /// **成功したら回数は消える。**
        ///
        /// **利用者のパスワードは、ASP.NET Identity 側で数えている**
        /// （`MaxFailedAccessAttemptsBeforeLockout`）。**こちらは別の口である。**
        ///
        /// **数えるのは「クライアント ＋ 送信元」ごと**である（#305 の段階 4）。
        /// **`client_id` だけで数えると、誰でもそのクライアントを止められる。**
        /// </remarks>
        public static int AuthFailureMaxAttempts
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureMaxAttempts");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は 0**（数えない。従来どおり）。
                    return 0;
                }

                int attempts = 0;
                return int.TryParse(value, out attempts) ? attempts : 0;
            }
        }

        /// <summary>
        /// 認証の失敗が上限に達したとき、断る長さ（秒。#305 の段階 2）
        /// </summary>
        /// <remarks>**未設定は 300 秒**（5 分）。</remarks>
        public static int AuthFailureLockoutSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureLockoutSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    return 300;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds) ? seconds : 300;
            }
        }

        /// <summary>
        /// 認証の失敗を、いつまで覚えているか（秒。#305 の段階 4）
        /// </summary>
        /// <remarks>
        /// **最後の失敗からこの時間が過ぎると、数えた分は忘れる**
        /// （**間隔を空けた失敗が、いつまでも積み上がらない**）。
        /// **行の寿命もこれで決まる** — **期限の過ぎた行は掃除される**
        /// （`AuthFailureProvider.PruneExpired`）。
        ///
        /// **未設定は `AuthFailureLockoutSeconds` と同じ**（雛形では 300 秒）。
        ///
        /// **`AuthFailureMaxAttempts` 回を試すのに掛かる時間より、長くすること。**
        /// **短いと、数が積まれる前に忘れるので、いつまでも断らない。**
        /// </remarks>
        public static int AuthFailureWindowSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureWindowSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は、断る長さと同じ。**
                    return Config.AuthFailureLockoutSeconds;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds)
                    ? seconds : Config.AuthFailureLockoutSeconds;
            }
        }

        #endregion

        #region レート制限

        /// <summary>
        /// 口ごとのレート制限 : クライアント 1 つあたりの上限（#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **`client_id` が分かる要求を、`client_id` ごとに数える**
        /// （`Extensions/Sts/RateLimitProvider`）。**窓は `RateLimitWindowSeconds`。**
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **制限しない**（従来どおり） |
        /// | 正の回数（雛形は 120） | **窓の中でこの回数を超えた要求に `429`**（`Retry-After` 付き） |
        ///
        /// **数えるのは口ごと**である（`/token` の洪水で `/revoke` が止まらない）。
        /// **段階 2 は「失敗の回数」、ここは「要求の回数」**（成否を問わない）。
        /// </remarks>
        public static int RateLimitPerClientPermits
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitPerClientPermits");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は 0**（制限しない。従来どおり）。
                    return 0;
                }

                int permits = 0;
                return int.TryParse(value, out permits) ? permits : 0;
            }
        }

        /// <summary>
        /// 口ごとのレート制限 : 送信元 1 つあたりの上限（#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **`client_id` が分からない要求**（`/jwkcerts` の読み出しなど）**と、**
        /// **`client_id` が分かる要求の両方**を、**送信元アドレスごとに数える。**
        /// **`client_id` を毎回変えて `client_id` ごとの上限を避ける**攻撃に、これが効く。
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **制限しない**（従来どおり） |
        /// | 正の回数（雛形は 600） | **窓の中でこの回数を超えた要求に `429`** |
        ///
        /// **リバース プロキシの後ろでは、見えるアドレスはプロキシのものになる。**
        /// **net10.0 版は `UseForwardedHeaders`**（設定キーも同名。`ForwardedHeadersKnownProxies` と併せて使う）**で元に戻せるが、**
        /// **net48 版は戻さない**（`Request.UserHostAddress` をそのまま使う）。
        /// **プロキシの後ろに置く配備では、プロキシ側で制限する方が確かである。**
        /// </remarks>
        public static int RateLimitPerIpPermits
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitPerIpPermits");

                if (string.IsNullOrEmpty(value))
                {
                    return 0;
                }

                int permits = 0;
                return int.TryParse(value, out permits) ? permits : 0;
            }
        }

        /// <summary>
        /// 口ごとのレート制限 : 数える窓の長さ（秒。#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **未設定は 60 秒。**
        /// **窓は固定窓**（`UNIX 時刻 / 窓` で切る。窓が変わると回数は 0 に戻る）。
        /// **窓の境目では、瞬間的に上限の 2 倍まで通り得る**
        /// （固定窓の性質。**滑る窓にするほどの精度は、ここでは要らない**）。
        /// </remarks>
        public static int RateLimitWindowSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitWindowSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    return 60;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds) ? seconds : 60;
            }
        }

        #endregion

        #region メールの送り過ぎ

        /// <summary>
        /// メアド検証・パスワード リセットのメールを、1 人に送る間隔（秒。#294）
        /// </summary>
        /// <remarks>
        /// **サインアップ・パスワードの失念は、誰でも何度でも押せる**ので、
        /// **他人の受信箱をメールで埋められた**（`Extensions/Sts/MailThrottle`）。
        ///
        /// | 値 | 振る舞い |
        /// |---|---|
        /// | **0（または未設定）** | **絞らない**（従来どおり） |
        /// | 正の秒数（雛形は 60） | **同じ利用者・同じ用途のメールは、この間隔に 1 通まで**（**画面は変えない**） |
        /// </remarks>
        public static int MailResendIntervalSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("MailResendIntervalSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    return 0;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds) ? seconds : 0;
            }
        }

        #endregion

        #region ポーリングの slow_down

        /// <summary>
        /// ポーリングが速すぎるときに `slow_down` を返すか（#305 の段階 1）
        /// </summary>
        /// <remarks>
        /// **Device Authorization Grant と CIBA は、クライアントが `/token` を繰り返し叩く。**
        /// **間隔は `interval`**（`DeviceAuthZPollingIntervalSeconds` /
        /// `CibaPollingIntervalSeconds`）**で伝えてあるが、守らなくても何も起きなかった。**
        ///
        /// **true なら、前回から `interval` 未満で来た要求に `slow_down` を返す**
        /// （RFC 8628 §3.5 / CIBA §11。**クライアントは間隔を 5 秒伸ばす**）。
        ///
        /// **未設定なら true**（**仕様どおりの振る舞い**）。
        /// **false にすると従来どおり**、`authorization_pending` を返し続ける。
        /// </remarks>
        public static bool EnablePollingSlowDown
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("EnablePollingSlowDown");

                //  **未設定は true**（仕様どおり）。**false と書いたときだけ止める。**
                if (string.IsNullOrEmpty(value))
                {
                    return true;
                }

                bool enabled = true;
                return bool.TryParse(value, out enabled) ? enabled : true;
            }
        }

        #endregion
    }
}