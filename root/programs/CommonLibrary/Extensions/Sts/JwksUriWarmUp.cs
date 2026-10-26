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
//* クラス名        ：JwksUriWarmUp
//* クラス日本語名  ：登録済みの jwks_uri を、起動のときに温める
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#309 の段階 2）
//*  2026/10/22  玄人 幸道         鍵の取得を Open棟梁 の RemoteJwkSetStore に移した（#294）
//*  2026/10/26  玄人 幸道         DataProvider の改名（Saml2OAuth2DataProvider）に追従した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **登録済みの `jwks_uri` を、起動のときに温める**（#309 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **クライアント認証は、キャッシュを読むだけである**（段階 1 の決め (A)）。
    /// **キャッシュはプロセスの中に在る**ので、**起こし直した直後は空**で、
    /// **最初のクライアント認証が 1 回断られる**（段階 1 の決め (C)(1)）。
    /// **ここで先に読んでおけば、その窓が小さくなる。**
    ///
    /// **窓は消えない。**
    ///
    /// | | |
    /// |---|---|
    /// | **net10.0** | **`Startup.Configure` から呼ぶ** — **要求を受ける前**なので、ほぼ間に合う |
    /// | **net48** | **`Application_Start` は、最初の要求が来るまで走らない**（IIS Express / アプリ プール）。**その要求自身は、温めを待たない** |
    ///
    /// **だから段階 1 の「1 回断って、背景で取り直す」は残してある。**
    /// **ここは「速くする」ための仕掛けであって、「必ず通す」ための仕掛けではない。**
    ///
    /// **起動を待たせない。** **失敗しても起動を止めない**（**理由はログに残す**）。
    /// </remarks>
    public static class JwksUriWarmUp
    {
        /// <summary>一度に温める URL の数の上限</summary>
        /// <remarks>
        /// **登録が何千件も在る配備で、起動と同時に外へ何千本も出さない**ため。
        /// **設定キーは増やさない**（#309 の段階 2 の決め (C)）。
        ///
        /// **上限に当たった分は、従来どおり要求のときに背景で読む**
        /// （**断られるのは、その 1 本だけ**）。
        /// </remarks>
        private const int MaxUrls = 100;

        /// <summary>登録済みの `jwks_uri` を、背景で温める（待たない）</summary>
        /// <remarks>
        /// **呼ぶのは両アプリの起動**（`Global.asax` / `Startup.Configure`）。
        ///
        /// **`Task.Run` で投げるだけ**である — **起動の経路を待たせない。**
        /// **同期コンテキストを持たないスレッドで走る**ので、
        /// **net48 でも継続が詰まらない**（#309 の起票）。
        /// </remarks>
        public static void StartInBackground()
        {
            Task.Run(async () =>
            {
                try
                {
                    await JwksUriWarmUp.WarmUpAllAsync();
                }
                catch (Exception ex)
                {
                    //  **起動の背景で走る**ので、**例外を外へ出さない。**
                    Logging.MyOperationTrace(string.Format(
                        "The jwks_uri warm-up failed. ({0})", ex.GetType().Name));
                }
            });
        }

        /// <summary>登録済みの `jwks_uri` を、順に読む</summary>
        /// <returns>読めた URL の数</returns>
        /// <remarks>
        /// **直列に読む**（**起動と同時に、外向きの接続を何十本も出さない**）。
        /// **1 本が読めなくても続ける**（`RemoteJwkSetStore` が例外を飲む）。
        /// </remarks>
        public static async Task<int> WarmUpAllAsync()
        {
            List<string> urls = JwksUriWarmUp.Collect();
            int warmed = 0;

            foreach (string url in urls)
            {
                if (await RemoteJwkSetStore.WarmUpAsync(url))
                {
                    warmed++;
                }
            }

            // オペレーション・トレース・ログ出力
            //   **URL は出さない**（**どこを読んだかは配備の情報**である）。**数だけ残す。**
            //   **0 件でも出す** ＝ **この仕掛けが動いていることを、運用で見られるようにする**
            //   （**起動のログに 1 行だけ出る**）。
            Logging.MyOperationTrace(string.Format(
                "The jwks_uri warm-up read {0} of {1} JWK Sets.", warmed, urls.Count));

            return warmed;
        }

        /// <summary>温める URL を集める（設定 ＋ user store。重複は除く）</summary>
        /// <returns>URL の一覧</returns>
        /// <remarks>
        /// **設定ファイルのクライアントも見る**（`OAuth2ClientsInformation` の `jwks_uri`）。
        /// **`JwksUri` が空でない行は、全部温める** —
        /// **`private_key_jwt` に絞らない**（**Request Object（JAR）の検証にも使い得る**）。
        ///
        /// **`https` でなければ集めない**（**ループバックの `http` は許す**。
        /// **判定は `RemoteJwkSetStore.IsUsableKeySource` の 1 か所**である）。
        /// </remarks>
        private static List<string> Collect()
        {
            List<string> urls = new List<string>();

            //  **設定ファイル**（**user store を読めない配備でも効く**ので、先に見る）。
            JwksUriWarmUp.AddRange(urls, Helper.GetInstance().GetConfiguredJwksUris());

            //  **user store**（**読めなければログに残して進む** — **起動を止めない**）。
            try
            {
                JwksUriWarmUp.AddRange(urls, Saml2OAuth2DataProvider.GetAllJwksUris());
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The registered jwks_uri could not be read from the user store. ({0})",
                    ex.GetType().Name));
            }

            return urls;
        }

        /// <summary>重複と、使えない URL を除いて足す</summary>
        /// <param name="urls">足し先（上限まで）</param>
        /// <param name="added">足す URL</param>
        private static void AddRange(List<string> urls, List<string> added)
        {
            if (added == null)
            {
                return;
            }

            foreach (string url in added)
            {
                if (JwksUriWarmUp.MaxUrls <= urls.Count)
                {
                    return;
                }

                //  **使える URL かの判定は `RemoteJwkSetStore` に 1 つだけ置いてある**
                //    （**登録の検査と同じ規則で絞る** — **2 か所に書くと食い違う**）。
                if (string.IsNullOrEmpty(url)
                    || urls.Contains(url)
                    || !RemoteJwkSetStore.IsUsableKeySource(url))
                {
                    continue;
                }

                urls.Add(url);
            }
        }
    }
}
