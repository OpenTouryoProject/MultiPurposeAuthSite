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
//* クラス名        ：CreateJwkSetJson
//* クラス日本語名  ：JWKSetJson情報の生成ツール（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/08/15  西野 大介         新規
//*  2026/10/02  玄人 幸道         署名に使う鍵をすべて載せる（#129 の段階 3 / D-9）
//**********************************************************************************

using System;
using System.IO;

using Newtonsoft.Json.Linq;

using MultiPurposeAuthSite.TokenProviders;

using Touryo.Infrastructure.Framework.Authentication;

using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace CreateJwkSetJson
{
    /// <summary>
    /// `jwkcerts` が返す JWK Set（`JwkSet.json`）を作る。
    /// </summary>
    /// <remarks>
    /// **アプリが署名に使う鍵を、そのまま載せる。**
    /// 載せる鍵は **`SigningKeys` の表**（CommonLibrary）が決める。
    /// **このツールは、その 1 ファイルをソース参照している**（`Compile Include` の `Link`）。
    /// ＝ **アプリが発行できる alg と、公開鍵の一覧が食い違わない**（D-9）。
    ///
    /// **追記しかしない。** 既に載っている `kid` は、そのまま残す。
    /// **鍵の入れ替え（ローテーション）で要るのは、この性質**である
    /// （新しい鍵を先に載せ、RP のキャッシュが切れてから署名に使う。`CONFIGURATION.md`）。
    /// **退役した鍵を外すのは、手で消す**（＝ 消すのは人が決める）。
    /// </remarks>
    class Program
    {
        static void Main(string[] args)
        {
#if NETCORE
            // configの初期化
            GetConfigParameter.InitConfiguration("appsettings.json");
#endif

            // JwkSet.jsonファイルの存在チェック
            if (!ResourceLoader.Exists(OAuth2AndOIDCParams.JwkSetFilePath, false))
            {
                // 新規
                File.Create(OAuth2AndOIDCParams.JwkSetFilePath).Close();
            }
            else
            {
                // 既存？
            }

            // JwkSet.jsonファイルのロード
            JwkSet jwkSetObject = JwkSet.LoadJwkSet(OAuth2AndOIDCParams.JwkSetFilePath);

            if (jwkSetObject == null)
            {
                // 新規（空のファイルだった）
                jwkSetObject = new JwkSet();
            }

            int before = jwkSetObject.keys.Count;

            // **署名に使う鍵を、すべて載せる**（#129 の段階 3）。
            //   RS256 / RS384 / RS512 は同じ鍵（kid も同じ）なので、2 つ目以降は追記されない。
            foreach (string alg in SigningKeys.SupportedAlgs)
            {
                SigningKeys.Entry key = SigningKeys.Of(alg);
                JObject jwkObject = key.JwkFromCer();

                // kidの重複確認（追記しかしない）
                JwkSet.AddJwkToJwkSet(jwkSetObject, jwkObject);

                Console.WriteLine("{0,-5} kid={1} <- {2}",
                    alg, (string)jwkObject[JwtConst.kid], key.CerFilePath);
            }

            // jwkSetObjectのセーブ
            JwkSet.SaveJwkSet(OAuth2AndOIDCParams.JwkSetFilePath, jwkSetObject);

            Console.WriteLine();
            Console.WriteLine("{0} : 鍵 {1} 本（{2} 本を追記）",
                OAuth2AndOIDCParams.JwkSetFilePath,
                jwkSetObject.keys.Count, jwkSetObject.keys.Count - before);
        }
    }
}
