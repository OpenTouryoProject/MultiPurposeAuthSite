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
//* クラス名        ：FcmOutbox
//* クラス日本語名  ：プッシュ通知の送信箱（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/12  玄人 幸道         新規（認証デバイスの代わりに、プッシュ通知を受け取る）（#196）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

using Xunit;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// プッシュ通知の送信箱（テスト用）を読む。
    ///
    /// サーバは、構成の FcmOutboxDirectory が設定されているとき、プッシュ通知を FCM に送らず、
    /// そのディレクトリに JSON ファイルとして書く（#196）。
    /// テストは、それを**認証デバイス（authentication_device）の代わりに受け取る。**
    /// test.ps1 -Launch が、サイトごとに別のディレクトリを設定する（MPAS_CORE_FCM_OUTBOX / MPAS_NETFX_FCM_OUTBOX）。
    ///
    /// **中身には device_token や 2FA のコードが入るので、テストの出力に出さないこと。**
    /// </summary>
    public static class FcmOutbox
    {
        /// <summary>送信箱のプッシュ通知</summary>
        public sealed class Message
        {
            /// <summary>宛先のデバイス・トークン</summary>
            public string Token { get; set; }

            /// <summary>バナーのタイトル</summary>
            public string Title { get; set; }

            /// <summary>バナーの本文</summary>
            public string Body { get; set; }

            /// <summary>アプリが受け取るデータ</summary>
            public Dictionary<string, string> Data { get; set; }
        }

        /// <summary>送信箱が設定されていなければ Skip する</summary>
        /// <param name="target">テスト対象</param>
        /// <remarks>
        /// 送信箱なしで CIBA の成功経路に入ると、サーバは本物の FCM に送ろうとする。
        /// 資格情報が無ければ HTTP 500 になり、有れば実機に通知が飛ぶので、測らない。
        /// </remarks>
        public static void SkipIfUnavailable(TargetInfo target)
        {
            Skip.If(string.IsNullOrEmpty(target.FcmOutbox),
                "プッシュ通知の送信箱が設定されていません（test.ps1 -Launch で起動したときだけ測る）。");
        }

        /// <summary>data の項目が一致するプッシュ通知を待つ（届かなければ null）</summary>
        /// <param name="target">テスト対象</param>
        /// <param name="dataKey">data の項目名（auth_req_id など）</param>
        /// <param name="dataValue">その値</param>
        /// <param name="timeout">待つ時間</param>
        /// <returns>Message</returns>
        public static async Task<Message> WaitForAsync(
            TargetInfo target, string dataKey, string dataValue, TimeSpan timeout)
        {
            DateTime limit = DateTime.UtcNow + timeout;

            while (true)
            {
                if (Directory.Exists(target.FcmOutbox))
                {
                    foreach (string path in Directory.GetFiles(target.FcmOutbox, "*.json"))
                    {
                        Message message = Read(path);
                        string value;

                        if (message.Data.TryGetValue(dataKey, out value) && value == dataValue)
                        {
                            return message;
                        }
                    }
                }

                if (limit < DateTime.UtcNow)
                {
                    return null;
                }

                await Task.Delay(200);
            }
        }

        /// <summary>送信箱のファイルを読む</summary>
        /// <param name="path">ファイルのパス</param>
        /// <returns>Message</returns>
        private static Message Read(string path)
        {
            using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path)))
            {
                JsonElement root = doc.RootElement;

                Message message = new Message()
                {
                    Token = StringOf(root, "token"),
                    Title = StringOf(root, "title"),
                    Body = StringOf(root, "body"),
                    Data = new Dictionary<string, string>()
                };

                JsonElement data;
                if (root.TryGetProperty("data", out data) && data.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty p in data.EnumerateObject())
                    {
                        message.Data[p.Name] =
                            (p.Value.ValueKind == JsonValueKind.String) ? p.Value.GetString() : p.Value.ToString();
                    }
                }

                return message;
            }
        }

        /// <summary>文字列の項目を返す（無い・null なら null）</summary>
        /// <param name="root">JSON</param>
        /// <param name="name">項目名</param>
        /// <returns>値</returns>
        private static string StringOf(JsonElement root, string name)
        {
            JsonElement value;

            if (!root.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            return (value.ValueKind == JsonValueKind.String) ? value.GetString() : value.ToString();
        }
    }
}
