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
//* クラス名        ：WebUi
//* クラス日本語名  ：ブラウザでしか測れないものを測るための土台
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Playwright;

using Xunit;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// ブラウザ（Chromium）でサイトを触るための土台（#277 の段階 7）。
    /// </summary>
    /// <remarks>
    /// **ここに置くのは、ブラウザでしか測れないものだけ**である。
    ///
    /// | | |
    /// |---|---|
    /// | ここで測る | **描画**（見て分かるか）、**JavaScript が要る画面**、**ブラウザ側の Cookie の扱い** |
    /// | ここで測らない | **HttpClient で測れるもの**。分野別のフォルダ（`Tests/Basic` など）に置く |
    ///
    /// **なぜ要るか。** **#277 の段階 6 の不具合**
    /// （Bootstrap 5 の `.form-control` が `appearance: none` を付け、
    /// **チェックの印が描かれなかった**）は、**HttpClient では原理的に見えない。**
    /// **値は正しく往復していた**ので、**画面を見るまで原因が分からなかった。**
    ///
    /// **ブラウザが無ければ Skip する**（netfx 版やコンテナと同じ流儀）。
    /// **入れ方** :
    ///
    /// ```
    /// pwsh programs\Tests\E2ETests\bin\Debug\net10.0\playwright.ps1 install chromium
    /// ```
    /// </remarks>
    public static class WebUi
    {
        #region ブラウザ

        /// <summary>ブラウザを開く（入っていなければ Skip する）</summary>
        /// <returns>IPlaywright と IBrowser</returns>
        /// <remarks>
        /// **呼ぶ側が using で閉じること**（`Browser` を Dispose すると Playwright も止まる）。
        /// **証明書は自己署名**なので、エラーを無視して開く。
        /// </remarks>
        public static async Task<Session> OpenAsync()
        {
            IPlaywright playwright;

            try
            {
                playwright = await Playwright.CreateAsync();
            }
            catch (Exception e)
            {
                Skip.If(true, "Playwright の driver を起動できません（" + e.GetType().Name + "）。");

                throw;
            }

            //  **3 通りを順に試す。**
            //    1. Playwright が持ってくる Chromium（`playwright.ps1 install chromium`）
            //    2. 入っている Google Chrome
            //    3. 入っている Microsoft Edge
            //
            //    **1 だけにしない。** **その場でダウンロードが要る**ので、
            //    **回線が通らない環境では、そのためだけに測れなくなる**（実測で踏んだ）。
            //    **2 / 3 は、開発機にはたいてい在る。**
            string reason = "";

            foreach (string channel in new string[] { null, "chrome", "msedge" })
            {
                try
                {
                    IBrowser browser = await playwright.Chromium.LaunchAsync(
                        new BrowserTypeLaunchOptions()
                        {
                            Headless = true,
                            Channel = channel
                        });

                    return new Session(playwright, browser, channel ?? "chromium");
                }
                catch (PlaywrightException e)
                {
                    reason += (channel ?? "chromium") + " : "
                        + e.Message.Split('\n')[0].Trim() + " / ";
                }
            }

            playwright.Dispose();

            //  **どれも開けない。**
            //    **netfx 版やコンテナと同じ扱い**（建っていなければ Skip）。
            Skip.If(true,
                "ブラウザを開けません。bin\\Debug\\net10.0\\playwright.ps1 install chromium "
                + "で入れるか、Chrome / Edge を入れてください（"
                + reason.TrimEnd(' ', '/') + "）。");

            throw new InvalidOperationException(reason);
        }

        /// <summary>開いたブラウザ（使い終わったら閉じる）</summary>
        public sealed class Session : IDisposable
        {
            /// <summary>コンストラクタ</summary>
            /// <param name="playwright">IPlaywright</param>
            /// <param name="browser">IBrowser</param>
            public Session(IPlaywright playwright, IBrowser browser, string channel)
            {
                this.Playwright = playwright;
                this.Browser = browser;
                this.Channel = channel;
            }

            /// <summary>使っているブラウザ（chromium / chrome / msedge）</summary>
            public string Channel { get; private set; }

            /// <summary>IPlaywright</summary>
            public IPlaywright Playwright { get; private set; }

            /// <summary>IBrowser</summary>
            public IBrowser Browser { get; private set; }

            /// <summary>自己署名の証明書を受け入れる文脈を作る</summary>
            /// <param name="target">対象（クライアント証明書を渡す先。省略可）</param>
            /// <returns>IBrowserContext</returns>
            /// <remarks>
            /// **クライアント証明書を渡す**（#277 の段階 7）。
            ///
            /// **E2E の net10.0 版は、mTLS を測るために
            /// `ClientCertificateMode.AllowCertificate` で起動している**
            /// （`test.ps1 -Launch` が `Tests/MtlsTestHook` を読ませる。#226）。
            /// **「無くても通す」設定だが、TLS では、サーバが証明書を要求する。**
            ///
            /// **HttpClient は、持っていなければ空で答えて先に進む。**
            /// **ブラウザは、どれを出すかを人に選ばせる**ので、
            /// **画面の無い Chromium では、そこで止まる**（**実測** : `goto` が 30 秒で時間切れ。
            /// **失敗した要求は 0 件**で、**同じサイトに HttpClient では届いていた**）。
            ///
            /// **原因はこれだけである**（**実測** : フックを読ませずに起動すると、
            /// **同じ通しの中で 10 秒で通った**）。
            ///
            /// **そこで、その場で作った自己署名のクライアント証明書を渡す。**
            /// **サーバは発行元を問わずに受け付ける**（`AllowAnyClientCertificate`）ので、
            /// **これで選択が要らなくなる。** **測っている内容は変わらない**
            /// （**この証明書で何かを認証しているわけではない**）。
            /// </remarks>
            public Task<IBrowserContext> NewContextAsync(TargetInfo target = null)
            {
                BrowserNewContextOptions options =
                    new BrowserNewContextOptions() { IgnoreHTTPSErrors = true };

                if (target != null)
                {
                    string keyPem;
                    string certPem =
                        TestCertificate.CreateClientCertificatePem("CN=e2e-webui", out keyPem);

                    options.ClientCertificates = new List<ClientCertificate>()
                    {
                        new ClientCertificate()
                        {
                            //  **Origin は scheme://host:port まで**（パスは付けない）。
                            Origin = new Uri(target.BaseUrl)
                                .GetLeftPart(UriPartial.Authority),
                            Cert = Encoding.UTF8.GetBytes(certPem),
                            Key = Encoding.UTF8.GetBytes(keyPem)
                        }
                    };
                }

                return this.Browser.NewContextAsync(options);
            }

            /// <summary>閉じる</summary>
            public void Dispose()
            {
                try
                {
                    this.Browser.CloseAsync().GetAwaiter().GetResult();
                }
                catch (Exception)
                {
                    // 閉じられなくても、測定の結果は変わらない。
                }

                this.Playwright.Dispose();
            }
        }

        /// <summary>画面を開く</summary>
        /// <param name="page">IPage</param>
        /// <param name="url">URL</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`load` ではなく `DOMContentLoaded` で進める。**
        /// **`load` は、絵や外部の資源まで待つ**ので、測りたいこと（描画）には要らない。
        /// </remarks>
        public static Task GotoAsync(IPage page, string url)
        {
            return page.GotoAsync(url,
                new PageGotoOptions() { WaitUntil = WaitUntilState.DOMContentLoaded });
        }

        #endregion

        #region サインイン

        /// <summary>画面からサインインする</summary>
        /// <param name="page">IPage</param>
        /// <param name="target">対象</param>
        /// <param name="userName">利用者名</param>
        /// <param name="password">パスワード</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **サインイン画面のボタンは、JavaScript で隠しフィールドを埋めてから submit する**
        /// （`submitButtonName`）。**ブラウザなので、そのまま押せばよい。**
        /// </remarks>
        public static async Task SignInAsync(
            IPage page, TargetInfo target, string userName, string password)
        {
            await WebUi.GotoAsync(page, target.Url("/Account/Login"));

            await page.FillAsync("#Email", userName);
            await page.FillAsync("#Password", password);
            await page.ClickAsync("#normal_signin");

            await page.WaitForURLAsync(u => !u.Contains("/Account/Login"),
                new PageWaitForURLOptions() { Timeout = 30000 });
        }

        #endregion
    }
}
