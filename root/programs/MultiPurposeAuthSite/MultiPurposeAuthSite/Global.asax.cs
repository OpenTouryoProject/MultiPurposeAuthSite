//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：Global
//* クラス日本語名  ：Global.asaxのコード ビハインド
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  20xx/xx/xx  西野 大介         新規
//*  2011/12/07  西野 大介         Application_ErrorにACCESSログを追加
//*  2012/04/05  西野 大介         Application_OnPreRequestHandlerExecute
//*                                OnPostRequestHandlerExecuteにACCESSログを追加
//*  2026/09/17  玄人 幸道         開発向けの設定が残っていないかを起動時に確かめる（#219）
//*  2026/09/30  玄人 幸道         OAuth2AndOIDCClient の HttpClient を初期化（#250 の段階 4）
//*  2026/10/07  玄人 幸道         /Fido2/ 専用のセッション有効化を削除（#137）
//*  2026/10/08  玄人 幸道         AntiForgery の Cookie にも接頭辞を掛ける（#282）
//*  2026/10/16  玄人 幸道         口ごとのレート制限を入口に掛ける（#305 の段階 3）
//*  2026/10/21  玄人 幸道         起動のときに jwks_uri を温める（#309 の段階 2）
//**********************************************************************************

// System
using System;
using System.Net.Http;
using System.Web;
using System.Web.Helpers;   // AntiForgeryConfig（#282）
using System.Web.SessionState;

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util.Sts;
using Sts = MultiPurposeAuthSite.Extensions.Sts;   // RateLimitProvider（#305 の段階 3）

// OpenTouryo
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Log;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite
{
    /// <summary>Global.asax class </summary>
    public class Global : System.Web.HttpApplication
    {
        /////////////////////////////////////////////////////////////////////////////////
        // Global_asaxのメンバ変数(インスタンス変数）はスレッドセーフ
        /////////////////////////////////////////////////////////////////////////////////

        // ここにインスタンス変数を定義した場合、これは、各スレッドに割り当てられる。
        // 故に、マルチスレッド（ユーザ）のASP.NETアプリケーションでも競合しない。
        // http:// support.microsoft.com/kb/312607/ja

        // ---

        // 静的変数の場合は競合する。

        // ASP.NET1.0、1.1では、Applicationオブジェクトではなく、静的変数の使用が推奨されていたが、
        // ASP.NET2.0では、静的変数が使用できないので、静的変数ではなく、Applicationオブジェクトを
        // 使用する（ただし、Applicationオブジェクトも競合するので注意する）。

        /// <summary>性能測定</summary>                                                       
        private PerformanceRecorder perfRec;

        /////////////////////////////////////////////////////////////////////////////////
        // イベント ハンドラ
        /////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////
        // アプリケーションの開始、終了に関するイベント
        ///////////////////////////////////////////////////

        /// <summary>
        /// アプリケーションの開始に関するイベント
        /// </summary>
        void Application_Start(object sender, EventArgs e)
        {
            // アプリケーションのスタートアップで実行するコード

            // **OAuth2AndOIDCClient の HttpClient を初期化する**（#250 の段階 4）。
            //   **net10.0 版は Program.Main で同じことをしている。** net48 版には無かった。
            //
            //   **これまでは Helper のコンストラクタ（Singleton）が設定していた**ので、
            //   Helper を一度でも通れば入っていた。
            //   **#140 の段階 3 で、ID フェデレーションが Helper を通さなくなった**ため
            //   （Helper は宛先を GetContainerizatedAuthZServerUri で書き換えてしまう）、
            //   **Helper に一度も触れていない状態で /token を叩くと、null 参照で落ちる。**
            //
            //   **Helper が後から自分のクライアントで上書きするのは、net10.0 版と同じ。**
            OAuth2AndOIDCClient.HttpClient = new HttpClient();

            // **開発向けの設定が残っていないかを確かめる**（#219。CONFIGURATION.md 11 節）。
            //   起動は止めない。警告を OPERATION ログに出すだけ。
            ProductionCheck.WarnIfRisky();

            // **登録済みの jwks_uri を、背景で温める**（#309 の段階 2）。
            //   **クライアント認証はキャッシュを読むだけ**（段階 1）なので、
            //   **起こし直した直後は、最初の 1 本が断られる。**
            //
            //   **net48 では、ここは最初の要求が来てから走る**（IIS Express / アプリ プール）。
            //   **その要求自身は温めを待たない**ので、**窓は残る** —
            //   **段階 1 の「1 回断って、背景で取り直す」が、そこを受ける。**
            //
            //   **待たない。** **失敗しても起動を止めない**（理由はログに残す）。
            Sts.JwksUriWarmUp.StartInBackground();

            // **AntiForgery の Cookie にも接頭辞を掛ける**（#282。#255 の続き）。
            //   **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
            //   **同じホストに 2 つ建てると互いに上書きする。**
            //
            //   **既定の名前は `__RequestVerificationToken` に仮想パス由来の接尾が付く**ので、
            //   **仮想パスが違えば分かれるが、同じパスで 2 つ建てると衝突する。**
            //
            //   **静的な設定なので、ここ（Application_Start）で 1 度だけ行う。**
            //   net10.0 版は `PostConfigure<AntiforgeryOptions>`（Startup）で行っている。
            //
            //   **接頭辞が空なら、名前は従来どおりである**（PrefixCookieName がそのまま返す）。
            if (!string.IsNullOrEmpty(Config.CookieNamePrefix))
            {
                AntiForgeryConfig.CookieName =
                    Config.PrefixedCookieName(AntiForgeryConfig.CookieName);
            }
        }

        /// <summary>
        /// アプリケーションの終了に関するイベント
        /// </summary>
        void Application_End(object sender, EventArgs e)
        {
            // アプリケーションのシャットダウンで実行するコード
        }

        ///////////////////////////////////////////////////
        // アプリケーションのエラーに関するイベント
        ///////////////////////////////////////////////////

        /// <summary>
        /// アプリケーションのエラーに関するイベント
        /// </summary>
        void Application_Error(object sender, EventArgs e)
        {
            // ハンドルされていないエラーが発生したときに実行するコード

            Exception ex = Server.GetLastError().GetBaseException();
            //Server.ClearError(); // Server.GetLastError()をクリア

            // ACCESSログ出力 ----------------------------------------------

            // ------------
            // メッセージ部
            // ------------
            // ユーザ名, IPアドレス,レイヤ, 
            // 画面名, コントロール名, メソッド名, 処理名
            // 処理時間（実行時間）, 処理時間（CPU時間）
            // エラーメッセージID, エラーメッセージ等
            // ------------
            string strLogMessage =
                "," + "－" +
                "," + Request.UserHostAddress +
                "," + "－" +
                "," + "Global.asax" +
                "," + "Application_Error" +
                ",,,,," + ex.ToString();

            // Log4Netへログ出力
            LogIF.FatalLog("ACCESS", strLogMessage);

            // -------------------------------------------------------------
        }

        ///////////////////////////////////////////////////
        // セッションの開始、終了に関するイベント
        ///////////////////////////////////////////////////

        /// <summary>
        /// セッションの開始に関するイベント
        /// </summary>
        void Session_Start(object sender, EventArgs e)
        {
            // 新規セッションを開始したときに実行するコード
        }

        /// <summary>
        /// セッションの終了に関するイベント
        /// </summary>
        void Session_End(object sender, EventArgs e)
        {
            // セッションが終了したときに実行するコード

            // Web.configファイル内でsessionstateモードが[InProc]に設定されているときのみ、Session_Endイベントが発生する。
            // sessionstateモードが[StateServer]か、または[SQLServer]に設定されている場合、イベントは発生しない。

        }

        /////////////////////////////////////////////////////////////////////////////////
        // ASP.NETパイプライン処理のイベント ハンドラ
        /////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////

        // Global.asaxが対応しているASP.NETパイプライン処理のイベント ハンドラの一覧
        // -----------------------------------------------------------------------------------
        // ① Application_OnBeginRequest                :リクエスト処理を開始する前に発生 
        // ② Application_OnAuthenticateRequest         :認証の直前に発生 
        // ③ Application_OnAuthorizeRequest            :認証が完了したタイミングで発生 
        // ④ Application_OnResolveRequestCache         :リクエストをキャッシングするタイミングで発生 
        // ⑤ Application_OnAcquireRequestState         :セッション状態などを取得するタイミングで発生 
        // ⑥ Application_OnPreRequestHandlerExecute    :ページの実行を開始する直前に発生 
        // ⑦ Application_OnPostRequestHandlerExecute   :ページの実行を完了した直後に発生 
        // ⑧ Application_OnReleaseRequestState         :すべての処理を完了したタイミングで発生 
        // ⑨ Application_OnUpdateRequestCache          :出力キャッシュを更新したタイミングで発生 
        // ⑩ Application_OnEndRequest                  :すべてのリクエスト処理が完了したタイミングで発生 
        // ⑪ Application_OnPreSendRequestHeaders       :ヘッダをクライアントに送信する直前に発生 
        // ⑫ Application_OnPreSendRequestContent       :コンテンツをクライアントに送信する直前に発生 

        // イベント・ハンドラはこの表の順番で呼び出される。

        // ただし、Application_OnPreSendRequestHeadersメソッドや
        // Application_OnPreSendRequestContentメソッドは
        // バッファ処理（HTTP応答バッファリング）が有効かどうかによって
        // 呼び出されるタイミングが異なるので注意すること。

        // バッファ処理が有効である場合には、上記表の順番で発生するが、
        // バッファ処理が無効である場合には最初のページ出力が開始される
        // 任意のタイミングで呼び出される。

        // なお、それぞれのイベント・ハンドラの名前から「Application_On」を
        // 取り除いた部分がGlobal.asaxで発生するイベントの名前である。
        // Global.asaxではイベント名に「Application_On」あるいは「Application_」を付けた
        // イベント・ハンドラが事前に定義されており、イベントの発生時に呼び出される。     

        /// <summary>
        /// ① リクエスト処理を開始する前に発生
        /// </summary>
        /// <remarks>
        /// （**net10.0 版は `Startup.Configure` の `app.Use(...)` から同じものを呼ぶ**。
        ///   **net48 には組み込みのレート制限が無いが、別々に作ると振る舞いが分かれる**）。
        /// </remarks>
        void Application_OnBeginRequest(object sender, EventArgs e)
        {
            // 1. 判定対象外のスキップ（アーリーリターン）
            // 機能がオフ、対象外のパスのリクエストの場合
            if (!RateLimitProvider.Enabled)
            {
                return;
            }

            //  **アプリからの相対パスにする**（仮想パスに置いた配備でも突き合わせられるように）。
            string path = this.Request.Url.AbsolutePath;
            string appPath = this.Request.ApplicationPath;

            if (!string.IsNullOrEmpty(appPath) && appPath != "/"
                && path.StartsWith(appPath, StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(appPath.Length);
            }

            if (!RateLimitProvider.IsLimitedPath(path))
            {
                return;
            }

            // 2. client_idの抽出（RFC 6749 §2.3.1）に則った優先順位で
            // 優先度 1: Authorization ヘッダー（Basic 認証）から取得
            string clientId = RateLimitProvider.ClientIdFromAuthorizationHeader(
                this.Request.Headers[Const.HeaderAuthorization]);

            if (string.IsNullOrEmpty(clientId))
            {
                try
                {
                    //  **本体（`client_secret_post`）か、クエリから拾う。**
                    if ((this.Request.ContentType ?? "").StartsWith(
                        "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                    {
                        // 優先度 2: フォームデータ（client_secret_post 等）から取得
                        clientId = this.Request.Form[OAuth2AndOIDCConst.client_id];
                    }
                    else
                    {
                        // 優先度 3: クエリ文字列から取得
                        clientId = this.Request.QueryString[OAuth2AndOIDCConst.client_id];
                    }
                }
                catch
                {
                    clientId = "";
                }
            }

            // 3. レート制限チェックの実行（パス、client_id、IPアドレス）
            int? retryAfter = RateLimitProvider.Check(
                path, clientId, this.Request.UserHostAddress);

            // 4. 制限超過時のレスポンス処理（429 応答）
            if (retryAfter.HasValue)
            {
                //  **429 ＋ `Retry-After`**（RFC 6585 §4）。**本体は返さない。**
                //    **IIS の独自エラー ページに差し替えさせない**（`TrySkipIisCustomErrors`）。
                this.Response.StatusCode = 429;
                this.Response.AddHeader(Const.HeaderRetryAfter, retryAfter.Value.ToString());
                this.Response.TrySkipIisCustomErrors = true;
                this.Response.SuppressContent = true;

                this.CompleteRequest();
            }
        }

        /// <summary>
        /// ② 認証の直前に発生
        /// </summary>
        void Application_OnAuthenticateRequest(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ③ 認証が完了したタイミングで発生
        /// </summary>
        void Application_OnAuthorizeRequest(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ④ リクエストをキャッシングするタイミングで発生
        /// </summary>
        void Application_OnResolveRequestCache(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑤ セッション状態などを取得するタイミングで発生
        /// </summary>
        void Application_OnAcquireRequestState(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑥ ページの実行を開始する直前に発生
        /// </summary>
        void Application_OnPreRequestHandlerExecute(object sender, EventArgs e)
        {
            // ------------
            // メッセージ部
            // ------------
            // ユーザ名, IPアドレス, レイヤ, 
            // 画面名, コントロール名, メソッド名, 処理名
            // ------------
            string strLogMessage =
                "," + "－" +
                "," + Request.UserHostAddress +
                "," + "-----↓" +
                "," + "Global.asax" +
                "," + "Application_OnPreRequest";

            // Log4Netへログ出力
            LogIF.DebugLog("ACCESS", strLogMessage);

            // -------------------------------------------------------------

            // 性能測定開始
            this.perfRec = new PerformanceRecorder();
            this.perfRec.StartsPerformanceRecord();
        }

        ///////////////////////////////////////////////////////////////////
        // ページの実行が⑥～⑦の間に入る。
        ///////////////////////////////////////////////////////////////////

        /// <summary>
        /// ⑦ ページの実行を完了した直後に発生
        /// </summary>
        void Application_OnPostRequestHandlerExecute(object sender, EventArgs e)
        {
            // nullチェック
            if (this.perfRec == null)
            {
                // なにもしない
            }
            else
            {
                // 性能測定終了
                this.perfRec.EndsPerformanceRecord();

                // ACCESSログ出力-----------------------------------------------

                // ------------
                // メッセージ部
                // ------------
                // ユーザ名, IPアドレス, レイヤ, 
                // 画面名, コントロール名, メソッド名, 処理名
                // 処理時間（実行時間）, 処理時間（CPU時間）
                // ------------
                string strLogMessage =
                    "," + "－" +
                    "," + Request.UserHostAddress +
                    "," + "-----↑" +
                    "," + "Global.asax" +
                    "," + "Application_OnPostRequest" +
                    "," + "－" +
                    "," + "－" +
                    "," + this.perfRec.ExecTime +
                    "," + this.perfRec.CpuTime;

                // Log4Netへログ出力
                LogIF.DebugLog("ACCESS", strLogMessage);
            }
        }

        /// <summary>
        /// ⑧ すべての処理を完了したタイミングで発生
        /// </summary>
        void Application_OnReleaseRequestState(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑨ 出力キャッシュを更新したタイミングで発生
        /// </summary>
        void Application_OnUpdateRequestCache(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑩ すべてのリクエスト処理が完了したタイミングで発生
        /// </summary>
        void Application_OnEndRequest(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑪ ヘッダをクライアントに送信する直前に発生
        /// </summary>
        void Application_OnPreSendRequestHeaders(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// ⑫ コンテンツをクライアントに送信する直前に発生
        /// </summary>
        void Application_OnPreSendRequestContent(object sender, EventArgs e)
        {
        }

        //  **WebAPI にセッションを有効にする仕掛けは落とした**（#137）。
        //    **真になる条件が `/Fido2/` だけで、**
        //    **`Fido2ServerController` を落としたので、残すと常に何もしない。**
    }
}
