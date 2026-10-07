-- セッションの置き場（#256）
--
--   **`SessionStoreType` が `sql` のときだけ要る。** `mem` / `redis` では不要。
--   **net10.0 版だけが読む。** net48 版は `Web.config` の `sessionState` で選ぶ。
--
--   **スキーマは `dotnet sql-cache create` が作るものと同じ。**
--     列名・型・索引を変えると `AddDistributedSqlServerCache` が動かない。
--     スキーマ名・テーブル名は `Const.SessionCacheSchemaName` /
--     `Const.SessionCacheTableName` と揃えてある（片方だけ変えない）。
--
--   **Create_UserStore.sql は DATABASE を作り直す。**
--     後から流すと、このテーブルは消える。**UserStore を作り直したら、これも流し直す。**
--
--   **Oracle / PostgreSQL 版は無い。** 標準の `IDistributedCache` に実装が無いため。
--     それらのストアでセッションを共有するなら `SessionStoreType` に `redis` を指定する。

USE [UserStore]
GO

IF OBJECT_ID(N'[dbo].[SessionCache]', N'U') IS NOT NULL
BEGIN
    DROP TABLE [dbo].[SessionCache]
END
GO

CREATE TABLE [dbo].[SessionCache](  -- SessionCache
    [Id] [nvarchar](449) NOT NULL,                  -- PK, キー
    [Value] [varbinary](max) NOT NULL,              -- 値
    [ExpiresAtTime] [datetimeoffset](7) NOT NULL,   -- 失効日時
    [SlidingExpirationInSeconds] [bigint] NULL,     -- Sliding（秒）
    [AbsoluteExpiration] [datetimeoffset](7) NULL,  -- 絶対の失効日時
    CONSTRAINT [PK_SessionCache] PRIMARY KEY CLUSTERED ([Id] ASC)
)
GO

-- **失効の掃除で使う。** 無いとテーブル スキャンになる。
CREATE NONCLUSTERED INDEX [Index_ExpiresAtTime] ON [dbo].[SessionCache]([ExpiresAtTime] ASC)
GO
