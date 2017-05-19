USE [master]
GO

ALTER DATABASE [UserStore] SET SINGLE_USER
DROP  DATABASE [UserStore]

CREATE DATABASE [UserStore]
GO

USE [UserStore]
GO

-- TABLE
CREATE TABLE [Users](
    [Id] [nvarchar](38) NOT NULL,            -- PK, guid
    [UserName] [nvarchar](256) NOT NULL,
    [Email] [nvarchar](256) NULL,
    [EmailConfirmed] [bit] NOT NULL,
    [PasswordHash] [nvarchar](max) NULL,
    [SecurityStamp] [nvarchar](max) NULL,
    [PhoneNumber] [nvarchar](256) NULL,
    [PhoneNumberConfirmed] [bit] NOT NULL,
    [TwoFactorEnabled] [bit] NOT NULL,
    [LockoutEndDateUtc] [datetime] NULL,
    [LockoutEnabled] [bit] NOT NULL,
    [AccessFailedCount] [int] NOT NULL,
    -- 追加の情報
    [ParentId] [nvarchar](38) NULL,          -- guid
    [PaymentInformation] [nvarchar](256) NULL,
    [UnstructuredData] [nvarchar](max) NULL,
    CONSTRAINT [PK.Users] PRIMARY KEY CLUSTERED ([Id] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

CREATE TABLE [Roles](
    [Id] [nvarchar](38) NOT NULL,            -- PK, guid
    [Name] [nvarchar](256) NOT NULL,
    [ParentId] [nvarchar](38) NULL,          -- guid
    CONSTRAINT [PK.Roles] PRIMARY KEY CLUSTERED ([Id] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [UserRoles](        -- 関連エンティティ
    [UserId] [nvarchar](38) NOT NULL,        -- PK, guid
    [RoleId] [nvarchar](38) NOT NULL,        -- PK, guid
    CONSTRAINT [PK.UserRoles] PRIMARY KEY CLUSTERED (
        [UserId] ASC,
        [RoleId] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [UserLogins](       -- Users ---* UserLogins
    [UserId] [nvarchar](38) NOT NULL,        -- PK, guid
    [LoginProvider] [nvarchar](128) NOT NULL,-- PK
    [ProviderKey] [nvarchar](128) NOT NULL,  -- PK
    CONSTRAINT [PK.UserLogins] PRIMARY KEY CLUSTERED (
        [UserId] ASC,
        [LoginProvider] ASC,
        [ProviderKey] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [UserClaims](       -- Users ---* UserClaims
    [Id] [int] IDENTITY(1,1) NOT NULL,       -- PK (キー長に問題があるため[Id] [int]を使用)
    [UserId] [nvarchar](38) NOT NULL,        -- *PK, guid
    [Issuer] [nvarchar](128) NOT NULL,       -- *PK[LoginProvider)
    [ClaimType] [nvarchar](1024) NULL,       -- *PK(実質的に*PKが複合主キー)
    [ClaimValue] [nvarchar](1024) NULL,
    CONSTRAINT [PK.UserClaims] PRIMARY KEY CLUSTERED ([Id] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [AuthenticationCodeDictionary](
    [Key] [nvarchar](64) NOT NULL,           -- PK, guid
    [Value] [nvarchar](1024) NOT NULL        -- AuthenticationCode
    CONSTRAINT [PK.AuthenticationCodeDictionary] PRIMARY KEY CLUSTERED ([Key] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [RefreshTokenDictionary](
    [Key] [nvarchar](256) NOT NULL,          -- PK, guid
    [Value] [binary](1024) NOT NULL          -- RefreshToken
    CONSTRAINT [PK.RefreshTokenDictionary] PRIMARY KEY CLUSTERED ([Key] ASC)
        WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

-- INDEX
---- Users
CREATE UNIQUE NONCLUSTERED INDEX [UserNameIndex] ON [Users] ([UserName] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
---- Roles
CREATE UNIQUE NONCLUSTERED INDEX [RoleNameIndex] ON [Roles] ([Name] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
---- UserRoles
CREATE NONCLUSTERED INDEX [IX_UserId] ON [UserRoles] ([UserId] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
CREATE NONCLUSTERED INDEX [IX_RoleId] ON [UserRoles] ([RoleId] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
---- UserLogins
CREATE NONCLUSTERED INDEX [IX_UserId] ON [UserLogins] ([UserId] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
---- UserClaims
CREATE NONCLUSTERED INDEX [IX_UserId] ON [UserClaims] ([UserId] ASC) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]

-- CONSTRAINT
---- UserRoles
ALTER TABLE [UserRoles]  WITH CHECK ADD  CONSTRAINT [FK.UserRoles.Users_UserId] FOREIGN KEY([UserId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE
ALTER TABLE [UserRoles]  CHECK CONSTRAINT [FK.UserRoles.Users_UserId]
ALTER TABLE [UserRoles]  WITH CHECK ADD  CONSTRAINT [FK.UserRoles.Roles_RoleId] FOREIGN KEY([RoleId]) REFERENCES [Roles] ([Id]) ON DELETE NO ACTION -- 使用中のRoleは削除できない。
ALTER TABLE [UserRoles]  CHECK CONSTRAINT [FK.UserRoles.Roles_RoleId]
---- UserLogins
ALTER TABLE [UserLogins] WITH CHECK ADD  CONSTRAINT [FK.UserLogins.Users_UserId] FOREIGN KEY([UserId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE
ALTER TABLE [UserLogins] CHECK CONSTRAINT [FK.UserLogins.Users_UserId]
---- UserClaims
--ALTER TABLE [UserClaims] ADD CONSTRAINT [UQ.UserClaims.Users_UserId] UNIQUE ([UserId], [ClaimType], [ClaimValue]) -- キー長の問題でダメ。
ALTER TABLE [UserClaims] WITH CHECK ADD CONSTRAINT [FK.UserClaims.Users_UserId] FOREIGN KEY([UserId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE
ALTER TABLE [UserClaims] CHECK CONSTRAINT [FK.UserClaims.Users_UserId]