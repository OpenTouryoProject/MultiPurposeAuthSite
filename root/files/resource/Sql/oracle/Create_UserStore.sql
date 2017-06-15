-- see : Oracle11gXE + ODP.NET Managed Driver - マイクロソフト系技術情報 Wiki
--       https://techinfoofmicrosofttech.osscons.jp/index.php?Oracle11gXE%20%2B%20ODP.NET%20Managed%20Driver

--UserClaimsのIDENTITY

CREATE TABLE "Users"(
    "Id" NVARCHAR2(38) NOT NULL,            -- PK, guid
    "UserName" NVARCHAR2(256) NOT NULL,
    "Email" NVARCHAR2(256) NULL,
    "EmailConfirmed" NUMBER(3) NOT NULL,
    "PasswordHash" NVARCHAR2(2000) NULL,
    "SecurityStamp" NVARCHAR2(2000) NULL,
    "PhoneNumber" NVARCHAR2(256) NULL,
    "PhoneNumberConfirmed" NUMBER(3) NOT NULL,
    "TwoFactorEnabled" NUMBER(3) NOT NULL,
    "LockoutEndDateUtc" DATE NULL,
    "LockoutEnabled" NUMBER(3) NOT NULL,
    "AccessFailedCount" NUMBER(10) NOT NULL,
    -- 追加の情報
    "ParentId" NVARCHAR2(38) NULL,          -- guid
    "ClientID" NVARCHAR2(256) NOT NULL,
    "PaymentInformation" NVARCHAR2(256) NULL,
    "UnstructuredData" NVARCHAR2(2000) NULL,
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.Users" PRIMARY KEY ("Id")
);

CREATE TABLE "Roles"(
    "Id" NVARCHAR2(38) NOT NULL,            -- PK, guid
    "Name" NVARCHAR2(256) NOT NULL,
    "ParentId" NVARCHAR2(38) NULL,          -- guid
    CONSTRAINT "PK.Roles" PRIMARY KEY ("Id")
);

CREATE TABLE "UserRoles"(        -- 関連エンティティ
    "UserId" NVARCHAR2(38) NOT NULL,        -- PK, guid
    "RoleId" NVARCHAR2(38) NOT NULL,        -- PK, guid
    CONSTRAINT "PK.UserRoles" PRIMARY KEY ("UserId", "RoleId")
);

CREATE TABLE "UserLogins"(       -- Users ---* UserLogins
    "UserId" NVARCHAR2(38) NOT NULL,        -- PK, guid
    "LoginProvider" NVARCHAR2(128) NOT NULL,-- PK
    "ProviderKey" NVARCHAR2(128) NOT NULL,  -- PK
    CONSTRAINT "PK.UserLogins" PRIMARY KEY ("UserId", "LoginProvider", "ProviderKey")
);

CREATE SEQUENCE TS_UserClaimID;  -- TS_UserClaimID.NEXTVAL
CREATE TABLE "UserClaims"(       -- Users ---* UserClaims
    "Id" NUMBER(10) NOT NULL,       -- PK (キー長に問題があるため"Id" "NUMBER(10)"を使用)
    "UserId" NVARCHAR2(38) NOT NULL,        -- *PK, guid
    "Issuer" NVARCHAR2(128) NOT NULL,       -- *PK"LoginProvider)
    "ClaimType" NVARCHAR2(1024) NULL,       -- *PK(実質的に*PKが複合主キー)
    "ClaimValue" NVARCHAR2(1024) NULL,
    CONSTRAINT "PK.UserClaims" PRIMARY KEY ("Id")
);

CREATE TABLE "AuthenticationCodeDictionary"(
    "Key" NVARCHAR2(64) NOT NULL,           -- PK, guid
    "Value" NVARCHAR2(1024) NOT NULL,       -- AuthenticationCode
    CONSTRAINT "PK.AuthCodeDictionary" PRIMARY KEY ("Key")
);

CREATE TABLE "RefreshTokenDictionary"(
    "Key" NVARCHAR2(256) NOT NULL,          -- PK, guid
    "Value" RAW(1024) NOT NULL,             -- RefreshToken
    CONSTRAINT "PK.RefreshTokenDictionary" PRIMARY KEY ("Key")
);

CREATE TABLE "OAuth2Data"(
    "ClientID" NVARCHAR2(256) NOT NULL,      -- PK
    "UnstructuredData" NVARCHAR2(2000) NULL, -- OAuth2 Unstructured Data
    CONSTRAINT "PK.OAuth2Data" PRIMARY KEY ("ClientID")
);

-- INDEX
--- UNIQUE INDEX
---- Users
CREATE UNIQUE INDEX "UserNameIndex" ON "Users" ("UserName" ASC);
--CREATE UNIQUE INDEX "ClientIDIndex" ON "Users" ("ClientID" ASC);
ALTER TABLE "Users" ADD CONSTRAINT "ClientIDIndex" UNIQUE ("ClientID");
---- Roles
CREATE UNIQUE INDEX "RoleNameIndex" ON "Roles" ("Name" ASC);

--- INDEX
---- UserRoles
CREATE INDEX "IX_UserRoles.UserId" ON "UserRoles" ("UserId" ASC);
CREATE INDEX "IX_UserRoles.RoleId" ON "UserRoles" ("RoleId" ASC);
---- UserLogins
CREATE INDEX "IX_UserLogins.UserId" ON "UserLogins" ("UserId" ASC);
---- UserClaims
CREATE INDEX "IX_UserClaims.UserId" ON "UserClaims" ("UserId" ASC);

-- CONSTRAINT
---- UserRoles
ALTER TABLE "UserRoles" ADD CONSTRAINT "FK.UserRoles.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
ALTER TABLE "UserRoles" ADD CONSTRAINT "FK.UserRoles.Roles_RoleId" FOREIGN KEY("RoleId") REFERENCES "Roles" ("Id"); -- 使用中のRoleは削除できない。
---- UserLogins
ALTER TABLE "UserLogins" ADD CONSTRAINT "FK.UserLogins.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- UserClaims
ALTER TABLE "UserClaims" ADD CONSTRAINT "FK.UserClaims.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- OAuth2Data
ALTER TABLE "OAuth2Data" ADD CONSTRAINT "FK.OAuth2Data.Users_ClientID" FOREIGN KEY("ClientID") REFERENCES "Users" ("ClientID") ON DELETE CASCADE;