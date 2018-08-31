-- For the information of using Oracle database and ODP.NET managed driver
-- for the user store of multi-purpose authentication site, see the following site.
--     Oracle11gXE + ODP.NET Managed Driver - マイクロソフト系技術情報 Wiki
--     https://techinfoofmicrosofttech.osscons.jp/index.php?Oracle11gXE%20%2B%20ODP.NET%20Managed%20Driver

--UserClaimsのIDENTITY

CREATE TABLE "Users"(              -- Users
    "Id" NVARCHAR2(38) NOT NULL,             -- PK, guid
    "UserName" NVARCHAR2(256) NOT NULL,
    "Email" NVARCHAR2(256) NULL,
    "EmailConfirmed" NUMBER(3) NOT NULL,
    "PasswordHash" NVARCHAR2(2000) NULL,
    "SecurityStamp" NVARCHAR2(2000) NULL,
    "PhoneNumber" NVARCHAR2(256) NULL,
    "PhoneNumberConfirmed" NUMBER(3) NOT NULL,
    "TwoFactorEnabled" NUMBER(3) NOT NULL,
    "LockoutEndDateUtc" TIMESTAMP NULL,
    "LockoutEnabled" NUMBER(3) NOT NULL,
    "AccessFailedCount" NUMBER(10) NOT NULL,
    -- 追加の情報
    "ClientID" NVARCHAR2(256) NOT NULL,
    "PaymentInformation" NVARCHAR2(256) NULL,
    "UnstructuredData" NVARCHAR2(2000) NULL,
    "FIDO2PublicKey" NVARCHAR2(2000) NULL,
    "CreatedDate" TIMESTAMP NOT NULL,
    "PasswordChangeDate" TIMESTAMP NOT NULL,
    CONSTRAINT "PK.Users" PRIMARY KEY ("Id")
);

CREATE TABLE "Roles"(              -- Roles
    "Id" NVARCHAR2(38) NOT NULL,             -- PK, guid
    "Name" NVARCHAR2(256) NOT NULL,
    CONSTRAINT "PK.Roles" PRIMARY KEY ("Id")
);

CREATE TABLE "UserRoles"(          -- 関連エンティティ (Users *--- UserRoles ---* Roles)
    "UserId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    "RoleId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    CONSTRAINT "PK.UserRoles" PRIMARY KEY ("UserId", "RoleId")
);

CREATE TABLE "UserLogins"(         -- Users ---* UserLogins
    "UserId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    "LoginProvider" NVARCHAR2(128) NOT NULL, -- PK
    "ProviderKey" NVARCHAR2(128) NOT NULL,   -- PK
    CONSTRAINT "PK.UserLogins" PRIMARY KEY ("UserId", "LoginProvider", "ProviderKey")
);

CREATE SEQUENCE TS_UserClaimID;    -- TS_UserClaimID.NEXTVAL
CREATE TABLE "UserClaims"(         -- Users ---* UserClaims
    "Id" NUMBER(10) NOT NULL,                -- PK (キー長に問題があるため"Id" "NUMBER(10)"を使用)
    "UserId" NVARCHAR2(38) NOT NULL,            -- *PK, guid
    "Issuer" NVARCHAR2(128) NOT NULL,           -- *PK(LoginProvider) *PK(実質的に複合主キー)
    "ClaimType" NVARCHAR2(1024) NULL,
    "ClaimValue" NVARCHAR2(1024) NULL,
    CONSTRAINT "PK.UserClaims" PRIMARY KEY ("Id")
);

CREATE TABLE "AuthenticationCodeDictionary"(
    "Key" NVARCHAR2(64) NOT NULL,            -- PK
    "Value" NVARCHAR2(2000) NOT NULL,        -- AuthenticationCode
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.AuthCodeDictionary" PRIMARY KEY ("Key")
);

CREATE TABLE "RefreshTokenDictionary"(
    "Key" NVARCHAR2(256) NOT NULL,           -- PK
    "Value" RAW(1024) NOT NULL,              -- RefreshToken
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.RefreshTokenDictionary" PRIMARY KEY ("Key")
);

CREATE TABLE "CustomizedConfirmation"(
    "UserId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    "Value" NVARCHAR2(2000) NOT NULL,        -- Value
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.CustomizedConfirmation" PRIMARY KEY ("UserId")
);

CREATE TABLE "OAuth2Data"(         -- OAuth2Data
    "ClientID" NVARCHAR2(256) NOT NULL,      -- PK
    "UnstructuredData" NVARCHAR2(2000) NULL, -- OAuth2 Unstructured Data
    CONSTRAINT "PK.OAuth2Data" PRIMARY KEY ("ClientID")
);

CREATE TABLE "OAuth2Revocation"(
    "Jti" NVARCHAR2(38) NOT NULL,            -- PK, guid
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.OAuth2Revocation" PRIMARY KEY ("Jti")
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
