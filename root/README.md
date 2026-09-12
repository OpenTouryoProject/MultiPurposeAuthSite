# Multi-purpose Authentication Site — Setup and Build

**This is the entry point for building.**

*Multi-purpose Authentication Site* is an Identity Provider (IdP) and Security Token Service (STS)
for OAuth 2.0 and OpenID Connect, powered by ASP.NET Identity and JSON Web Token (JWT).
For an overview of the product, see [Readme.ja.md in the repository root](../Readme.ja.md).

Click [here](Readme.ja.md) for Japanese version of this file.

This document covers **getting the environment ready and making the build pass.**
Arguments, pass criteria, and what each batch file builds are documented elsewhere, and are not
duplicated here (duplicated text goes stale unless both copies are fixed).
**The documents linked below are written in Japanese only.**

- If you develop with a coding agent, read [AGENTS.md](../AGENTS.md) first.
- If you only want the commands, [CHEATSHEET.md](CHEATSHEET.md) is quicker.

## Prerequisites

- **Visual Studio** (or MSBuild and the .NET SDK).
  MSBuild is located with `vswhere`, so **any edition works** (Professional / Enterprise / Build Tools,
  not just Community) → [BUILDING.md](BUILDING.md) section 5
- **.NET 10.0 SDK**, required for the net10.0 build.
- **IIS Express**, required only to run the net48 build (without it, those tests are skipped).

**`dotnet build` alone cannot build net48** → [BUILDING.md](BUILDING.md) section 10

A DBMS is **not** required to build. Setting `UserStoreType` to `mem` runs the site against an
in-memory store → [CONFIGURATION.md](CONFIGURATION.md) section 7

## First-time setup

### 1. Obtain the OpenTouryo assemblies

This repository builds against the assemblies of OpenTouryo.

```bat
cd root\programs
3_BuildLibsAtOtherRepos.bat
```

It fetches OpenTouryo as a ZIP, builds it, and copies the output into `OpenTouryoAssemblies`.
If you are working on OpenTouryo at the same time, use
`3_BuildLibsAtOtherReposInTimeOfDev.bat` instead.

> **Neither is called by the full build** (`0_ExecAllBat.bat` has them commented out),
> because fetching every time is slow. **Run it yourself after updating OpenTouryo.**

### 2. Create the configuration files

Copy them from the templates. **Both are in `.gitignore`** and hold real credentials.

| Template | Create |
|---|---|
| `programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\_appsettings.json` | `appsettings.json` |
| `programs\MultiPurposeAuthSite\MultiPurposeAuthSite\_app.config` | `app.config` |

For what the settings mean, see [CONFIGURATION.md](CONFIGURATION.md).
**Without them the site cannot run** (the build still passes)
→ [BUILDING.md](BUILDING.md) section 10

### 3. Place the certificates

Put the pfx / cer files in `root\files\resource\X509` at the paths the configuration files point to
→ [CONFIGURATION.md](CONFIGURATION.md) section 8

## Building

```powershell
cd root
.\1_BuildAll.ps1
```

`1_BuildAll.ps1` is a wrapper: it calls the build batch files (`root\programs\*.bat`) and
**parses their output to decide pass or fail.** The batch files themselves do not propagate
MSBuild's exit code and wait for input at the end, so on their own they yield no verdict
→ [BUILDING.md](BUILDING.md) section 2

| What you want | Primary source |
|---|---|
| Arguments (`-Only`, `-List`, `-Configuration`, `-SkipClean`, `-WarnDetail`, …) | [BUILDING.md](BUILDING.md) section 1 |
| Pass criteria (how errors and warnings are treated) | [BUILDING.md](BUILDING.md) section 3 |
| Which batch file builds what | [BUILDING.md](BUILDING.md) section 4 |
| Known warnings | [BUILDING.md](BUILDING.md) section 8 |

**You can also run the batch files directly.** `root\programs\0_ExecAllBat.bat` for the whole set
(clean → net48 → net10.0), or `10_MultiPurposeAuthSite*.bat` for one of them.

**Build `Release` as well.** After changing the project configuration, it is easy to end up in a
state that only builds in `Debug` → [BUILDING.md](BUILDING.md) section 5

## Verifying after the build

The scripts in `root` run the build and the E2E tests. **Both report pass or fail as an exit code.**

```powershell
cd root
.\0_RunAll.ps1          # runs the two scripts below
```

| Script | What it does |
|---|---|
| `1_BuildAll.ps1` | Builds everything, aggregating errors and warnings into a verdict |
| `2_RunAllTests.ps1` | Runs the E2E tests, sending the same tests to both the net10.0 and net48 sites |

You can run the two separately, but **the order is fixed** (the tests hit a running site, so the
build comes first). **If the build fails, the tests are not run.**

**The sites are launched by default** (`-Launch` defaults to on), because forgetting to launch them
turns the run into "all skipped", which cannot be read as a verdict. Pass `-Launch:$false` to use
sites that are already running, or `-NoNetFx` to leave net48 out.

For the procedure and the pass criteria see [TESTING.md](TESTING.md)
(section 1 usage / section 5 pass criteria / section 8 prerequisites); for how the tests are
organized and how to add one, see [programs/Tests/README.md](programs/Tests/README.md).

**All logs go to one place:** `root\programs\Tests\E2ETests\Result` (in `.gitignore`)
→ [CHEATSHEET.md](CHEATSHEET.md) section 2

## Documents

| Document | Contents |
|---|---|
| [BUILDING.md](BUILDING.md) | Running the build, and how it is judged |
| [TESTING.md](TESTING.md) | Running the E2E tests, and how they are judged |
| [CONFIGURATION.md](CONFIGURATION.md) | Handling of the configuration files |
| [CODING.md](CODING.md) | Per-format conventions (line endings, file headers, bat / ps1) |
| [CHEATSHEET.md](CHEATSHEET.md) | The commands alone |
| [../AGENTS.md](../AGENTS.md) | What development agents must follow |
| [../Contributing.ja.md](../Contributing.ja.md) | Contribution rules (comments, git-flow, PR granularity) |
| [programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md](programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md) | Conformance as an IdP, and what has been addressed |
