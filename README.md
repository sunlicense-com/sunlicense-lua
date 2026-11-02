# SunLicense — Lua Client

Official Lua client for [SunLicense](https://sunlicense.com), a licence management and
anti-piracy system for indie software developers.

Built for **FiveM scripts** and **Garry's Mod addons**, with plain-Lua support via luasocket.

> **Early preview.** The client API is being finalised alongside SunLicense 2.0.

## Install

**Drop-in (recommended for FiveM and Garry's Mod):** copy `sunlicense.lua` into your
resource or addon.

**LuaRocks:**

```bash
luarocks install sunlicense
```

## Usage

### FiveM

```lua
local SunLicense = require("sunlicense")

local client = SunLicense.new({ baseUrl = "https://your-instance.example.com" })

client:validate("LICENCE-KEY-HERE", { productId = 7 }, function(ok, status, body)
    if ok then
        print("Licence valid")
    else
        print(("Rejected: %s %s"):format(status, body))
        -- StopResource(GetCurrentResourceName())
    end
end)
```

Add it to your `fxmanifest.lua`:

```lua
server_scripts {
    'sunlicense.lua',
    'server/main.lua',
}
```

### Garry's Mod

```lua
local SunLicense = include("sunlicense.lua")

SunLicense.new({ baseUrl = "https://your-instance.example.com" })
    :validate("LICENCE-KEY-HERE", function(ok, status, body)
        print(ok and "Licence valid" or "Rejected: " .. body)
    end)
```

### Plain Lua (synchronous, needs luasocket)

```lua
local SunLicense = require("sunlicense")

local client = SunLicense.new({
    baseUrl = "https://your-instance.example.com",
    token = os.getenv("SUNLICENSE_TOKEN"), -- optional
    timeout = 10,
})

local ok, status, body = client:validate("LICENCE-KEY-HERE")
print(ok, status, body)
```

## How it picks an HTTP backend

`SunLicense.environment()` returns whichever it detects:

| Environment | Mechanism | Style |
|---|---|---|
| **FiveM** | `PerformHttpRequest` | asynchronous, callback |
| **Garry's Mod** | `HTTP` | asynchronous, callback |
| **Plain Lua** | `luasocket` | synchronous, also returns values |
| None available | raises an error | — |

Callbacks receive `(ok, status, body)`; `ok` is true only when the API answers 2xx (a valid
licence), and `body` is the JSON answer, whose `code` says why a key was rejected. Under luasocket those same three values are also
returned directly, so both styles work.

## API

### `SunLicense.new(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `baseUrl` | string | — | **Required.** Base URL of your SunLicense instance |
| `token` | string | `nil` | API token, if your endpoint requires one |
| `timeout` | number | `10` | Timeout in seconds (luasocket only) |

### `client:validate(licenseKey [, context] [, callback])`

Sends `licenseKey` plus any `context` fields. `context` may be omitted and the callback
passed in its place.

### `SunLicense.environment()`

Returns `"fivem"`, `"gmod"`, `"luasocket"` or `"none"`.

## Built-in analytics

Reports anonymous usage statistics for your resource's **Analytics** tab (installs, versions, server build,
OS), plus your own feature usage and charts. Like bStats, for FiveM, RedM, Garry's Mod and plain Lua.

```lua
local SunLicense = require("sunlicense")

-- A licensed resource: the API key, license key and machine id it validates with.
local analytics = client:analytics({ licenseKey = Config.LicenseKey, fingerprint = machineId,
                                     enabled = GetConvar("myresource_analytics", "true") ~= "false" })
-- A free resource, no license: its public product analytics id (Product -> Analytics).
local analytics = SunLicense.analytics("pa_7Hk2mQ9xZr4LbN8vT1wYcD")

analytics:feature("auto-sell")                                             -- feature usage
analytics:simplePie("framework", function() return Config.Framework end)   -- custom charts
analytics:singleLine("players", function() return #GetPlayers() end)
```

Charts: `simplePie`, `advancedPie`, `drilldownPie`, `singleLine`, `multiLine`, `simpleBar`, `advancedBar`,
`removeChart`. Ids and feature names: `[a-z0-9][a-z0-9._-]{0,47}`. On FiveM the product version defaults to
the `version` in your `fxmanifest.lua`. **Plain Lua** has no timers: call `analytics:poll()` from your main
loop (it sends when a report is due).

**What is sent** (raw values; SunLicense groups them, e.g. `5.15.0-1051-oracle` into Linux 5.15): your
product version, the OS and its version, CPU architecture, CPU cores, locale, Lua version (LuaJIT on Garry's Mod), the platform (`fivem` or `redm` with the server build, `gmod` with its version, else `standalone`),
the SDK's name and version, and the identity: licensed = license key + machine id (with the API key), free =
the product analytics id + a random install id kept in the resource (`.sunlicense-install-id`, FiveM), `data/<dataName>/install-id.txt` (Garry's Mod) or `dataDirectory` (plain Lua). The country comes from SunLicense's edge, not
from the SDK. Nothing personal is sent: no user, host, server or player names, IP addresses or file paths.

**Switching it off.** Nothing is sent, not even an empty report, while any of these says so (checked before
every report): your product's own switch (`enabled = false`, or a function read before each report); the environment variable `SUNLICENSE_ANALYTICS=off` (also
`false` or `0`); the convar `sunlicense_analytics` (FiveM: `set sunlicense_analytics false` in server.cfg); the global `SUNLICENSE_ANALYTICS = false`.

The first report goes 1 to 30 minutes after start (random), then one every 30 minutes. When
SunLicense answers with `Retry-After` (analytics switched off for the product, rate limits) it waits that long,
at most 24 hours. Reporting never runs on the license check's path, never delays or fails a check, and swallows
its own errors.

Docs: https://docs.sunlicense.com/guide/sdks#built-in-analytics

## Requirements

**Lua 5.1 or newer**, including LuaJIT. No hard dependencies — luasocket is only needed
outside FiveM and Garry's Mod.

## Other clients

Also available for **Java**, **.NET**, **JavaScript**, **Python** and **PHP**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-lua/issues

## Changelog

- **0.1.0**: built-in product analytics (opt-out), feature usage and custom charts: `client:analytics()`, `SunLicense.analytics()`.
- **0.0.2**: validates against `/api/v2/license/validate` (`{"license": key, ...context}`), like
  every other SunLicense client. **0.0.1 called `/api/v1/validate`, which answers HTTP 200 for every
  key, so unknown, revoked and expired keys were reported as valid.** On Garry's Mod 0.0.1 also
  sent no API key and always reported `(true, 200)`. Upgrade: replace `sunlicense.lua`.
- **0.0.1**: first release.

## Tests

```bash
lua test/test_sunlicense.lua
lua test/test_analytics.lua
```

## Licence

MIT © Hapangama
