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
| **Garry's Mod** | `http.Post` | asynchronous, callback |
| **Plain Lua** | `luasocket` | synchronous, also returns values |
| None available | raises an error | — |

Callbacks receive `(ok, status, body)`. Under luasocket those same three values are also
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

## Requirements

**Lua 5.1 or newer**, including LuaJIT. No hard dependencies — luasocket is only needed
outside FiveM and Garry's Mod.

## Other clients

Also available for **Java**, **.NET**, **JavaScript**, **Python** and **PHP**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-lua/issues

## Licence

MIT © Hapangama
