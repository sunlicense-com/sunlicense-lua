--- Official SunLicense client for Lua.
--
-- Early preview. The client API is being finalised alongside SunLicense 2.0.
--
-- Drop this file into your resource and require it. It detects the host
-- environment and uses whichever HTTP mechanism is available:
--
--   * FiveM        -- PerformHttpRequest (async, callback)
--   * Garry's Mod  -- HTTP (async, callback)
--   * Plain Lua    -- luasocket (synchronous), if installed
--
-- Docs: https://docs.sunlicense.hapangama.com
-- @module sunlicense

local SunLicense = {}
SunLicense.__index = SunLicense

--- The version of this client.
SunLicense.VERSION = "0.1.0"

-- ---------------------------------------------------------------------------
-- Environment detection
-- ---------------------------------------------------------------------------

--- Detects which host environment this is running in.
-- @return string one of "fivem", "gmod", "luasocket" or "none"
function SunLicense.environment()
  if type(_G.PerformHttpRequest) == "function" then
    return "fivem"
  end
  if type(_G.HTTP) == "function" then
    return "gmod"
  end
  local ok = pcall(require, "socket.http")
  if ok then
    return "luasocket"
  end
  return "none"
end

-- ---------------------------------------------------------------------------
-- Minimal JSON encoding (flat string/number tables only)
-- ---------------------------------------------------------------------------

local ESCAPES = {
  ['"']  = '\\"',
  ['\\'] = '\\\\',
  ['\n'] = '\\n',
  ['\r'] = '\\r',
  ['\t'] = '\\t',
  ['\b'] = '\\b',
  ['\f'] = '\\f',
}

local function escape(value)
  return (tostring(value):gsub('[%c"\\]', function(c)
    return ESCAPES[c] or string.format('\\u%04x', c:byte())
  end))
end

local function encode(tbl)
  local parts = {}
  for key, value in pairs(tbl) do
    local encoded
    if type(value) == "number" then
      encoded = tostring(value)
    elseif type(value) == "boolean" then
      encoded = value and "true" or "false"
    else
      encoded = '"' .. escape(value) .. '"'
    end
    parts[#parts + 1] = '"' .. escape(key) .. '":' .. encoded
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

SunLicense.encode = encode

-- ---------------------------------------------------------------------------
-- Client
-- ---------------------------------------------------------------------------

--- Creates a client.
-- @tparam table options table with `baseUrl` (required), `token` and `timeout`
-- @treturn SunLicense the client
-- @error "baseUrl is required" when baseUrl is missing or empty
function SunLicense.new(options)
  options = options or {}

  if type(options.baseUrl) ~= "string" or options.baseUrl == "" then
    error("SunLicense: baseUrl is required", 2)
  end

  return setmetatable({
    baseUrl = (options.baseUrl:gsub("/+$", "")),
    token = options.token,
    timeout = options.timeout or 10,
  }, SunLicense)
end

--- Builds the headers sent with every request.
-- @treturn table header name to value
function SunLicense:headers()
  local headers = {
    ["Content-Type"] = "application/json",
    ["User-Agent"] = "sunlicense-lua/" .. SunLicense.VERSION,
  }
  if self.token and self.token ~= "" then
    headers["Authorization"] = "Bearer " .. self.token
  end
  return headers
end

--- Validates a licence key.
--
-- On FiveM and Garry's Mod the call is asynchronous and `callback` receives
-- `(ok, status, body)`. Under luasocket it is synchronous and those three
-- values are returned directly.
--
-- @tparam string licenseKey the licence key to check
-- @tparam[opt] table context extra fields to send
-- @tparam[opt] function callback called with (ok, status, body)
-- @treturn[opt] boolean ok, number status, string body -- synchronous mode only
function SunLicense:validate(licenseKey, context, callback)
  if type(licenseKey) ~= "string" or licenseKey == "" then
    error("SunLicense: licenseKey is required", 2)
  end

  if type(context) == "function" then
    callback = context
    context = nil
  end

  local payload = { license = licenseKey }
  for key, value in pairs(context or {}) do
    payload[key] = value
  end

  -- The endpoint every SunLicense SDK uses: 2xx means valid, 4xx means rejected (0.0.1 called
  -- /api/v1/validate, which answers 200 for every key, so every key passed).
  local url = self.baseUrl .. "/api/v2/license/validate"
  local body = encode(payload)
  local env = SunLicense.environment()

  if env == "fivem" then
    _G.PerformHttpRequest(url, function(status, responseBody)
      if callback then
        callback(status >= 200 and status < 300, status, responseBody)
      end
    end, "POST", body, self:headers())
    return
  end

  if env == "gmod" then
    -- HTTP{} rather than http.Post, which sends form fields instead of JSON. 0.0.1 used http.Post
    -- without the API key and reported every answer as (true, 200).
    local headers = self:headers()
    headers["Content-Type"] = nil
    _G.HTTP({
      url = url,
      method = "POST",
      headers = headers,
      body = body,
      type = "application/json",
      success = function(status, responseBody)
        if callback then callback(status >= 200 and status < 300, status, responseBody) end
      end,
      failed = function(err)
        if callback then callback(false, 0, err) end
      end,
    })
    return
  end

  if env == "luasocket" then
    local httpClient = require("socket.http")
    local ltn12 = require("ltn12")
    local chunks = {}

    local headers = self:headers()
    headers["Content-Length"] = tostring(#body)

    httpClient.TIMEOUT = self.timeout

    local _, status = httpClient.request({
      url = url,
      method = "POST",
      headers = headers,
      source = ltn12.source.string(body),
      sink = ltn12.sink.table(chunks),
    })

    local responseBody = table.concat(chunks)
    local ok = type(status) == "number" and status >= 200 and status < 300

    if callback then
      callback(ok, status, responseBody)
    end
    return ok, status, responseBody
  end

  error("SunLicense: no HTTP support found. Install luasocket, or run inside FiveM or Garry's Mod.", 2)
end

-- ---------------------------------------------------------------------------
-- Built-in product analytics
-- ---------------------------------------------------------------------------
--
-- Every 30 minutes this install tells SunLicense its product version, OS, runtime and platform
-- (FiveM or RedM with the server build, Garry's Mod, plain Lua). Sellers see the totals on the
-- product's Analytics tab. It never blocks, delays or fails a license check and never raises.
--
--   -- A licensed product: the API key, license key and machine id it validates with.
--   local analytics = client:analytics({ licenseKey = key, fingerprint = machineId,
--                                        enabled = GetConvar("myresource_analytics", "true") ~= "false" })
--   -- A free product: its public product analytics id (Product -> Analytics), no license needed.
--   local analytics = SunLicense.analytics("pa_7Hk2mQ9xZr4LbN8vT1wYcD")
--   analytics:feature("auto-sell")
--   analytics:simplePie("storage", function() return Config.Storage end)
--
-- Nothing is sent while the product's `enabled` switch is off, the environment variable
-- SUNLICENSE_ANALYTICS or the FiveM convar sunlicense_analytics is off/false/0, or the global
-- SUNLICENSE_ANALYTICS is false; each is checked before every report. No personal data is sent:
-- no user, host, server or player names, IP addresses or file paths.

local Analytics = {}
Analytics.__index = Analytics
SunLicense.Analytics = Analytics

--- Sent as sdk.name / sdk.version.
Analytics.SDK_NAME = "lua"
Analytics.DEFAULT_BASE_URL = "https://api.sunlicense.com"

local PATH = "/api/v2/analytics/report"
local INTERVAL = 30 * 60
local MIN_WAIT, MAX_WAIT = 60, 24 * 3600
local MAX_BODY = 16 * 1024
local INSTALL_ID_FILE = ".sunlicense-install-id"
local CORE_KEYS = { schema = true, licenseKey = true, fingerprint = true, productAnalyticsId = true,
                    installId = true, sdk = true, metrics = true }
local OFF = { off = true, ["false"] = true, ["0"] = true, no = true, disabled = true }
local MAX_FEATURES, MAX_CHARTS, MAX_VALUES, MAX_BAR, MAX_NUMBER = 50, 30, 50, 20, 1e9

-- JSON (objects with sorted keys, so reports are stable; a table marked as an array is a list)
local ARRAY = {}
local function array(t) return setmetatable(t, ARRAY) end

local function isInteger(v)
  return type(v) == "number" and v == math.floor(v) and v > -2^53 and v < 2^53
end

local function json(value)
  local t = type(value)
  if t == "table" then
    local parts = {}
    if getmetatable(value) == ARRAY then
      for i = 1, #value do parts[i] = json(value[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local keys = {}
    for k in pairs(value) do keys[#keys + 1] = tostring(k) end
    table.sort(keys)
    for i, k in ipairs(keys) do parts[i] = '"' .. escape(k) .. '":' .. json(value[k]) end
    return "{" .. table.concat(parts, ",") .. "}"
  elseif t == "number" then
    if value ~= value or value == math.huge or value == -math.huge then return "null" end
    return isInteger(value) and string.format("%d", value) or tostring(value)
  elseif t == "boolean" then
    return value and "true" or "false"
  elseif value == nil then
    return "null"
  end
  return '"' .. escape(value) .. '"'
end
Analytics.json = json

--- Trimmed, control characters removed, cut at max; nil when empty.
local function clean(value, max)
  if value == nil then return nil end
  local s = tostring(value):gsub("%c", ""):match("^%s*(.-)%s*$")
  if s == "" then return nil end
  if #s > max then
    s = s:sub(1, max)
    s = s:gsub("[\192-\255][\128-\191]*$", "") -- don't cut a UTF-8 character in half
    s = s:match("^%s*(.-)%s*$")
  end
  return s ~= "" and s or nil
end
Analytics.clean = clean

--- Feature names and chart ids: lower-cased, [a-z0-9][a-z0-9._-]{0,47}, else nil.
local function chartId(value)
  if type(value) ~= "string" then return nil end
  local id = value:match("^%s*(.-)%s*$"):lower()
  if #id >= 1 and #id <= 48 and id:match("^[a-z0-9][a-z0-9._%-]*$") then return id end
  return nil
end
Analytics.chartId = chartId

local function isOff(value)
  if value == false then return true end
  return value ~= nil and OFF[tostring(value):match("^%s*(.-)%s*$"):lower()] == true
end
Analytics.isOff = isOff

local function try(fn, ...)
  local ok, result = pcall(fn, ...)
  if ok then return result end
  return nil
end

local function now()
  return (os and os.time and os.time()) or 0
end

--- First report after a random 1-30 minutes (seconds), so a fleet restarted together doesn't report together.
function Analytics.firstDelay(random)
  return 60 + math.floor((random or math.random)() * (29 * 60 + 1))
end

--- 30 minutes after a 204 or no answer; else the server's Retry-After, between 1 minute and 24 hours.
function Analytics.nextDelay(status, retryAfter)
  if status == 204 or retryAfter == nil then return INTERVAL end
  local seconds = tonumber(tostring(retryAfter):match("^%s*(%d+)%s*$"))
  if not seconds then return INTERVAL end
  return math.min(MAX_WAIT, math.max(MIN_WAIT, seconds))
end

-- A random v4 UUID from its own generator, so the product's math.random sequence is left alone
-- (Lua 5.1 and LuaJIT aren't seeded: every install would draw the same "random" id).
local function uuid()
  local seed = now() + math.floor(((os and os.clock and os.clock()) or 0) * 1e6)
  for c in tostring({}):gmatch("%x") do seed = (seed * 16 + tonumber(c, 16)) % 2147483647 end
  local function nextByte()
    seed = (seed * 48271) % 2147483647
    return math.floor(seed / 2147483647 * 256) % 256
  end
  local b = {}
  for i = 1, 16 do b[i] = (nextByte() + math.random(0, 255)) % 256 end
  b[7] = 64 + b[7] % 16
  b[9] = 128 + b[9] % 64
  local hex = {}
  for i = 1, 16 do hex[i] = string.format("%02x", b[i]) end
  local h = table.concat(hex)
  return h:sub(1, 8) .. "-" .. h:sub(9, 12) .. "-" .. h:sub(13, 16) .. "-" .. h:sub(17, 20) .. "-" .. h:sub(21, 32)
end

local function header(headers, name)
  if type(headers) ~= "table" then return nil end
  name = name:lower()
  for k, v in pairs(headers) do
    if tostring(k):lower() == name then return type(v) == "table" and v[1] or v end
  end
  return nil
end

--- Raw built-in metrics for the environment this runs in; the server maps them to families and majors.
function Analytics.collect(env, platformOverride)
  local m = { runtime = "lua", runtimeVersion = clean((_VERSION or ""):match("%d+%.%d+"), 64) }
  if type(_G.jit) == "table" then
    m.runtime = "luajit"
    m.runtimeVersion = clean(_G.jit.version and _G.jit.version:match("%d[%w%.%-]*"), 64)
    m.arch = clean(_G.jit.arch, 64)
    m.os = clean(_G.jit.os == "OSX" and "Mac OS X" or _G.jit.os, 64)
  end
  local platform, platformVersion = "standalone", nil
  if env == "fivem" then
    -- "FXServer-master SERVER v1.0.0.7290 linux"
    local version = try(_G.GetConvar, "version", "") or ""
    platform = try(_G.GetConvar, "gamename", "gta5") == "rdr3" and "redm" or "fivem"
    platformVersion = version:match("v%d+%.%d+%.%d+%.(%d+)")
    local os = version:match("(%w+)%s*$")
    if os == "linux" then m.os = "Linux" elseif os == "win32" then m.os = "Windows" end
  elseif env == "gmod" then
    platform, platformVersion = "gmod", _G.VERSION and tostring(_G.VERSION)
    local sys = _G.system
    if type(sys) == "table" then
      if try(sys.IsWindows) then m.os = "Windows" elseif try(sys.IsOSX) then m.os = "Mac OS X"
      elseif try(sys.IsLinux) then m.os = "Linux" end
    end
  else
    local getenv = os and os.getenv
    if getenv then
      if not m.os and try(getenv, "OS") == "Windows_NT" then m.os = "Windows" end
      local cores = tonumber(try(getenv, "NUMBER_OF_PROCESSORS") or "")
      if cores and cores >= 1 then m.cores = math.min(1024, math.floor(cores)) end
      local locale = clean(try(getenv, "LC_ALL") or try(getenv, "LANG"), 64)
      if locale ~= "C" and locale ~= "POSIX" and not (locale or ""):match("^C%.") then m.locale = locale end
    end
  end
  if platformOverride and platformOverride.name then
    platform, platformVersion = tostring(platformOverride.name):lower(), platformOverride.version
  end
  m.platform = clean(platform, 32)
  m.platformVersion = clean(platformVersion, 64)
  return m
end

--- Starts built-in analytics. `SunLicense.analytics("pa_...", options)` for a free product, or
-- `client:analytics({ licenseKey = ..., fingerprint = ... })` for a licensed one (the client's
-- base URL and API key). Options: baseUrl, apiKey, licenseKey (string or function), fingerprint,
-- productAnalyticsId, productVersion (string or function; FiveM default: the resource's version),
-- platform ({ name, version }), enabled (boolean or function), dataDirectory (plain Lua: where the
-- install id file goes, default "."), dataName (Garry's Mod: data/<dataName>/install-id.txt).
-- Never raises.
function SunLicense.analytics(first, options)
  options = type(options) == "table" and options or {}
  local o = {}
  for k, v in pairs(options) do o[k] = v end
  if type(first) == "string" then
    o.productAnalyticsId = first
  elseif type(first) == "table" and getmetatable(first) == SunLicense then
    o.baseUrl = o.baseUrl or first.baseUrl
    o.apiKey = o.apiKey or first.token
  elseif type(first) == "table" then
    for k, v in pairs(first) do if o[k] == nil then o[k] = v end end
  end
  local ok, analytics = pcall(Analytics.new, o)
  if not ok then
    analytics = Analytics.new({ enabled = false })
  end
  return analytics:start()
end

--- A reporter that isn't started (call :start(), or :sendNow() in tests). Never raises.
function Analytics.new(o)
  o = o or {}
  local self = setmetatable({}, Analytics)
  self.endpoint = tostring(o.baseUrl or Analytics.DEFAULT_BASE_URL):gsub("/+$", "") .. PATH
  self.apiKey = clean(o.apiKey, 512)
  self.licenseKey = o.licenseKey
  self.fingerprint = clean(o.fingerprint, 255)
  self.productAnalyticsId = clean(o.productAnalyticsId, 64)
  self.productVersion = o.productVersion
  self.platform = o.platform
  if o.enabled == nil then self.enabled = true else self.enabled = o.enabled end
  self.dataDirectory = o.dataDirectory or "."
  self.dataName = o.dataName or "sunlicense"
  self.env = o.environment or SunLicense.environment()
  self.features, self.featureOrder = {}, {}
  self.charts, self.chartOrder = {}, {}
  self.closed = false
  self.nextAt = nil
  self.debug = o.debug == true
  -- test seams
  self._getenv = o._getenv or (os and os.getenv)
  self._collect = o._collect
  self._post = o._post
  self._random = o._random
  self._firstDelay = o._firstDelay
  return self
end

local function value(v)
  if type(v) == "function" then return try(v) end
  return v
end

--- True unless the product's switch, SUNLICENSE_ANALYTICS or the sunlicense_analytics convar turns it off.
function Analytics:isEnabled()
  if self._getenv and isOff(try(self._getenv, "SUNLICENSE_ANALYTICS")) then return false end
  if isOff(rawget(_G, "SUNLICENSE_ANALYTICS")) then return false end
  if type(_G.GetConvar) == "function" and isOff(try(_G.GetConvar, "sunlicense_analytics", "on")) then return false end
  if type(self.enabled) == "function" then
    local fine, result = pcall(self.enabled)
    return fine and result ~= false and result ~= nil -- a switch that can't be read counts as off
  end
  return self.enabled ~= false
end

--- Stops reporting.
function Analytics:close()
  self.closed = true
end

function Analytics:log(kind, message)
  if kind ~= self.lastOutcome then
    self.lastOutcome = kind
    if self.debug then print("SunLicense analytics: " .. message) end
  end
end

--- Schedules the first report (1-30 minutes). On FiveM and Garry's Mod it then reports every
-- 30 minutes by itself; in plain Lua call analytics:poll() from your main loop.
function Analytics:start()
  if not self.productAnalyticsId and not (self.apiKey and self.fingerprint) then
    self:log("no-identity", "no product analytics id, and no API key and machine id: not reporting")
    return self
  end
  self:schedule(self._firstDelay or Analytics.firstDelay(self._random))
  return self
end

function Analytics:schedule(seconds)
  if self.closed then return end
  self.nextAt = now() + seconds
  local run = function() self:tick() end
  if self.env == "fivem" then
    local setTimeout = _G.SetTimeout or (type(_G.Citizen) == "table" and _G.Citizen.SetTimeout)
    if setTimeout then pcall(setTimeout, math.floor(seconds * 1000), run) end
  elseif self.env == "gmod" and type(_G.timer) == "table" and _G.timer.Simple then
    pcall(_G.timer.Simple, seconds, run)
  end
end

--- Plain Lua: sends a report when one is due (call it every few seconds or minutes). Returns true
-- when it sent one. Blocks for the HTTP call (at most the client's timeout) when it does.
function Analytics:poll()
  if self.closed or not self.nextAt or now() < self.nextAt then return false end
  self.nextAt = nil
  self:tick()
  return true
end

function Analytics:tick()
  if self.closed then return end
  local ok = pcall(self.send, self, function(status, retryAfter)
    self:schedule(Analytics.nextDelay(status, retryAfter))
  end)
  if not ok then self:schedule(INTERVAL) end
end

--- Sends one report now. `callback(status, retryAfter)` gets the HTTP status (204 = stored,
-- 0 = nothing sent: analytics off or no identity, -1 = no answer). In plain Lua the status is
-- also returned. Never raises.
function Analytics:sendNow(callback)
  local result
  local ok = pcall(self.send, self, function(status, retryAfter)
    result = status
    if callback then pcall(callback, status, retryAfter) end
  end)
  if not ok and result == nil then
    result = -1
    if callback then pcall(callback, -1, nil) end
  end
  return result
end

function Analytics:send(done)
  if self.closed then return done(0) end
  if not self:isEnabled() then
    self:log("off", "analytics is switched off; nothing sent")
    return done(0)
  end
  local report, sending = self:report()
  if not report then
    self:log("no-identity", "no license key yet and no product analytics id; nothing sent")
    return done(0)
  end
  local body = json(report)
  if #body > MAX_BODY then
    for k in pairs(report) do if not CORE_KEYS[k] then report[k] = nil end end
    sending = nil
    body = json(report)
  end
  local headers = {
    ["Content-Type"] = "application/json",
    ["User-Agent"] = "sunlicense-lua/" .. SunLicense.VERSION .. " analytics",
  }
  if report.licenseKey then headers["Authorization"] = "Bearer " .. self.apiKey end
  local finished = false
  local function answer(status, responseHeaders)
    if finished then return end
    finished = true
    status = tonumber(status) or -1
    if status <= 0 then status = -1 end
    local retryAfter = header(responseHeaders, "Retry-After")
    if status == 204 and sending then
      for name, uses in pairs(sending) do
        local left = (self.features[name] or 0) - uses
        if left > 0 then self.features[name] = left else self.features[name] = nil end
      end
    end
    if status == 204 then self:log("204", "report accepted")
    elseif status < 0 then self:log("no-answer", "SunLicense didn't answer; next report in 30 minutes")
    else self:log("http-" .. status, "report answered HTTP " .. status) end
    done(status, retryAfter)
  end
  local ok = pcall(self._post or Analytics.post, self.env, self.endpoint, headers, body, answer)
  if not ok then answer(-1) end
end

--- POSTs with whatever HTTP the environment has; `answer(status, headers)`.
function Analytics.post(env, url, headers, body, answer)
  if env == "fivem" then
    _G.PerformHttpRequest(url, function(status, _, responseHeaders) answer(status, responseHeaders) end,
      "POST", body, headers)
  elseif env == "gmod" then
    local h = {}
    for k, v in pairs(headers) do if k ~= "Content-Type" then h[k] = v end end
    _G.HTTP({ url = url, method = "POST", headers = h, body = body, type = "application/json",
      success = function(status, _, responseHeaders) answer(status, responseHeaders) end,
      failed = function() answer(-1) end })
  elseif env == "luasocket" then
    local http, ltn12 = require("socket.http"), require("ltn12")
    headers["Content-Length"] = tostring(#body)
    http.TIMEOUT = 10
    local _, status, responseHeaders = http.request({ url = url, method = "POST", headers = headers,
      source = ltn12.source.string(body), sink = ltn12.sink.null and ltn12.sink.null() or ltn12.sink.table({}) })
    answer(type(status) == "number" and status or -1, responseHeaders)
  else
    answer(-1)
  end
end

--- The report body and the feature counts it carries, or nil when this install can't say who it is yet.
function Analytics:report()
  local key = clean(value(self.licenseKey), 128)
  local licensed = key ~= nil and self.apiKey ~= nil and self.fingerprint ~= nil
  if not licensed and not self.productAnalyticsId then return nil end
  local r = { schema = 1, sdk = { name = Analytics.SDK_NAME, version = SunLicense.VERSION } }
  if licensed then
    r.licenseKey, r.fingerprint = key, self.fingerprint
  end
  if self.productAnalyticsId then
    r.productAnalyticsId = self.productAnalyticsId
    r.installId = self:installId() -- also with a license: an unknown key then still counts
  end
  local metrics = {}
  local okSystem, system = pcall(function()
    if not self.systemMetrics then
      self.systemMetrics = self._collect and self._collect() or Analytics.collect(self.env, self.platform)
    end
    return self.systemMetrics
  end)
  if okSystem and type(system) == "table" then for k, v in pairs(system) do metrics[k] = v end end
  local version = value(self.productVersion)
  if version == nil and self.env == "fivem" then
    version = try(function() return _G.GetResourceMetadata(_G.GetCurrentResourceName(), "version", 0) end)
  end
  metrics.productVersion = clean(version, 64)
  r.metrics = metrics
  local sending
  local okUsage = pcall(function()
    local features, n = {}, 0
    for _, name in ipairs(self.featureOrder) do
      if self.features[name] and n < MAX_FEATURES then
        features[name], n = self.features[name], n + 1
      end
    end
    if n > 0 then r.features, sending = features, features end
    local charts = array({})
    for _, id in ipairs(self.chartOrder) do
      local chart = self.charts[id]
      if chart and #charts < MAX_CHARTS then
        local ok, data = pcall(function() return Analytics.chartData(chart.type, chart.callback()) end)
        if ok and data then charts[#charts + 1] = { id = id, type = chart.type, data = data } end
      end
    end
    if #charts > 0 then r.charts = charts end
  end)
  if not okUsage then r.features, r.charts, sending = nil, nil, nil end
  return r, sending
end

function Analytics:installId()
  if self.id then return self.id end
  local stored
  if self.env == "fivem" then
    stored = try(function() return _G.LoadResourceFile(_G.GetCurrentResourceName(), INSTALL_ID_FILE) end)
  elseif self.env == "gmod" then
    stored = try(function() return _G.file.Read(self.dataName .. "/install-id.txt", "DATA") end)
  else
    stored = try(function()
      local f = io.open(self.dataDirectory .. "/" .. INSTALL_ID_FILE, "r")
      if not f then return nil end
      local s = f:read("*a")
      f:close()
      return s
    end)
  end
  stored = stored and tostring(stored):match("^%s*([%w_%-]+)%s*$")
  if stored and #stored >= 8 and #stored <= 64 then
    self.id = stored
    return stored
  end
  self.id = uuid()
  pcall(function()
    if self.env == "fivem" then
      _G.SaveResourceFile(_G.GetCurrentResourceName(), INSTALL_ID_FILE, self.id, -1)
    elseif self.env == "gmod" then
      _G.file.CreateDir(self.dataName)
      _G.file.Write(self.dataName .. "/install-id.txt", self.id)
    else
      local f = io.open(self.dataDirectory .. "/" .. INSTALL_ID_FILE, "w")
      if f then f:write(self.id) f:close() end
    end
  end)
  return self.id
end

--- Counts uses of one of your product's features ("auto-sell"): `uses` (default 1) is added and
-- sent with the next report, and kept until a report is stored. Never raises; nothing is counted
-- while analytics is off.
function Analytics:feature(name, uses)
  pcall(function()
    uses = uses == nil and 1 or uses
    local id = chartId(name)
    if not id or not isInteger(uses) or uses < 1 or not self:isEnabled() then return end
    if not self.features[id] then
      local known = false
      for _, n in ipairs(self.featureOrder) do if n == id then known = true break end end
      if not known then self.featureOrder[#self.featureOrder + 1] = id end
    end
    self.features[id] = math.min(MAX_NUMBER, (self.features[id] or 0) + uses)
  end)
  return self
end

function Analytics:chart(id, kind, callback)
  local key = chartId(id)
  if not key or type(callback) ~= "function" then
    self:log("bad-chart", "chart id " .. tostring(id) .. " ignored: use [a-z0-9][a-z0-9._-]{0,47} and a function")
    return self
  end
  self:removeChart(key)
  self.charts[key] = { type = kind, callback = callback }
  self.chartOrder[#self.chartOrder + 1] = key
  return self
end

--- A pie of one value per install: simplePie("storage", function() return Config.Storage end).
function Analytics:simplePie(id, callback) return self:chart(id, "simple_pie", callback) end
--- A pie of weighted values per install: advancedPie("modules", function() return { shop = 1 } end).
function Analytics:advancedPie(id, callback) return self:chart(id, "advanced_pie", callback) end
--- A two-level pie: drilldownPie("framework", function() return { esx = { ["1.10"] = 1 } } end).
function Analytics:drilldownPie(id, callback) return self:chart(id, "drilldown_pie", callback) end
--- A number summed over installs: singleLine("players", function() return #GetPlayers() end).
function Analytics:singleLine(id, callback) return self:chart(id, "single_line", callback) end
--- Several numbers per install, one line each.
function Analytics:multiLine(id, callback) return self:chart(id, "multi_line", callback) end
--- Numbers per category: simpleBar("commands", function() return { sell = 12 } end).
function Analytics:simpleBar(id, callback) return self:chart(id, "simple_bar", callback) end
--- Several numbers per category: advancedBar("tiers", function() return { gold = { 1, 2, 3 } } end).
function Analytics:advancedBar(id, callback) return self:chart(id, "advanced_bar", callback) end

--- Stops sending a custom chart.
function Analytics:removeChart(id)
  local key = chartId(id)
  if not key then return self end
  self.charts[key] = nil
  for i = #self.chartOrder, 1, -1 do
    if self.chartOrder[i] == key then table.remove(self.chartOrder, i) end
  end
  return self
end

local function number(v)
  if isInteger(v) and math.abs(v) <= MAX_NUMBER then return v end
  return nil
end

-- {key = integer >= min}, at most 50 entries (in key order); nil when empty.
local function numbers(t, min)
  if type(t) ~= "table" then return nil end
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local out, n = {}, 0
  for _, k in ipairs(keys) do
    local key, v = clean(k, 64), t[k]
    if key and number(v) and v >= min and n < MAX_VALUES then
      out[key], n = v, n + 1
    end
  end
  return n > 0 and out or nil
end

--- A chart callback's value as the report's `data`, or nil when there's nothing (valid) to send.
function Analytics.chartData(kind, v)
  if v == nil then return nil end
  if kind == "simple_pie" then
    local s = (type(v) == "string" or type(v) == "number") and clean(v, 64) or nil
    return s and { value = s } or nil
  elseif kind == "single_line" then
    return number(v) and { value = v } or nil
  elseif kind == "advanced_pie" or kind == "multi_line" or kind == "simple_bar" then
    local values = numbers(v, kind == "advanced_pie" and 1 or -MAX_NUMBER)
    return values and { values = values } or nil
  elseif kind == "drilldown_pie" and type(v) == "table" then
    local out, n = {}, 0
    for outer, inner in pairs(v) do
      local key, slice = clean(outer, 64), numbers(inner, 1)
      if key and slice and n < MAX_VALUES then out[key], n = slice, n + 1 end
    end
    return n > 0 and { values = out } or nil
  elseif kind == "advanced_bar" and type(v) == "table" then
    local out, n = {}, 0
    for k, list in pairs(v) do
      local key, nums, fine = clean(k, 64), array({}), type(list) == "table" and #list > 0
      if fine then
        for i = 1, math.min(#list, MAX_BAR) do
          if not number(list[i]) then fine = false break end
          nums[i] = list[i]
        end
      end
      if key and fine and n < MAX_VALUES then out[key], n = nums, n + 1 end
    end
    return n > 0 and { values = out } or nil
  end
  return nil
end

return SunLicense
