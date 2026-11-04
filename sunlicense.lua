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
SunLicense.VERSION = "0.2.0"

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

  -- With client:protection{...}: send the integrity result, and keep (valid + unlock) or forget
  -- (valid: false) the unlock from the answer. Outages change nothing.
  local protector = self.protector
  if protector then
    protector:license(licenseKey, payload.fingerprint or payload.hwid or payload.host or protector.fingerprint)
    for key, value in pairs(protector:validateFields()) do
      if payload[key] == nil then payload[key] = value end
    end
    local inner = callback
    callback = function(ok, status, responseBody)
      pcall(protector.accept, protector, responseBody)
      if inner then return inner(ok, status, responseBody) end
    end
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
    self.features, self.featureOrder = {}, {} -- nothing is counted while it's off
    self:log("off", "analytics is switched off; nothing sent")
    return done(0)
  end
  local report, sending = self:report()
  if not report then
    self:log("no-identity", "no license key yet and no product analytics id; nothing sent")
    return done(0)
  end
  local body = json(report)
  if #body > MAX_BODY and report.charts then -- charts go first, then features
    report.charts = nil
    body = json(report)
  end
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
    if not id or not isInteger(uses) or uses < 1 or self.closed or not self:isEnabled() then return end
    if not self.features[id] then
      local count = 0
      for _ in pairs(self.features) do count = count + 1 end
      if count >= MAX_FEATURES then return end -- at most 50 different features
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
      local key, nums = clean(k, 64), array({})
      if type(list) == "table" then
        for i = 1, math.min(#list, MAX_BAR) do
          if not number(list[i]) then break end -- up to 20 numbers, until the first that isn't one
          nums[i] = list[i]
        end
      end
      if key and #nums > 0 and n < MAX_VALUES then out[key], n = nums, n + 1 end
    end
    return n > 0 and { values = out } or nil
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- Crypto for core unlock and integrity: SHA-256, HMAC-SHA256, AES-256-GCM (decrypt and
-- encrypt), base64. Pure Lua for every host: Lua 5.3/5.4 (FiveM) with native bit operators,
-- LuaJIT (Garry's Mod) with `bit`, Lua 5.2 with `bit32`, and plain Lua 5.1 with arithmetic.
-- ---------------------------------------------------------------------------

local Crypto = {}
SunLicense.Crypto = Crypto

local M32 = 4294967296

-- 32-bit operations on non-negative integers in [0, 2^32).
local band, bor, bxor, shl, shr
do
  local native = (loadstring or load)([[
    return function(a, b) return a & b end,
           function(a, b) return a | b end,
           function(a, b) return a ~ b end,
           function(a, n) return (a << n) & 0xffffffff end,
           function(a, n) return a >> n end
  ]])
  local ok, a, o, x, l, r = false
  if native and math.type then ok, a, o, x, l, r = pcall(native) end
  if ok and a then
    band, bor, bxor, shl, shr = a, o, x, l, r
  else
    local lib = rawget(_G, "bit32") or rawget(_G, "bit")
    if not lib then
      local okBit, b = pcall(require, "bit")
      if okBit and type(b) == "table" then lib = b end
    end
    if lib then
      local f = function(fn) return function(p, q) return fn(p, q) % M32 end end
      band, bor, bxor, shl, shr = f(lib.band), f(lib.bor), f(lib.bxor), f(lib.lshift), f(lib.rshift)
    else
      -- Lua 5.1 without a bit library: bit by bit (slow, but correct).
      local function op(p, q, which)
        local res, bitv = 0, 1
        for _ = 1, 32 do
          local pa, qa = p % 2, q % 2
          local on
          if which == 1 then on = pa == 1 and qa == 1
          elseif which == 2 then on = pa == 1 or qa == 1
          else on = pa ~= qa end
          if on then res = res + bitv end
          p, q, bitv = (p - pa) / 2, (q - qa) / 2, bitv * 2
        end
        return res
      end
      band = function(p, q) return op(p, q, 1) end
      bor = function(p, q) return op(p, q, 2) end
      bxor = function(p, q) return op(p, q, 3) end
      shl = function(p, n) return (p * 2 ^ n) % M32 end
      shr = function(p, n) return math.floor(p / 2 ^ n) end
    end
  end
end

local function rotr(x, n) return bor(shr(x, n), shl(x, 32 - n)) end

local function bytesToWord(s, i)
  local b1, b2, b3, b4 = s:byte(i, i + 3)
  return ((b1 * 256 + b2) * 256 + b3) * 256 + b4
end

local function wordToBytes(w)
  return string.char(math.floor(w / 16777216) % 256, math.floor(w / 65536) % 256,
    math.floor(w / 256) % 256, w % 256)
end

-- SHA-256 ------------------------------------------------------------------

local K256 = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

--- SHA-256 of a byte string, as 32 raw bytes.
function Crypto.sha256(msg)
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  local len = #msg
  local bits = len * 8
  local tail = "\128" .. string.rep("\0", (55 - len) % 64)
    .. wordToBytes(math.floor(bits / M32) % M32) .. wordToBytes(bits % M32)
  msg = msg .. tail
  local w = {}
  for chunk = 1, #msg, 64 do
    for i = 1, 16 do w[i] = bytesToWord(msg, chunk + (i - 1) * 4) end
    for i = 17, 64 do
      local x, y = w[i - 15], w[i - 2]
      local s0 = bxor(bxor(rotr(x, 7), rotr(x, 18)), shr(x, 3))
      local s1 = bxor(bxor(rotr(y, 17), rotr(y, 19)), shr(y, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % M32
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 64 do
      local S1 = bxor(bxor(rotr(e, 6), rotr(e, 11)), rotr(e, 25))
      local ch = bxor(band(e, f), band(M32 - 1 - e, g))
      local t1 = (h + S1 + ch + K256[i] + w[i]) % M32
      local S0 = bxor(bxor(rotr(a, 2), rotr(a, 13)), rotr(a, 22))
      local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
      local t2 = (S0 + maj) % M32
      h, g, f, e, d, c, b, a = g, f, e, (d + t1) % M32, c, b, a, (t1 + t2) % M32
    end
    h0, h1, h2, h3 = (h0 + a) % M32, (h1 + b) % M32, (h2 + c) % M32, (h3 + d) % M32
    h4, h5, h6, h7 = (h4 + e) % M32, (h5 + f) % M32, (h6 + g) % M32, (h7 + h) % M32
  end
  return wordToBytes(h0) .. wordToBytes(h1) .. wordToBytes(h2) .. wordToBytes(h3)
    .. wordToBytes(h4) .. wordToBytes(h5) .. wordToBytes(h6) .. wordToBytes(h7)
end

--- Lower-case hex of a byte string.
function Crypto.hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

--- HMAC-SHA256(key, msg), raw bytes.
function Crypto.hmacSha256(key, msg)
  if #key > 64 then key = Crypto.sha256(key) end
  key = key .. string.rep("\0", 64 - #key)
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local k = key:byte(i)
    ipad[i] = string.char(bxor(k, 0x36))
    opad[i] = string.char(bxor(k, 0x5c))
  end
  return Crypto.sha256(table.concat(opad) .. Crypto.sha256(table.concat(ipad) .. msg))
end

--- HKDF-SHA256 (RFC 5869): `length` bytes from input key material, salt and info.
function Crypto.hkdf(ikm, salt, info, length)
  local prk = Crypto.hmacSha256(salt or "", ikm)
  local out, t, i = {}, "", 1
  while #table.concat(out) < length do
    t = Crypto.hmacSha256(prk, t .. (info or "") .. string.char(i))
    out[#out + 1] = t
    i = i + 1
  end
  return table.concat(out):sub(1, length)
end

-- base64 ---------------------------------------------------------------------

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64DEC = {}
for i = 1, 64 do B64DEC[B64:byte(i)] = i - 1 end
B64DEC[("-"):byte()] = 62
B64DEC[("_"):byte()] = 63

--- Decodes base64 or base64url, with or without padding; nil when it isn't base64.
function Crypto.fromBase64(s)
  if type(s) ~= "string" then return nil end
  s = s:gsub("%s", ""):gsub("=+$", "")
  if #s % 4 == 1 then return nil end
  local out, acc, n = {}, 0, 0
  for i = 1, #s do
    local v = B64DEC[s:byte(i)]
    if not v then return nil end
    acc, n = acc * 64 + v, n + 6
    if n >= 8 then
      n = n - 8
      local b = math.floor(acc / 2 ^ n)
      out[#out + 1] = string.char(b)
      acc = acc - b * 2 ^ n
    end
  end
  return table.concat(out)
end

--- Standard base64 with padding (`url` = true: base64url without padding).
function Crypto.toBase64(s, url)
  local out = {}
  for i = 1, #s, 3 do
    local a, b, c = s:byte(i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1, c2 = math.floor(n / 262144) % 64, math.floor(n / 4096) % 64
    local c3, c4 = math.floor(n / 64) % 64, n % 64
    out[#out + 1] = B64:sub(c1 + 1, c1 + 1) .. B64:sub(c2 + 1, c2 + 1)
      .. (b and B64:sub(c3 + 1, c3 + 1) or "=") .. (c and B64:sub(c4 + 1, c4 + 1) or "=")
  end
  local r = table.concat(out)
  if url then r = r:gsub("+", "-"):gsub("/", "_"):gsub("=", "") end
  return r
end

-- AES-256 (encryption direction only: GCM needs nothing else) ------------------

local SBOX = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}
do
  for i = 1, 256 do SBOX[i - 1] = SBOX[i] end
  SBOX[256] = nil
end
local TE0, TE1, TE2, TE3 = {}, {}, {}, {}
do
  local function xtime(x) x = x * 2 if x >= 256 then x = bxor(x, 0x11b) end return x end
  for i = 0, 255 do
    local s = SBOX[i]
    local s2 = xtime(s)
    local s3 = bxor(s2, s)
    TE0[i] = ((s2 * 256 + s) * 256 + s) * 256 + s3
    TE1[i] = ((s3 * 256 + s2) * 256 + s) * 256 + s
    TE2[i] = ((s * 256 + s3) * 256 + s2) * 256 + s
    TE3[i] = ((s * 256 + s) * 256 + s3) * 256 + s2
  end
end

local function byteOf(w, n) -- n = 0 (most significant) .. 3
  return math.floor(w / 2 ^ (24 - 8 * n)) % 256
end

local function subWord(w)
  return ((SBOX[byteOf(w, 0)] * 256 + SBOX[byteOf(w, 1)]) * 256 + SBOX[byteOf(w, 2)]) * 256 + SBOX[byteOf(w, 3)]
end

--- Expands a 32-byte key into 60 round-key words.
local function expandKey(key)
  local w = {}
  for i = 0, 7 do w[i] = bytesToWord(key, i * 4 + 1) end
  local rcon = 1
  for i = 8, 59 do
    local t = w[i - 1]
    if i % 8 == 0 then
      t = bxor(subWord(bor(shl(t, 8), shr(t, 24))), rcon * 16777216)
      rcon = rcon * 2
      if rcon >= 256 then rcon = bxor(rcon, 0x11b) end
    elseif i % 8 == 4 then
      t = subWord(t)
    end
    w[i] = bxor(w[i - 8], t)
  end
  return w
end

-- Encrypts one block given as four words; returns four words.
local function encryptBlock(rk, s0, s1, s2, s3)
  s0, s1, s2, s3 = bxor(s0, rk[0]), bxor(s1, rk[1]), bxor(s2, rk[2]), bxor(s3, rk[3])
  local k = 4
  for _ = 1, 13 do
    local t0 = bxor(bxor(TE0[byteOf(s0, 0)], TE1[byteOf(s1, 1)]), bxor(TE2[byteOf(s2, 2)], bxor(TE3[s3 % 256], rk[k])))
    local t1 = bxor(bxor(TE0[byteOf(s1, 0)], TE1[byteOf(s2, 1)]), bxor(TE2[byteOf(s3, 2)], bxor(TE3[s0 % 256], rk[k + 1])))
    local t2 = bxor(bxor(TE0[byteOf(s2, 0)], TE1[byteOf(s3, 1)]), bxor(TE2[byteOf(s0, 2)], bxor(TE3[s1 % 256], rk[k + 2])))
    local t3 = bxor(bxor(TE0[byteOf(s3, 0)], TE1[byteOf(s0, 1)]), bxor(TE2[byteOf(s1, 2)], bxor(TE3[s2 % 256], rk[k + 3])))
    s0, s1, s2, s3 = t0, t1, t2, t3
    k = k + 4
  end
  local function last(a, b, c, d, r)
    return bxor(((SBOX[byteOf(a, 0)] * 256 + SBOX[byteOf(b, 1)]) * 256 + SBOX[byteOf(c, 2)]) * 256 + SBOX[d % 256], r)
  end
  return last(s0, s1, s2, s3, rk[56]), last(s1, s2, s3, s0, rk[57]),
    last(s2, s3, s0, s1, rk[58]), last(s3, s0, s1, s2, rk[59])
end

--- AES-256 of one 16-byte block (exposed for tests).
function Crypto.aes256Block(key, block)
  local rk = expandKey(key)
  local a, b, c, d = encryptBlock(rk, bytesToWord(block, 1), bytesToWord(block, 5), bytesToWord(block, 9), bytesToWord(block, 13))
  return wordToBytes(a) .. wordToBytes(b) .. wordToBytes(c) .. wordToBytes(d)
end

-- GHASH with a 4-bit table (Shoup), on four 32-bit words ----------------------

local LAST4 = { [0] = 0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0 }

local function ghashTable(h0, h1, h2, h3)
  local T = { [0] = { 0, 0, 0, 0 } }
  local v = { h0, h1, h2, h3 }
  T[8] = { v[1], v[2], v[3], v[4] }
  local i = 4
  while i > 0 do
    local carry = v[4] % 2
    v[4] = bor(shr(v[4], 1), shl(v[3] % 2, 31))
    v[3] = bor(shr(v[3], 1), shl(v[2] % 2, 31))
    v[2] = bor(shr(v[2], 1), shl(v[1] % 2, 31))
    v[1] = shr(v[1], 1)
    if carry == 1 then v[1] = bxor(v[1], 0xe1000000) end
    T[i] = { v[1], v[2], v[3], v[4] }
    i = math.floor(i / 2)
  end
  i = 2
  while i <= 8 do
    for j = 1, i - 1 do
      local a, b = T[i], T[j]
      T[i + j] = { bxor(a[1], b[1]), bxor(a[2], b[2]), bxor(a[3], b[3]), bxor(a[4], b[4]) }
    end
    i = i * 2
  end
  return T
end

-- x (16-byte string) * H; returns four words.
local function ghashMul(T, x)
  local lo = x:byte(16) % 16
  local z = T[lo]
  local z1, z2, z3, z4 = z[1], z[2], z[3], z[4]
  for i = 16, 1, -1 do
    local byte = x:byte(i)
    local nlo, nhi = byte % 16, math.floor(byte / 16)
    if i ~= 16 then
      local rem = z4 % 16
      z4 = bor(shr(z4, 4), shl(z3 % 16, 28))
      z3 = bor(shr(z3, 4), shl(z2 % 16, 28))
      z2 = bor(shr(z2, 4), shl(z1 % 16, 28))
      z1 = bxor(shr(z1, 4), LAST4[rem] * 65536)
      local t = T[nlo]
      z1, z2, z3, z4 = bxor(z1, t[1]), bxor(z2, t[2]), bxor(z3, t[3]), bxor(z4, t[4])
    end
    local rem = z4 % 16
    z4 = bor(shr(z4, 4), shl(z3 % 16, 28))
    z3 = bor(shr(z3, 4), shl(z2 % 16, 28))
    z2 = bor(shr(z2, 4), shl(z1 % 16, 28))
    z1 = bxor(shr(z1, 4), LAST4[rem] * 65536)
    local t = T[nhi]
    z1, z2, z3, z4 = bxor(z1, t[1]), bxor(z2, t[2]), bxor(z3, t[3]), bxor(z4, t[4])
  end
  return z1, z2, z3, z4
end

local function xorBlock(a, b) -- b may be shorter (last block)
  local out = {}
  for i = 1, #b do out[i] = string.char(bxor(a:byte(i), b:byte(i))) end
  return table.concat(out)
end

local function words(a, b, c, d) return wordToBytes(a) .. wordToBytes(b) .. wordToBytes(c) .. wordToBytes(d) end

local function ghash(T, aad, ct)
  local y = string.rep("\0", 16)
  local function absorb(data)
    for i = 1, #data, 16 do
      local block = data:sub(i, i + 15)
      if #block < 16 then block = block .. string.rep("\0", 16 - #block) end
      y = words(ghashMul(T, xorBlock(y, block)))
    end
  end
  absorb(aad)
  absorb(ct)
  local function len64(n)
    local bits = n * 8
    return wordToBytes(math.floor(bits / M32) % M32) .. wordToBytes(bits % M32)
  end
  return words(ghashMul(T, xorBlock(y, len64(#aad) .. len64(#ct))))
end

local function gcmCore(key, iv, input, aad)
  local rk = expandKey(key)
  local T = ghashTable(encryptBlock(rk, 0, 0, 0, 0))
  local j0
  if #iv == 12 then
    j0 = iv .. "\0\0\0\1"
  else
    local pad = string.rep("\0", (16 - #iv % 16) % 16)
    local bits = #iv * 8
    local y = string.rep("\0", 16)
    local data = iv .. pad .. string.rep("\0", 8) .. wordToBytes(math.floor(bits / M32) % M32) .. wordToBytes(bits % M32)
    for i = 1, #data, 16 do y = words(ghashMul(T, xorBlock(y, data:sub(i, i + 15)))) end
    j0 = y
  end
  local c0, c1, c2 = bytesToWord(j0, 1), bytesToWord(j0, 5), bytesToWord(j0, 9)
  local counter = bytesToWord(j0, 13)
  local out = {}
  for i = 1, #input, 16 do
    counter = (counter + 1) % M32
    local ks = words(encryptBlock(rk, c0, c1, c2, counter))
    out[#out + 1] = xorBlock(ks, input:sub(i, i + 15))
  end
  local tagMask = words(encryptBlock(rk, c0, c1, c2, bytesToWord(j0, 13)))
  return table.concat(out), T, tagMask
end

--- AES-256-GCM encryption: ciphertext and 16-byte tag.
function Crypto.gcmEncrypt(key, iv, plaintext, aad)
  aad = aad or ""
  local ct, T, mask = gcmCore(key, iv, plaintext, aad)
  return ct, xorBlock(mask, ghash(T, aad, ct))
end

--- AES-256-GCM decryption; nil when the tag doesn't match (wrong key or changed data).
function Crypto.gcmDecrypt(key, iv, ciphertext, tag, aad)
  aad = aad or ""
  if #key ~= 32 or #tag ~= 16 then return nil end
  local pt, T, mask = gcmCore(key, iv, ciphertext, aad)
  local expected = xorBlock(mask, ghash(T, aad, ciphertext))
  local diff = 0
  for i = 1, 16 do diff = bor(diff, bxor(expected:byte(i), tag:byte(i))) end
  if diff ~= 0 then return nil end
  return pt
end

-- ---------------------------------------------------------------------------
-- Protection: core unlock, tamper reports, ownership notice, protected files
-- ---------------------------------------------------------------------------
--
-- `sunlicense seal` encrypts part of your resource (its "core") under a key only SunLicense
-- holds. A valid license check answers with that key (`unlock`); a rejected one (suspended,
-- expired, revoked) doesn't, and the unlock the resource had is forgotten. A copy whose license
-- check was cut out can't run its core. To ride out outages, the unlock from the last valid check
-- is cached for 7 days, encrypted under a key bound to the license key, the machine id and this
-- machine.
--
--   local client = SunLicense.new({ baseUrl = "https://api.sunlicense.com", token = apiKey })
--   local protection = client:protection({ licenseKey = key, fingerprint = machineId,
--     product = "My Script", owner = "Example Studio", terms = "https://example.com/terms",
--     productCode = "my-script" })                      -- productCode: protected files only
--   print(protection:notice())                          -- product, owner, masked key
--   client:validate(key, { fingerprint = machineId }, function(ok)
--     local core, err = protection:unseal(SEALED_CORE) -- nil + reason without a valid unlock
--     if core then load(core, "@core")() end
--     protection:integrity()                            -- "OK" / "MODIFIED", sent with the next check
--   end)
--
-- Honest limit: someone with a valid license can still extract the unlock and patch their copy;
-- that copy then fails its integrity check and is reported. Protection raises the cost and makes
-- leaks visible; it doesn't make code uncrackable.

local Protection = {}
Protection.__index = Protection
SunLicense.Protection = Protection

Protection.CACHE_TTL = 7 * 24 * 3600 -- seconds
local SKEW = 10 * 60
local SEALED_PREFIX, CACHE_PREFIX, CACHE_FILE = "SLS1.", "SLC1.", ".sunlicense-unlock-"
local SEALED_AAD = "SLS1"
local MAX_DETAIL = 200

-- JSON reader (objects -> tables, arrays -> lists, null -> nil) ---------------

local function jsonDecode(s)
  local pos = 1
  local value
  local function ws() pos = s:find("[^ \t\r\n]", pos) or (#s + 1) end
  local function fail() error("bad json at " .. pos, 0) end
  local function str()
    local out = {}
    pos = pos + 1
    while true do
      local c = s:sub(pos, pos)
      if c == "" then fail() end
      if c == '"' then pos = pos + 1 break end
      if c == "\\" then
        local e = s:sub(pos + 1, pos + 1)
        local map = { b = "\b", f = "\f", n = "\n", r = "\r", t = "\t", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
        if map[e] then
          out[#out + 1] = map[e]
          pos = pos + 2
        elseif e == "u" then
          local cp = tonumber(s:sub(pos + 2, pos + 5), 16)
          if not cp then fail() end
          pos = pos + 6
          if cp >= 0xD800 and cp <= 0xDBFF and s:sub(pos, pos + 1) == "\\u" then
            local lo = tonumber(s:sub(pos + 2, pos + 5), 16)
            if lo then cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00) pos = pos + 6 end
          end
          if cp < 0x80 then out[#out + 1] = string.char(cp)
          elseif cp < 0x800 then out[#out + 1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64)
          elseif cp < 0x10000 then
            out[#out + 1] = string.char(0xE0 + math.floor(cp / 4096), 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
          else
            out[#out + 1] = string.char(0xF0 + math.floor(cp / 262144), 0x80 + math.floor(cp / 4096) % 64,
              0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
          end
        else
          fail()
        end
      else
        local stop = s:find('["\\]', pos) or (#s + 1)
        out[#out + 1] = s:sub(pos, stop - 1)
        pos = stop
      end
    end
    return table.concat(out)
  end
  function value()
    ws()
    local c = s:sub(pos, pos)
    if c == "{" then
      local t = {}
      pos = pos + 1
      ws()
      if s:sub(pos, pos) == "}" then pos = pos + 1 return t end
      while true do
        ws()
        if s:sub(pos, pos) ~= '"' then fail() end
        local k = str()
        ws()
        if s:sub(pos, pos) ~= ":" then fail() end
        pos = pos + 1
        t[k] = value()
        ws()
        local d = s:sub(pos, pos)
        pos = pos + 1
        if d == "}" then return t end
        if d ~= "," then fail() end
      end
    elseif c == "[" then
      local t, n = {}, 0
      pos = pos + 1
      ws()
      if s:sub(pos, pos) == "]" then pos = pos + 1 return t end
      while true do
        n = n + 1
        t[n] = value()
        ws()
        local d = s:sub(pos, pos)
        pos = pos + 1
        if d == "]" then return t end
        if d ~= "," then fail() end
      end
    elseif c == '"' then
      return str()
    elseif s:sub(pos, pos + 3) == "true" then pos = pos + 4 return true
    elseif s:sub(pos, pos + 4) == "false" then pos = pos + 5 return false
    elseif s:sub(pos, pos + 3) == "null" then pos = pos + 4 return nil
    end
    local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
    if not num or num == "" then fail() end
    pos = pos + #num
    return tonumber(num)
  end
  local result = value()
  ws()
  if pos <= #s then fail() end
  return result
end
SunLicense.jsonDecode = function(s)
  local ok, v = pcall(jsonDecode, s)
  if ok then return v end
  return nil
end

-- Helpers ---------------------------------------------------------------------

local function trim(s)
  if s == nil then return nil end
  s = tostring(s):match("^%s*(.-)%s*$")
  return s ~= "" and s or nil
end

local randomCounter = 0
--- n unpredictable-enough bytes (no CSPRNG in plain Lua: hashed clocks, addresses and a counter).
local function randomBytes(n)
  local out = ""
  while #out < n do
    randomCounter = randomCounter + 1
    local seed = table.concat({ tostring(now()), tostring((os and os.clock and os.clock()) or 0), tostring({}),
      tostring(randomCounter), tostring(math.random()), tostring(collectgarbage and collectgarbage("count") or 0) }, "|")
    out = out .. Crypto.sha256(seed .. out)
  end
  return out:sub(1, n)
end

--- "AX8P-XXXX-XXXX-XXXX": the first group, the rest as X.
function Protection.mask(key)
  key = trim(key)
  if not key then return "(none)" end
  local groups = {}
  for g in (key .. "-"):gmatch("([^-]*)-") do groups[#groups + 1] = g end
  if #groups == 1 then
    return key:sub(1, 4) .. string.rep("X", math.max(0, #key - 4))
  end
  local out = { groups[1] }
  for i = 2, #groups do out[i] = string.rep("X", #groups[i]) end
  return table.concat(out, "-")
end

--- Lower-case hex SHA-256 of a string ("sha256:" and upper case accepted where digests are read).
function Protection.digest(bytes)
  return Crypto.hex(Crypto.sha256(bytes))
end

local function normaliseDigest(d)
  if type(d) ~= "string" then return nil end
  d = d:match("^%s*(.-)%s*$"):lower()
  return (d:gsub("^sha256:", ""))
end
Protection.normaliseDigest = normaliseDigest

--- The "N changed: a, b, +3 more" text sent as integrityDetail (at most 200 characters).
function Protection.detail(changed)
  local b = #changed .. " changed: "
  local shown = 0
  for _, c in ipairs(changed) do
    local nextPart = (shown == 0 and "" or ", ") .. c
    local reserve = (shown + 1 < #changed) and 16 or 0
    if #b + #nextPart + reserve > MAX_DETAIL then break end
    b = b .. nextPart
    shown = shown + 1
  end
  if shown < #changed then
    b = b .. (shown == 0 and "" or ", ") .. "+" .. (#changed - shown) .. " more"
  end
  return b:sub(1, MAX_DETAIL)
end

--- Opens an `SLS1.` blob with a product key: data, digests; or nil and the reason.
function Protection.open(sealed, key)
  sealed = trim(sealed)
  if not sealed or sealed:sub(1, #SEALED_PREFIX) ~= SEALED_PREFIX then
    return nil, "not sealed data: expected text starting with " .. SEALED_PREFIX
  end
  local raw = Crypto.fromBase64(sealed:sub(#SEALED_PREFIX + 1))
  if not raw or #raw < 12 + 16 then return nil, "not sealed data: too short" end
  local plain = Crypto.gcmDecrypt(key, raw:sub(1, 12), raw:sub(13, #raw - 16), raw:sub(#raw - 15), SEALED_AAD)
  if not plain then
    return nil, "this data wasn't sealed for this product's unlock (sealed for another product, or re-sealed since)"
  end
  local m = SunLicense.jsonDecode(plain)
  if type(m) ~= "table" or type(m.data) ~= "string" then return nil, "sealed content has no data" end
  local data = Crypto.fromBase64(m.data)
  if not data then return nil, "sealed content isn't readable" end
  local digests = {}
  if type(m.digests) == "table" then
    for path, d in pairs(m.digests) do
      if type(d) == "string" then digests[tostring(path)] = d:lower() end
    end
  end
  return data, digests
end

-- A stable id for this machine: what makes a copied cache file useless elsewhere.
local function machineId()
  local parts = { (package and package.config or "/"):sub(1, 1) }
  for _, file in ipairs({ "/etc/machine-id", "/var/lib/dbus/machine-id" }) do
    local id = try(function()
      local f = io.open(file, "r")
      if not f then return nil end
      local s = f:read("*l")
      f:close()
      return s
    end)
    if id and id ~= "" then parts[#parts + 1] = id break end
  end
  local getenv = os and os.getenv
  for _, name in ipairs({ "COMPUTERNAME", "HOSTNAME", "PROCESSOR_IDENTIFIER" }) do
    local v = getenv and try(getenv, name)
    if v then parts[#parts + 1] = v end
  end
  return Protection.digest(table.concat(parts, "|"))
end
Protection.machineId = machineId

-- Protection object -----------------------------------------------------------

--- `client:protection{...}` (bound to the client: its base URL and API key, and every later
-- client:validate() sends the integrity result and keeps or forgets the unlock) or
-- `SunLicense.protection{...}` on its own. Options: licenseKey, fingerprint, apiKey, baseUrl, productCode
-- (protected files), product and owner (the notice), terms (link), cacheDirectory (plain Lua;
-- false = memory only; default "."), dataName (Garry's Mod: data/<dataName>/). Never raises.
function SunLicense.protection(first, options)
  options = type(options) == "table" and options or {}
  local o = {}
  for k, v in pairs(options) do o[k] = v end
  local client = type(first) == "table" and getmetatable(first) == SunLicense and first or nil
  if client then
    o.baseUrl = o.baseUrl or client.baseUrl
    o.apiKey = o.apiKey or client.token
  elseif type(first) == "table" then
    for k, v in pairs(first) do if o[k] == nil then o[k] = v end end
  end
  local p = Protection.new(o)
  -- client:protection{...}: every later client:validate() sends its integrity result and gives it the answer
  if client then client.protector = p end
  return p
end

function Protection.new(o)
  o = o or {}
  local self = setmetatable({}, Protection)
  self.baseUrl = tostring(o.baseUrl or Analytics.DEFAULT_BASE_URL):gsub("/+$", "")
  self.apiKey = trim(o.apiKey)
  self.licenseKey = trim(o.licenseKey)
  self.fingerprint = trim(o.fingerprint)
  self.productCode = trim(o.productCode)
  self.productName = trim(o.product)
  self.owner = trim(o.owner)
  self.terms = trim(o.terms)
  if o.cacheDirectory == nil then self.cacheDirectory = "." else self.cacheDirectory = o.cacheDirectory end
  self.dataName = o.dataName or "sunlicense"
  self.env = o.environment or SunLicense.environment()
  self.unlock = nil
  self.sealedDigests = {}
  self.integrityValue, self.integrityDetailValue = nil, nil
  -- test seams
  self._now = o._now or now
  self._machine = o._machine or machineId
  self._get = o._get
  self._storage = o._storage
  return self
end

--- The license key and machine id this install checks with; a different key drops the unlock held in memory.
function Protection:license(licenseKey, fingerprint)
  local key = trim(licenseKey)
  if key == nil or key ~= self.licenseKey then self.unlock = nil end
  self.licenseKey = key
  self.fingerprint = trim(fingerprint)
end

--- Reads a license check's answer (the JSON body of /api/v2/license/validate or /api/v1/validate).
-- A valid answer with `unlock` keeps and caches it; a definite "no" (valid: false) forgets it.
-- Anything unreadable is ignored (like no answer).
function Protection:accept(body, unlockBase64)
  if type(body) == "boolean" then return self:acceptAnswer(body, unlockBase64) end
  local parsed = type(body) == "table" and body or SunLicense.jsonDecode(tostring(body or ""))
  if type(parsed) ~= "table" then return end
  if parsed.valid == true then
    self:acceptAnswer(true, type(parsed.unlock) == "string" and parsed.unlock or nil)
  elseif parsed.valid == false then
    self:acceptAnswer(false)
  end
end

function Protection:acceptAnswer(valid, unlockBase64)
  if not valid then return self:rejected() end
  if not trim(unlockBase64) then return end -- valid, but nothing sealed: keep what we have
  local key = Crypto.fromBase64(trim(unlockBase64))
  if not key or (#key ~= 16 and #key ~= 24 and #key ~= 32) then return end
  self.unlock = key
  pcall(self.writeCache, self, key)
end

--- SunLicense said no: the unlock (in memory and on disk) is gone until the next valid check.
function Protection:rejected()
  self.unlock = nil
  local name = self:cacheFile()
  if name then pcall(self.storage(self).delete, name) end
end

--- True when an unlock is available: from this run's valid check or the cache (at most 7 days old).
function Protection:unlocked()
  return self:key() ~= nil
end

--- Decrypts data sealed with `sunlicense seal` (an "SLS1." string). Returns the data and the
-- digests sealed with it, or nil and the reason without a valid unlock or when the data was
-- sealed for another product. Remembers the digests for :integrity().
function Protection:unseal(sealed)
  local key = self:key()
  if not key then
    return nil, "no valid license check yet: the protected part of this product stays locked"
  end
  local data, digests = Protection.open(sealed, key)
  if not data then return nil, digests end
  self.sealedDigests = digests
  return data, digests
end

--- The digests sealed with the last data :unseal() opened (path -> lowercase hex SHA-256).
function Protection:digests()
  return self.sealedDigests
end

-- Reads one of the product's own files by its path: the resource's files on FiveM, the addon's
-- Lua files on Garry's Mod, files under `base` (default ".") in plain Lua.
function Protection:defaultReader(base)
  local env = self.env
  return function(path)
    if env == "fivem" then
      return try(function() return _G.LoadResourceFile(_G.GetCurrentResourceName(), path) end)
    elseif env == "gmod" then
      return try(function() return _G.file.Read(path, "LUA") end)
    end
    return try(function()
      local f = io.open((base or ".") .. "/" .. path, "rb")
      if not f then return nil end
      local s = f:read("*a")
      f:close()
      return s
    end)
  end
end

--- Compares the sealed digests with the product's files. `reader` is a function(path) -> bytes or
-- nil, or a directory (plain Lua); default: the resource's own files. `digests` defaults to the
-- ones sealed with the last :unseal(). Returns "OK" or "MODIFIED" (nil when nothing was sealed
-- with digests); the result goes with the next license check. Never raises.
function Protection:integrity(reader, digests)
  if type(reader) ~= "function" then reader = self:defaultReader(type(reader) == "string" and reader or nil) end
  digests = digests or self.sealedDigests
  if type(digests) ~= "table" or next(digests) == nil then return nil end
  local paths = {}
  for path in pairs(digests) do paths[#paths + 1] = path end
  table.sort(paths)
  local changed = {}
  for _, path in ipairs(paths) do
    local ok, bytes = pcall(reader, path)
    if not ok or type(bytes) ~= "string" then
      changed[#changed + 1] = path .. " (missing)"
    elseif Protection.digest(bytes) ~= normaliseDigest(digests[path]) then
      changed[#changed + 1] = path
    end
  end
  if #changed == 0 then
    self.integrityValue, self.integrityDetailValue = "OK", nil
  else
    self.integrityValue, self.integrityDetailValue = "MODIFIED", Protection.detail(changed)
  end
  return self.integrityValue
end

--- The latest :integrity() result, or nil before any.
function Protection:integrityResult()
  return self.integrityValue
end

--- Fields to add to the next license check's body: integrity and, when modified, integrityDetail.
function Protection:validateFields()
  local fields = {}
  if self.integrityValue then
    fields.integrity = self.integrityValue
    if self.integrityDetailValue then fields.integrityDetail = self.integrityDetailValue end
  end
  return fields
end

--- One line for the start-up log: product, owner, masked license key and terms link. Never
-- contains a full key or the buyer's name.
function Protection:notice()
  local b = (self.productName or "This product") .. " is licensed software"
  if self.owner then b = b .. " by " .. self.owner end
  b = b .. ". License " .. Protection.mask(self.licenseKey) .. "."
  if self.terms then b = b .. " Terms: " .. self.terms end
  return b
end

local function segment(s)
  return (tostring(s):gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end))
end

--- Downloads a protected file uploaded to the product (Standard plan). SunLicense sends it only
-- while the license is valid. `callback(data, err, status)`: data is nil when refused (err says
-- why, status is the HTTP status: 401/403 refused, 404 no such file, 402 plan without protected
-- files; 0 = SunLicense unreachable). Under luasocket the same three values are also returned.
function Protection:protectedFile(name, callback)
  local function finish(data, err, status)
    if callback then pcall(callback, data, err, status) end
    return data, err, status
  end
  if not self.productCode then return finish(nil, "set productCode to download protected files", 0) end
  if not self.licenseKey then return finish(nil, "no license key", 401) end
  local url = self.baseUrl .. "/api/v2/protected-files/" .. segment(self.productCode) .. "/" .. segment(name)
  local headers = { ["User-Agent"] = "sunlicense-lua/" .. SunLicense.VERSION, ["X-License-Key"] = self.licenseKey }
  if self.apiKey then headers["Authorization"] = "Bearer " .. self.apiKey end
  if self.fingerprint then headers["X-Fingerprint"] = self.fingerprint end
  local result
  local function answer(status, body)
    status = tonumber(status) or 0
    if status == 200 then
      result = { finish(body or "", nil, 200) }
      return
    end
    if status <= 0 or status >= 500 or status == 429 then
      result = { finish(nil, "SunLicense returned HTTP " .. status .. " for protected file " .. name, status) }
      return
    end
    local parsed = SunLicense.jsonDecode(body or "")
    local code = type(parsed) == "table" and (parsed.code or parsed.detail) or nil
    result = { finish(nil, "SunLicense refused protected file " .. name .. " (HTTP " .. status
      .. (type(code) == "string" and ", " .. code or "") .. ")", status) }
  end
  local ok = pcall(self._get or Protection.get, self.env, url, headers, answer)
  if not ok and not result then answer(0, nil) end
  if result then return result[1], result[2], result[3] end
end

--- GETs with whatever HTTP the environment has; `answer(status, body)`.
function Protection.get(env, url, headers, answer)
  if env == "fivem" then
    _G.PerformHttpRequest(url, function(status, body) answer(status, body) end, "GET", "", headers)
  elseif env == "gmod" then
    _G.HTTP({ url = url, method = "GET", headers = headers,
      success = function(status, body) answer(status, body) end, failed = function() answer(0) end })
  elseif env == "luasocket" then
    local http, ltn12 = require("socket.http"), require("ltn12")
    local chunks = {}
    http.TIMEOUT = 15
    local _, status = http.request({ url = url, method = "GET", headers = headers, sink = ltn12.sink.table(chunks) })
    answer(type(status) == "number" and status or 0, table.concat(chunks))
  else
    answer(0)
  end
end

-- The unlock cache: one file per license key, AES-GCM under a key bound to the license key, the
-- machine id and this machine. The same format as the other SunLicense SDKs ("SLC1.").

--- Where cache files go: FiveM resource files, Garry's Mod data/, plain files under cacheDirectory.
function Protection:storage()
  if self._storage then return self._storage end
  local env, dir, dataName = self.env, self.cacheDirectory, self.dataName
  if env == "fivem" then
    return {
      read = function(name) return _G.LoadResourceFile(_G.GetCurrentResourceName(), name) end,
      write = function(name, data) _G.SaveResourceFile(_G.GetCurrentResourceName(), name, data, -1) end,
      delete = function(name) _G.SaveResourceFile(_G.GetCurrentResourceName(), name, "", 0) end,
    }
  elseif env == "gmod" then
    return {
      read = function(name) return _G.file.Read(dataName .. "/" .. name:sub(2) .. ".txt", "DATA") end,
      write = function(name, data) _G.file.CreateDir(dataName) _G.file.Write(dataName .. "/" .. name:sub(2) .. ".txt", data) end,
      delete = function(name) _G.file.Delete(dataName .. "/" .. name:sub(2) .. ".txt") end,
    }
  end
  if dir == false then return { read = function() return nil end, write = function() end, delete = function() end } end
  return {
    read = function(name)
      local f = io.open(dir .. "/" .. name, "rb")
      if not f then return nil end
      local s = f:read("*a")
      f:close()
      return s
    end,
    write = function(name, data)
      local tmp = dir .. "/" .. name .. ".tmp"
      local f = assert(io.open(tmp, "wb"))
      f:write(data)
      f:close()
      if not os.rename(tmp, dir .. "/" .. name) then
        os.remove(dir .. "/" .. name)
        os.rename(tmp, dir .. "/" .. name)
      end
    end,
    delete = function(name) os.remove(dir .. "/" .. name) end,
  }
end

function Protection:cacheFile()
  if not self.licenseKey then return nil end
  return CACHE_FILE .. Protection.digest("sunlicense-unlock-file\0" .. self.licenseKey):sub(1, 16)
end

function Protection:cacheKey()
  return Crypto.sha256("sunlicense-unlock-cache\0" .. self.licenseKey .. "\0" .. (self.fingerprint or "")
    .. "\0" .. tostring(self._machine()))
end

function Protection:writeCache(key)
  local name = self:cacheFile()
  if not name then return end
  local plain = string.format("%d", self._now() * 1000) .. "\n" .. Crypto.toBase64(key)
  local nonce = randomBytes(12)
  local ct, tag = Crypto.gcmEncrypt(self:cacheKey(), nonce, plain)
  self:storage().write(name, CACHE_PREFIX .. Crypto.toBase64(nonce .. ct .. tag, true))
end

function Protection:readCache()
  local name = self:cacheFile()
  if not name then return nil end
  local text = trim(try(self:storage().read, name))
  if not text or text:sub(1, #CACHE_PREFIX) ~= CACHE_PREFIX then return nil end
  local raw = Crypto.fromBase64(text:sub(#CACHE_PREFIX + 1))
  if not raw or #raw < 28 then return nil end
  local plain = Crypto.gcmDecrypt(self:cacheKey(), raw:sub(1, 12), raw:sub(13, #raw - 16), raw:sub(#raw - 15))
  if not plain then return nil end -- another machine, another license key, or a damaged file
  local millis, b64 = plain:match("^(%d+)\n(.+)$")
  if not millis then return nil end
  local saved, t = tonumber(millis) / 1000, self._now()
  if saved > t + SKEW or t >= saved + Protection.CACHE_TTL then return nil end -- too old, or the clock went back
  local key = Crypto.fromBase64(b64)
  if not key or (#key ~= 16 and #key ~= 24 and #key ~= 32) then return nil end
  return key
end

function Protection:key()
  if self.unlock then return self.unlock end
  local ok, key = pcall(self.readCache, self)
  if ok and key then self.unlock = key end
  return self.unlock
end

return SunLicense
