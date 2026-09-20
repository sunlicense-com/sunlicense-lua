--- Official SunLicense client for Lua.
--
-- Early preview. The client API is being finalised alongside SunLicense 2.0.
--
-- Drop this file into your resource and require it. It detects the host
-- environment and uses whichever HTTP mechanism is available:
--
--   * FiveM        -- PerformHttpRequest (async, callback)
--   * Garry's Mod  -- http.Post / HTTP (async, callback)
--   * Plain Lua    -- luasocket (synchronous), if installed
--
-- Docs: https://docs.sunlicense.hapangama.com
-- @module sunlicense

local SunLicense = {}
SunLicense.__index = SunLicense

--- The version of this client.
SunLicense.VERSION = "0.0.1"

-- ---------------------------------------------------------------------------
-- Environment detection
-- ---------------------------------------------------------------------------

--- Detects which host environment this is running in.
-- @return string one of "fivem", "gmod", "luasocket" or "none"
function SunLicense.environment()
  if type(_G.PerformHttpRequest) == "function" then
    return "fivem"
  end
  if type(_G.http) == "table" and type(_G.http.Post) == "function" then
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

  local payload = { licenseKey = licenseKey }
  for key, value in pairs(context or {}) do
    payload[key] = value
  end

  local url = self.baseUrl .. "/api/v1/validate"
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
    _G.http.Post(url, { json = body }, function(responseBody)
      if callback then callback(true, 200, responseBody) end
    end, function(err)
      if callback then callback(false, 0, err) end
    end)
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

return SunLicense
