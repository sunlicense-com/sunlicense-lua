-- Tests for built-in product analytics, with stand-ins for FiveM, Garry's Mod and luasocket. No dependencies.
-- Run from the repository root: lua test/test_analytics.lua

package.path = "./?.lua;" .. package.path

-- A minimal JSON decoder (enough for the fixtures and the reports).
local function decode(s)
  local i = 1
  local function ws() i = s:find("[^%s]", i) or #s + 1 end
  local value
  local function str()
    local out = {}
    i = i + 1
    while true do
      local c = s:sub(i, i)
      if c == '"' then i = i + 1 break end
      if c == "\\" then
        local n = s:sub(i + 1, i + 1)
        local map = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f" }
        if n == "u" then
          out[#out + 1] = utf8 and utf8.char(tonumber(s:sub(i + 2, i + 5), 16)) or "?"
          i = i + 6
        else
          out[#out + 1] = map[n] or n
          i = i + 2
        end
      else
        out[#out + 1] = c
        i = i + 1
      end
    end
    return table.concat(out)
  end
  function value()
    ws()
    local c = s:sub(i, i)
    if c == "{" then
      local t = {}
      i = i + 1
      ws()
      if s:sub(i, i) == "}" then i = i + 1 return t end
      while true do
        ws()
        local k = str()
        ws()
        i = i + 1 -- :
        t[k] = value()
        ws()
        local d = s:sub(i, i)
        i = i + 1
        if d == "}" then return t end
      end
    elseif c == "[" then
      local t = { __array = true }
      i = i + 1
      ws()
      if s:sub(i, i) == "]" then i = i + 1 return t end
      while true do
        t[#t + 1] = value()
        ws()
        local d = s:sub(i, i)
        i = i + 1
        if d == "]" then return t end
      end
    elseif c == '"' then
      return str()
    elseif s:sub(i, i + 3) == "true" then i = i + 4 return true
    elseif s:sub(i, i + 4) == "false" then i = i + 5 return false
    elseif s:sub(i, i + 3) == "null" then i = i + 4 return nil
    end
    local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    i = i + #num
    return tonumber(num)
  end
  return value()
end

local function same(a, b, where)
  where = where or "body"
  if type(a) ~= "table" or type(b) ~= "table" then
    assert(a == b, where .. ": expected " .. tostring(b) .. ", got " .. tostring(a))
    return
  end
  for k, v in pairs(b) do if k ~= "__array" then same(a[k], v, where .. "." .. tostring(k)) end end
  for k in pairs(a) do
    if k ~= "__array" then assert(b[k] ~= nil, where .. ": unexpected " .. tostring(k)) end
  end
end

local function read(path)
  local f = assert(io.open(path, "r"))
  local s = f:read("*a")
  f:close()
  return s
end

-- SunLicense's conformance fixtures (spec 185 section 4.8,
-- analytics-service/src/test/resources/conformance/reports.json): copy the file again when it changes.
local fixtures = decode(read("test/fixtures/conformance-reports.json"))

local function reset()
  _G.PerformHttpRequest, _G.HTTP, _G.GetConvar, _G.SetTimeout, _G.timer, _G.system, _G.VERSION = nil
  _G.GetCurrentResourceName, _G.GetResourceMetadata, _G.LoadResourceFile, _G.SaveResourceFile, _G.file = nil
  _G.SUNLICENSE_ANALYTICS = nil
  package.loaded["socket.http"], package.loaded["ltn12"], package.loaded["sunlicense"] = nil, nil, nil
end

local tmp = os.tmpname()
os.remove(tmp)
local function tmpDir()
  local d = tmp .. "-" .. tostring(math.random(1, 1e9))
  os.execute('mkdir -p "' .. d .. '"')
  return d
end

local function noEnv() return nil end

-- A recording transport: answers `status` with Retry-After.
local function recorder(status, retryAfter)
  local seen = {}
  local post = function(env, url, headers, body, answer)
    seen[#seen + 1] = { env = env, url = url, headers = headers, body = decode(body), raw = body }
    answer(status or 204, retryAfter and { ["retry-after"] = retryAfter } or {})
  end
  return post, seen
end

local cases, failed = 0, 0
local function test(name, fn)
  cases = cases + 1
  reset()
  local ok, err = pcall(fn)
  if ok then
    print("ok   " .. name)
  else
    failed = failed + 1
    print("FAIL " .. name .. ": " .. tostring(err))
  end
end

local function make(o)
  local SunLicense = require("sunlicense")
  o._getenv = o._getenv or noEnv
  o.environment = o.environment or "luasocket"
  o.dataDirectory = o.dataDirectory or tmpDir()
  return SunLicense.Analytics.new(o), SunLicense
end

for _, c in ipairs(fixtures.cases) do
  test("conformance: sends the request side of \"" .. c.name .. "\"", function()
    local r = c.report
    local system, productVersion = {}, nil
    for k, v in pairs(r.metrics or {}) do
      if k == "productVersion" then productVersion = v else system[k] = v end
    end
    local dir = tmpDir()
    if r.installId then
      local f = assert(io.open(dir .. "/.sunlicense-install-id", "w"))
      f:write(r.installId)
      f:close()
    end
    local post, seen = recorder(204)
    local a, SunLicense = make({
      baseUrl = "https://api.example.test/", apiKey = c.licensed and "slk_test" or nil,
      licenseKey = r.licenseKey, fingerprint = r.fingerprint, productAnalyticsId = r.productAnalyticsId,
      dataDirectory = dir, productVersion = productVersion,
      _collect = function() return system end, _post = post,
    })
    assert(a:sendNow() == 204, "expected 204")
    local sent = seen[1]
    assert(sent.url == "https://api.example.test/api/v2/analytics/report", "wrong url " .. sent.url)
    local expected = {}
    for k, v in pairs(r) do expected[k] = v end
    expected.schema = 1
    expected.sdk = { name = "lua", version = SunLicense.VERSION }
    same(sent.body, expected)
    assert(sent.headers.Authorization == (c.licensed and "Bearer slk_test" or nil), "Authorization header")
    assert(sent.headers["User-Agent"]:match("^sunlicense%-lua/%d+%.%d+%.%d+ analytics$"), "User-Agent")
  end)
end

test("FiveM: platform and build from the version convar, resource version, install id in the resource", function()
  local saved = {}
  _G.GetConvar = function(name, default)
    if name == "version" then return "FXServer-master SERVER v1.0.0.7290 linux" end
    if name == "gamename" then return "gta5" end
    return default
  end
  _G.GetCurrentResourceName = function() return "my-resource" end
  _G.GetResourceMetadata = function(_, key) return key == "version" and "1.4.0" or nil end
  _G.LoadResourceFile = function(_, name) return saved[name] end
  _G.SaveResourceFile = function(_, name, data) saved[name] = data return true end
  local requests = {}
  _G.PerformHttpRequest = function(url, cb, method, data, headers)
    requests[#requests + 1] = { url = url, method = method, body = decode(data), headers = headers }
    cb(204, "", {})
  end
  local SunLicense = require("sunlicense")
  local a = SunLicense.Analytics.new({ productAnalyticsId = "pa_x", _getenv = noEnv })
  assert(a.env == "fivem", "env " .. tostring(a.env))
  local status
  a:sendNow(function(s) status = s end)
  assert(status == 204, "status " .. tostring(status))
  local m = requests[1].body.metrics
  assert(requests[1].method == "POST")
  assert(m.platform == "fivem" and m.platformVersion == "7290", "platform " .. tostring(m.platform) .. " " .. tostring(m.platformVersion))
  assert(m.os == "Linux" and m.runtime == "lua", "os/runtime")
  assert(m.productVersion == "1.4.0", "productVersion " .. tostring(m.productVersion))
  assert(saved[".sunlicense-install-id"] == requests[1].body.installId, "install id saved in the resource")
end)

test("FiveM: RedM, Windows; the sunlicense_analytics convar switches it off", function()
  local convars = { version = "FXServer-master SERVER v1.0.0.12345 win32", gamename = "rdr3" }
  _G.GetConvar = function(name, default) return convars[name] or default end
  _G.PerformHttpRequest = function() end
  local SunLicense = require("sunlicense")
  local m = SunLicense.Analytics.collect("fivem")
  assert(m.platform == "redm" and m.platformVersion == "12345" and m.os == "Windows", "redm")
  convars.sunlicense_analytics = "false"
  local post, seen = recorder()
  local a = SunLicense.Analytics.new({ productAnalyticsId = "pa_x", _getenv = noEnv, _post = post })
  assert(a:isEnabled() == false, "convar off")
  assert(a:sendNow() == 0 and #seen == 0, "nothing sent")
end)

test("FiveM: start() schedules with SetTimeout, reports, then every 30 minutes", function()
  local timers = {}
  _G.GetConvar = function(_, default) return default end
  _G.GetCurrentResourceName = function() return "r" end
  _G.SetTimeout = function(ms, fn) timers[#timers + 1] = { ms = ms, fn = fn } end
  _G.PerformHttpRequest = function(_, cb) cb(204, "", {}) end
  local SunLicense = require("sunlicense")
  local a = SunLicense.analytics("pa_x", { _getenv = noEnv, _random = function() return 0 end })
  assert(#timers == 1 and timers[1].ms == 60000, "first report after 1 minute")
  timers[1].fn()
  assert(#timers == 2 and timers[2].ms == 30 * 60 * 1000, "then 30 minutes")
  a:close()
  timers[2].fn()
  assert(#timers == 2, "closed: no more reports")
end)

test("Garry's Mod: HTTP{}, platform gmod, install id in data/", function()
  local files = {}
  _G.VERSION = 240313
  _G.system = { IsWindows = function() return false end, IsLinux = function() return true end, IsOSX = function() return false end }
  _G.file = { Read = function(p) return files[p] end, Write = function(p, d) files[p] = d end, CreateDir = function() end }
  local seen = {}
  _G.HTTP = function(req)
    seen[#seen + 1] = { body = decode(req.body), type = req.type, headers = req.headers }
    req.success(429, '{"error":"rate_limited"}', { ["Retry-After"] = "120" })
    return true
  end
  local SunLicense = require("sunlicense")
  local a = SunLicense.Analytics.new({ productAnalyticsId = "pa_x", dataName = "myaddon", _getenv = noEnv })
  local status, retry
  a:sendNow(function(s, r) status, retry = s, r end)
  assert(status == 429 and retry == "120", "status " .. tostring(status))
  assert(SunLicense.Analytics.nextDelay(status, retry) == 120)
  assert(seen[1].type == "application/json")
  local m = seen[1].body.metrics
  assert(m.platform == "gmod" and m.platformVersion == "240313" and m.os == "Linux", "gmod metrics")
  assert(files["myaddon/install-id.txt"] == seen[1].body.installId, "install id in data/")
end)

test("luasocket: a real luasocket-shaped request, synchronous; poll() reports when due", function()
  local posted = {}
  package.loaded["ltn12"] = {
    source = { string = function(s) return s end },
    sink = { table = function(t) return t end },
  }
  package.loaded["socket.http"] = {
    request = function(req)
      posted[#posted + 1] = { url = req.url, body = decode(req.source), headers = req.headers }
      return 1, 204, {}
    end,
  }
  local SunLicense = require("sunlicense")
  local client = SunLicense.new({ baseUrl = "https://api.example.test", token = "slk_x" })
  local a = client:analytics({ licenseKey = "K", fingerprint = "f", dataDirectory = tmpDir(), _getenv = noEnv, _firstDelay = 0 })
  assert(a.env == "luasocket")
  assert(a:poll() == true, "due at once")
  assert(#posted == 1 and posted[1].url == "https://api.example.test/api/v2/analytics/report")
  assert(posted[1].headers.Authorization == "Bearer slk_x")
  assert(posted[1].headers["Content-Length"])
  assert(posted[1].body.licenseKey == "K" and posted[1].body.installId == nil)
  assert(a:poll() == false, "next one in 30 minutes")
  assert(a.nextAt - os.time() >= 1799, "30 minutes")
end)

test("opt-out: product switch, environment, global; nothing is sent", function()
  local optOuts = {
    { enabled = false },
    { enabled = function() return false end },
    { enabled = function() error("config gone") end },
    { _getenv = function(n) return n == "SUNLICENSE_ANALYTICS" and "off" or nil end },
    { _getenv = function(n) return n == "SUNLICENSE_ANALYTICS" and " FALSE " or nil end },
    { _getenv = function(n) return n == "SUNLICENSE_ANALYTICS" and "0" or nil end },
  }
  for i, extra in ipairs(optOuts) do
    local post, seen = recorder()
    extra.productAnalyticsId, extra._post = "pa_x", post
    local a = make(extra)
    assert(a:isEnabled() == false, "case " .. i .. " is off")
    assert(a:sendNow() == 0 and #seen == 0, "case " .. i .. " sent nothing")
  end
  _G.SUNLICENSE_ANALYTICS = false
  local post, seen = recorder()
  assert(make({ productAnalyticsId = "pa_x", _post = post }):sendNow() == 0 and #seen == 0, "global off")
  _G.SUNLICENSE_ANALYTICS = nil
  local on = false
  local a = make({ productAnalyticsId = "pa_x", _post = post, enabled = function() return on end })
  assert(a:sendNow() == 0)
  on = true
  assert(a:sendNow() == 204, "switched back on at runtime")
end)

test("identity: nothing sent without one; licensed needs API key, license key and machine id", function()
  local post, seen = recorder()
  assert(make({ _post = post }):sendNow() == 0)
  assert(make({ apiKey = "slk", fingerprint = "f", _post = post }):sendNow() == 0)
  local key
  local a = make({ apiKey = "slk", fingerprint = "f", licenseKey = function() return key end, _post = post })
  assert(a:sendNow() == 0)
  key = " AX8P-4Q2M "
  assert(a:sendNow() == 204)
  assert(seen[1].body.licenseKey == "AX8P-4Q2M")
end)

test("never raises: a transport that errors, broken suppliers, no HTTP at all", function()
  local a = make({ productAnalyticsId = "pa_x", productVersion = function() error("x") end,
                   _post = function() error("network down") end })
  assert(a:sendNow() == -1, "no answer")
  local b = make({ productAnalyticsId = "pa_x", environment = "none", _post = nil })
  assert(b:sendNow() == -1)
  local SunLicense = require("sunlicense")
  local c = SunLicense.analytics(nil, nil)
  assert(c and c.close, "a reporter even without options")
end)

test("schedule: 1-30 minutes first, Retry-After between 1 minute and 24 hours", function()
  local A = require("sunlicense").Analytics
  assert(A.firstDelay(function() return 0 end) == 60)
  assert(A.firstDelay(function() return 0.9999999 end) == 1800)
  assert(A.nextDelay(204, "86400") == 1800)
  assert(A.nextDelay(-1, nil) == 1800)
  assert(A.nextDelay(429, "120") == 120)
  assert(A.nextDelay(429, "5") == 60)
  assert(A.nextDelay(403, "999999") == 86400)
  assert(A.nextDelay(503, "Wed, 21 Oct 2026 07:28:00 GMT") == 1800)
end)

test("install id: created once, kept, a random v4 UUID", function()
  local dir = tmpDir()
  local post, seen = recorder()
  make({ productAnalyticsId = "pa_x", dataDirectory = dir, _post = post }):sendNow()
  make({ productAnalyticsId = "pa_x", dataDirectory = dir, _post = post }):sendNow()
  local id = read(dir .. "/.sunlicense-install-id")
  assert(id:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89ab]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"), "uuid " .. id)
  assert(seen[1].body.installId == id and seen[2].body.installId == id)
  local other = make({ productAnalyticsId = "pa_x", _post = post })
  other:sendNow()
  assert(seen[3].body.installId ~= id, "another install gets another id")
end)

test("features: counted, sent, kept until stored; nothing counted while off", function()
  local post, seen = recorder(503, "60")
  local a = make({ productAnalyticsId = "pa_x", _post = post })
  a:feature("auto-sell"):feature("Auto-Sell", 2):feature("web-editor")
  a:feature("bad name!"):feature("x", 0):feature("y", 1.5):feature(42)
  assert(a:sendNow() == 503)
  same(seen[1].body.features, { ["auto-sell"] = 3, ["web-editor"] = 1 })
  a:feature("auto-sell")
  a._post = recorder(204)
  local ok, okSeen = recorder(204)
  a._post = ok
  assert(a:sendNow() == 204)
  same(okSeen[1].body.features, { ["auto-sell"] = 4, ["web-editor"] = 1 })
  a:sendNow()
  assert(okSeen[2].body.features == nil, "sent features are gone")
  local off = make({ productAnalyticsId = "pa_x", enabled = false, _post = ok })
  off:feature("auto-sell")
  assert(next(off.features) == nil, "nothing counted while off")
end)

test("features: at most 50 different ones, like the Java SDK; switching off drops the counts", function()
  local post, seen = recorder()
  local a = make({ productAnalyticsId = "pa_x", _post = post })
  for i = 1, 60 do a:feature("f" .. i) end
  a:feature("f1")
  a:sendNow()
  a:sendNow()
  local n1 = 0
  for _ in pairs(seen[1].body.features) do n1 = n1 + 1 end
  assert(n1 == 50 and seen[1].body.features.f1 == 2, "50 features, f1 twice")
  assert(seen[2].body.features == nil, "the other 10 were never counted")
  local on = true
  local b = make({ productAnalyticsId = "pa_x", _post = post, enabled = function() return on end })
  b:feature("auto-sell")
  on = false
  assert(b:sendNow() == 0)
  on = true
  b:sendNow()
  assert(seen[3].body.features == nil, "counts dropped while off")
end)

test("custom charts: every type, the wire shape of spec 185 section 4.6", function()
  local post, seen = recorder()
  local a = make({ productAnalyticsId = "pa_x", _post = post })
  a:simplePie("storage", function() return "mysql" end)
   :advancedPie("modules", function() return { shop = 2, auctions = 1, zero = 0 } end)
   :drilldownPie("java", function() return { ["Java 21"] = { ["21.0.4"] = 1 }, empty = {} } end)
   :singleLine("players", function() return 42 end)
   :multiLine("worlds", function() return { overworld = 30, nether = -2 } end)
   :simpleBar("commands", function() return { sell = 12 } end)
   :advancedBar("tiers", function() return { gold = { 1, 2, 3 }, bad = { 1, "x" } } end)
   :simplePie("nothing", function() return nil end)
   :simplePie("empty", function() return "  " end)
   :singleLine("huge", function() return 2e9 end)
   :simplePie("throws", function() error("x") end)
   :simplePie("Bad Id", function() return "x" end)
   :simplePie("removed", function() return "x" end)
   :removeChart("removed")
  assert(a:sendNow() == 204)
  assert(seen[1].raw:find('"charts":[', 1, true), "charts is a JSON array")
  assert(seen[1].raw:find('"gold":[1,2,3]', 1, true), "advanced_bar values are arrays")
  same(seen[1].body.charts, {
    { id = "storage", type = "simple_pie", data = { value = "mysql" } },
    { id = "modules", type = "advanced_pie", data = { values = { shop = 2, auctions = 1 } } },
    { id = "java", type = "drilldown_pie", data = { values = { ["Java 21"] = { ["21.0.4"] = 1 } } } },
    { id = "players", type = "single_line", data = { value = 42 } },
    { id = "worlds", type = "multi_line", data = { values = { overworld = 30, nether = -2 } } },
    { id = "commands", type = "simple_bar", data = { values = { sell = 12 } } },
    { id = "tiers", type = "advanced_bar", data = { values = { gold = { 1, 2, 3 }, bad = { 1 } } } },
  }, "charts")
end)

test("custom charts: same id replaces, at most 30, and a report over 16 KB keeps the built-ins", function()
  local post, seen = recorder()
  local a = make({ productAnalyticsId = "pa_x", _post = post })
  a:simplePie("storage", function() return "mysql" end):simplePie("STORAGE", function() return "sqlite" end)
  for i = 1, 40 do a:singleLine("c" .. i, function() return i end) end
  a:sendNow()
  assert(#seen[1].body.charts == 30, "30 charts")
  same(seen[1].body.charts[1], { id = "storage", type = "simple_pie", data = { value = "sqlite" } })
  local big = make({ productAnalyticsId = "pa_x", _post = post })
  for i = 1, 30 do
    big:advancedPie("big" .. i, function()
      local t = {}
      for j = 1, 50 do t[string.rep("v", 40) .. j] = j end
      return t
    end)
  end
  big:feature("kept")
  assert(big:sendNow() == 204)
  assert(seen[2].body.charts == nil and seen[2].body.metrics, "charts dropped first")
  same(seen[2].body.features, { kept = 1 }, "features")
  assert(big.features.kept == nil, "sent features are gone")
end)

test("nothing personal in a real report from this machine", function()
  local post, seen = recorder()
  local a = make({ productAnalyticsId = "pa_x", _post = post, _getenv = os.getenv })
  a:sendNow()
  local raw = seen[1].raw
  for _, v in ipairs({ os.getenv("USER"), os.getenv("HOME"), os.getenv("PWD"), os.getenv("HOSTNAME") }) do
    if v and v ~= "" then assert(not raw:find(v, 1, true), "report contains " .. v) end
  end
  assert(seen[1].body.metrics.runtime and seen[1].body.metrics.platform == "standalone")
end)

print(("%d tests, %d failed"):format(cases, failed))
os.exit(failed == 0 and 0 or 1)
