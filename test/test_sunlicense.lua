-- Tests for sunlicense.lua with stand-ins for FiveM, Garry's Mod and luasocket. No dependencies.
-- Run from the repository root: lua test/test_sunlicense.lua

package.path = "./?.lua;" .. package.path

-- A fake SunLicense API. /api/v2/license/validate answers 2xx only for a valid key (the contract
-- every SDK uses); /api/v1/validate answers 200 for every key and says valid:false in the body.
local requests = {}
local function api(url, body, headers)
  local path = url:gsub("^https?://[^/]+", "")
  local license = body:match('"license":"(.-)"')
  requests[#requests + 1] = { path = path, body = body, headers = headers or {}, license = license }
  if path == "/api/v1/validate" then
    return 200, '{"valid":false,"code":"NOT_FOUND"}'
  end
  if path ~= "/api/v2/license/validate" then
    return 404, "not found"
  end
  if (headers or {})["Authorization"] ~= "Bearer good-token" then
    return 401, '{"status":401}'
  end
  if license == "GOOD-KEY" then
    return 200, '{"valid":true,"code":"VALID"}'
  end
  return 400, '{"valid":false,"code":"NOT_FOUND"}'
end

local function reset()
  requests = {}
  _G.PerformHttpRequest, _G.http, _G.HTTP = nil, nil, nil
  package.loaded["socket.http"], package.loaded["ltn12"], package.loaded["sunlicense"] = nil, nil, nil
end

local function fivem()
  _G.PerformHttpRequest = function(url, cb, method, data, headers)
    assert(method == "POST", "FiveM request must be a POST")
    local status, body = api(url, data, headers)
    cb(status, body, {})
  end
end

local function gmod()
  -- Garry's Mod: http.Post can't send headers, so the client must use HTTP{}. Its success
  -- callback runs for every HTTP answer, 4xx included.
  _G.http = { Post = function() error("http.Post can't send the Authorization header") end }
  _G.HTTP = function(req)
    assert(req.method == "POST", "GMod request must be a POST")
    assert(req.type == "application/json", "GMod request must send JSON")
    local status, body = api(req.url, req.body, req.headers)
    req.success(status, body, {})
    return true
  end
end

local function luasocket()
  package.loaded["ltn12"] = {
    source = { string = function(s) return s end },
    sink = { table = function(t) return t end },
  }
  package.loaded["socket.http"] = {
    request = function(req)
      local status, body = api(req.url, req.source, req.headers)
      table.insert(req.sink, body)
      return 1, status
    end,
  }
end

local function check(env, key, token)
  local SunLicense = require("sunlicense")
  local client = SunLicense.new({ baseUrl = "https://api.example.test/", token = token or "good-token" })
  local result
  client:validate(key, { host = "pc-1" }, function(ok, status, body)
    result = { ok = ok, status = status, body = body }
  end)
  assert(result, env .. ": callback was not called")
  return result, requests[#requests]
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

for env, setup in pairs({ fivem = fivem, gmod = gmod, luasocket = luasocket }) do
  test(env .. ": a valid key is accepted", function()
    setup()
    local r, req = check(env, "GOOD-KEY")
    assert(r.ok == true and r.status == 200, "expected ok, got " .. tostring(r.ok) .. " " .. tostring(r.status))
    assert(req.path == "/api/v2/license/validate", "wrong endpoint " .. req.path)
    assert(req.license == "GOOD-KEY", "payload must carry the key as \"license\"")
    assert(req.body:find('"host":"pc-1"', 1, true), "context must be sent")
    assert(req.headers["User-Agent"]:match("^sunlicense%-lua/"), "User-Agent must be sunlicense-lua")
  end)
  test(env .. ": an unknown key is rejected", function()
    setup()
    local r = check(env, "BAD-KEY")
    assert(r.ok == false, "an unknown key was accepted (status " .. tostring(r.status) .. ")")
    assert(r.status == 400, "expected 400, got " .. tostring(r.status))
  end)
  test(env .. ": a wrong API key is rejected", function()
    setup()
    local r = check(env, "GOOD-KEY", "wrong-token")
    assert(r.ok == false and r.status == 401, "expected 401, got " .. tostring(r.ok) .. " " .. tostring(r.status))
  end)
end

print(("%d tests, %d failed"):format(cases, failed))
os.exit(failed == 0 and 0 or 1)
