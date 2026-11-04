-- Tests for core unlock, integrity, the notice and protected files: the shared test vectors
-- (test/fixtures/protection-test-vectors.json, a copy of SunLicense's) and the cache rules.
-- Run from the repository root: lua test/test_protection.lua

package.path = "./?.lua;" .. package.path

local passed = 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if not ok then
    io.stderr:write("FAIL " .. name .. ": " .. tostring(err) .. "\n")
    os.exit(1)
  end
  passed = passed + 1
end

local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end

local SunLicense = dofile("sunlicense.lua")
local C, P = SunLicense.Crypto, SunLicense.Protection
local f = assert(io.open("test/fixtures/protection-test-vectors.json", "rb"))
local V = assert(SunLicense.jsonDecode(f:read("*a")), "vectors parse")
f:close()

-- In-memory storage and a clock, so the cache rules can be tested.
local function memory()
  local files = {}
  return files, {
    read = function(name) return files[name] end,
    write = function(name, data) files[name] = data end,
    delete = function(name) files[name] = nil end,
  }
end

local KEY = "AX8P-QW3E-RT5Y-ZZ12"

local function newProtection(o)
  o = o or {}
  local files, storage = o.files and o.files[1], o.files and o.files[2]
  if not storage then files, storage = memory() end
  local clock = o.clock or { t = 1762000000 }
  local p = P.new({ licenseKey = o.licenseKey or KEY, fingerprint = o.fingerprint or "machine-1",
    product = o.product, owner = o.owner, terms = o.terms, productCode = o.productCode, apiKey = o.apiKey,
    baseUrl = "https://api.example.test", environment = "none",
    _storage = storage, _now = function() return clock.t end, _machine = function() return o.machine or "host-a" end,
    _get = o.get })
  return p, files, storage, clock
end

test("HKDF matches RFC 5869 test case 1", function()
  local t = V.rfc5869TestCase1
  assert(C.hex(C.hkdf(unhex(t.ikmHex), unhex(t.saltHex), unhex(t.infoHex), t.length)) == t.okmHex)
end)

test("product keys derive like the server's", function()
  for _, k in ipairs(V.productKeys) do
    local key = C.hkdf(unhex(k.orgSecretHex), k.saltAscii, k.infoAscii, 32)
    assert(C.hex(key) == k.productKeyHex, k.name)
    assert(C.toBase64(key) == k.productKeyBase64, k.name)
  end
end)

test("every sealed vector opens to its data and digests", function()
  for _, v in ipairs(V.sealed) do
    local data, digests = P.open(v.sealed, C.fromBase64(v.productKeyBase64))
    assert(data, v.name .. ": " .. tostring(digests))
    assert(data == C.fromBase64(v.dataBase64), v.name .. " data")
    local n = 0
    for path, d in pairs(v.digests) do
      assert(digests[path] == d, v.name .. " digest " .. path)
      n = n + 1
    end
    for _ in pairs(digests) do n = n - 1 end
    assert(n == 0, v.name .. " digest count")
    -- the plaintext is the documented JSON, byte for byte
    local raw = C.fromBase64(v.sealed:sub(6))
    assert(raw:sub(1, 12) == unhex(v.nonceHex), v.name .. " nonce")
    local plain = C.gcmDecrypt(C.fromBase64(v.productKeyBase64), raw:sub(1, 12), raw:sub(13, #raw - 16), raw:sub(#raw - 15), "SLS1")
    assert(plain == v.plaintextUtf8, v.name .. " plaintext")
  end
end)

test("sealing here opens on the server's terms (same bytes for the same nonce)", function()
  for _, v in ipairs(V.sealed) do
    local ct, tag = C.gcmEncrypt(C.fromBase64(v.productKeyBase64), unhex(v.nonceHex), v.plaintextUtf8, "SLS1")
    assert("SLS1." .. C.toBase64(unhex(v.nonceHex) .. ct .. tag, true) == v.sealed, v.name)
  end
end)

test("padded base64url sealed text opens too", function()
  local v = V.sealed[1]
  local padded = v.sealed .. string.rep("=", (4 - (#v.sealed - 5) % 4) % 4)
  assert(P.open(padded, C.fromBase64(v.productKeyBase64)))
end)

test("must-fail vectors fail", function()
  for _, v in ipairs(V.mustFail) do
    local data, err = P.open(v.sealed, C.fromBase64(v.productKeyBase64))
    assert(data == nil and type(err) == "string", v.name)
  end
end)

test("digests", function()
  for _, d in ipairs(V.digests) do
    if d.inputUtf8 then assert(P.digest(d.inputUtf8) == d.sha256Hex, d.name) end
    if d.inputBase64 then assert(P.digest(C.fromBase64(d.inputBase64)) == d.sha256Hex, d.name) end
    if d.input then assert(P.normaliseDigest(d.input) == d.normalised, d.name) end
  end
end)

test("locked until a valid answer with unlock; then unseal works and remembers digests", function()
  local p = newProtection()
  assert(not p:unlocked())
  local data, err = p:unseal(V.sealed[1].sealed)
  assert(data == nil and err:find("locked"), "locked")
  local compat = SunLicense.encode({ valid = true, status = 200, code = "VALID", unlock = V.wire.compatResponseV2.unlock })
  p:accept(compat)
  assert(p:unlocked())
  local core, digests = p:unseal(V.sealed[1].sealed)
  assert(core == C.fromBase64(V.sealed[1].dataBase64))
  assert(digests["plugin.jar"] == V.sealed[1].digests["plugin.jar"])
  assert(p:digests()["plugin.jar"])
end)

test("v1 answers carry unlock too", function()
  local p = newProtection()
  p:accept('{"valid":true,"code":"VALID","detail":"License is valid","expiresAt":null,"machines":{"used":1,"max":3},"unlock":"'
    .. V.wire.validateResponseV1.unlock .. '"}')
  assert(p:unlocked())
end)

test("a valid answer without unlock keeps what it had; unreadable answers change nothing", function()
  local p = newProtection()
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  p:accept('{"valid":true,"code":"VALID"}')
  p:accept("<html>502</html>")
  p:accept('{"status":401}')
  assert(p:unlocked())
end)

test("a refused check forgets the unlock, in memory and on disk", function()
  local p, files = newProtection()
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  assert(next(files), "cached")
  p:accept('{"valid":false,"status":403,"code":"SUSPENDED"}')
  assert(not p:unlocked())
  assert(next(files) == nil, "cache deleted")
  assert(p:unseal(V.sealed[1].sealed) == nil)
end)

test("the cache unlocks for 7 days on this machine with this key, and nowhere else", function()
  local files = { memory() }
  local clock = { t = 1762000000 }
  local p = newProtection({ files = files, clock = clock })
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  local name, text = next(files[1])
  assert(name:match("^%.sunlicense%-unlock%-%x+$") and #name == 19 + 16, name)
  assert(text:sub(1, 5) == "SLC1.", "cache format")
  assert(not text:find(V.wire.compatResponseV2.unlock, 1, true), "the key isn't stored in the clear")

  local again = newProtection({ files = files, clock = clock })
  assert(again:unlocked(), "same machine, same key")
  assert(not newProtection({ files = files, clock = clock, machine = "host-b" }):unlocked(), "another machine")
  assert(not newProtection({ files = files, clock = clock, fingerprint = "machine-2" }):unlocked(), "another machine id")
  assert(not newProtection({ files = files, clock = clock, licenseKey = "OTHR-XXXX" }):unlocked(), "another key")

  clock.t = 1762000000 + 7 * 24 * 3600 - 60
  assert(newProtection({ files = files, clock = clock }):unlocked(), "6 days 23:59")
  clock.t = 1762000000 + 7 * 24 * 3600
  assert(not newProtection({ files = files, clock = clock }):unlocked(), "7 days")
  clock.t = 1762000000 - 3600
  assert(not newProtection({ files = files, clock = clock }):unlocked(), "clock turned back")
end)

test("a damaged cache file is ignored", function()
  local files = { memory() }
  local p = newProtection({ files = files })
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  local name, text = next(files[1])
  files[1][name] = text:sub(1, -3) .. (text:sub(-2, -2) == "A" and "B" or "A") .. text:sub(-1)
  assert(not newProtection({ files = files }):unlocked())
end)

test("a new license key drops the unlock in memory", function()
  local p = newProtection()
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  p:license("NEWK-XXXX-XXXX-XXXX", "machine-1")
  assert(not p:unlocked())
end)

test("integrity: OK, MODIFIED with the changed files, sent with the next check", function()
  local p = newProtection()
  p:accept({ valid = true, unlock = V.wire.compatResponseV2.unlock })
  assert(p:integrity(function() return "x" end) == nil, "nothing unsealed yet: nothing to check")
  local v = V.sealed[3]
  local files = { ["Main.class"] = "main", ["assets/rules.dat"] = "rules", ["lib/util.jar"] = "util" }
  local reader = function(path) return files[path] end
  assert(p:unseal(v.sealed))
  assert(p:integrity(reader) == "OK")
  assert(p:validateFields().integrity == "OK" and p:validateFields().integrityDetail == nil)
  files["lib/util.jar"] = "patched"
  files["Main.class"] = nil
  assert(p:integrity(reader) == "MODIFIED")
  assert(p:integrityResult() == "MODIFIED")
  assert(p:validateFields().integrityDetail == "2 changed: Main.class (missing), lib/util.jar", p:validateFields().integrityDetail)
end)

test("integrity detail stays within 200 characters", function()
  local changed = {}
  for i = 1, 40 do changed[i] = string.format("lib/some-long-library-name-%02d.jar", i) end
  local d = P.detail(changed)
  assert(#d <= 200, #d)
  assert(d:match("^40 changed: ") and d:match(", %+%d+ more$"), d)
end)

test("integrity over files in a directory (plain Lua)", function()
  local dir = os.tmpname()
  os.remove(dir)
  assert(os.execute("mkdir -p " .. dir .. "/lib"))
  local function put(path, s) local h = io.open(dir .. "/" .. path, "wb") h:write(s) h:close() end
  put("Main.class", "main") put("lib/util.jar", "util")
  local digests = { ["Main.class"] = P.digest("main"), ["lib/util.jar"] = "SHA256:" .. P.digest("util"):upper() }
  local p = newProtection()
  assert(p:integrity(dir, digests) == "OK")
  put("Main.class", "evil")
  assert(p:integrity(dir, digests) == "MODIFIED")
  os.execute("rm -rf " .. dir)
end)

test("notice: product, owner, masked key, terms; never the full key", function()
  local p = newProtection({ product = "My Script", owner = "Example Studio", terms = "https://example.com/terms" })
  assert(p:notice() == "My Script is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://example.com/terms",
    p:notice())
  assert(not p:notice():find(KEY, 1, true))
  assert(newProtection():notice() == "This product is licensed software. License AX8P-XXXX-XXXX-XXXX.")
  assert(P.mask(nil) == "(none)")
  assert(P.mask("ABCDEFGHIJ") == "ABCDXXXXXX")
end)

test("protected files: API key, license and machine headers; refusals say why", function()
  local seen
  local status, body = 200, "RULES"
  local get = function(_, url, headers, answer) seen = { url = url, headers = headers } answer(status, body) end
  local p = newProtection({ productCode = "my script", apiKey = "sk_test", get = get })
  local data, err, code = p:protectedFile("rules.dat")
  assert(data == "RULES" and err == nil and code == 200)
  assert(seen.url == "https://api.example.test/api/v2/protected-files/my%20script/rules.dat", seen.url)
  assert(seen.headers.Authorization == "Bearer sk_test" and seen.headers.license == KEY and seen.headers.fingerprint == "machine-1")
  status, body = 403, '{"code":"SUSPENDED"}'
  local got
  data, err, code = p:protectedFile("rules.dat", function(...) got = { ... } end)
  assert(data == nil and code == 403 and err:find("SUSPENDED"), tostring(err))
  assert(got[3] == 403)
  status = 503
  data, err, code = p:protectedFile("rules.dat")
  assert(data == nil and code == 503)
  assert(select(3, newProtection({ get = get }):protectedFile("x")) == 0, "no productCode")
end)

test("client:validate sends integrity and keeps or forgets the unlock (FiveM)", function()
  local answers, sent = {}, {}
  _G.PerformHttpRequest = function(url, cb, method, data, headers)
    sent[#sent + 1] = data
    local a = table.remove(answers, 1)
    cb(a[1], a[2], {})
  end
  local client = SunLicense.new({ baseUrl = "https://api.example.test", token = "sk_test" })
  local files, storage = memory()
  local p = client:protection({ product = "My Script", _storage = storage, _machine = function() return "host-a" end })
  assert(p.apiKey == "sk_test" and p.baseUrl == "https://api.example.test")
  answers[1] = { 200, '{"valid":true,"status":200,"code":"VALID","unlock":"' .. V.wire.compatResponseV2.unlock .. '"}' }
  local okSeen
  client:validate(KEY, { fingerprint = "machine-1" }, function(ok) okSeen = ok end)
  assert(okSeen == true and p:unlocked() and p.licenseKey == KEY and p.fingerprint == "machine-1")
  assert(not sent[1]:find("integrity"), "no integrity before a check")
  local v = V.sealed[1]
  assert(p:unseal(v.sealed))
  assert(p:integrity(function() return "not the jar" end) == "MODIFIED")
  answers[1] = { 403, '{"valid":false,"status":403,"code":"SUSPENDED"}' }
  client:validate(KEY, { fingerprint = "machine-1" }, function(ok) okSeen = ok end)
  assert(okSeen == false)
  assert(sent[2]:find('"integrity":"MODIFIED"') and sent[2]:find('"integrityDetail":"1 changed: plugin.jar"'), sent[2])
  assert(not p:unlocked() and next(files) == nil)
  _G.PerformHttpRequest = nil
end)

test("crypto agrees with every bit-operation fallback (LuaJIT bit, plain 5.1)", function()
  if not math.type then return end
  for _, shim in ipairs({ "bit", "none" }) do
    local saved, savedBit = math.type, rawget(_G, "bit")
    if shim == "bit" then
      local function s(x) x = x & 0xffffffff if x >= 0x80000000 then return x - 0x100000000 end return x end
      _G.bit = { band = function(a, b) return s(a & b) end, bor = function(a, b) return s(a | b) end,
        bxor = function(a, b) return s(a ~ b) end, lshift = function(a, n) return s(a << n) end,
        rshift = function(a, n) return s((a & 0xffffffff) >> n) end }
    end
    math.type = nil
    local ok, S2 = pcall(dofile, "sunlicense.lua")
    math.type, _G.bit = saved, savedBit
    assert(ok, S2)
    for _, v in ipairs(V.sealed) do
      local data = S2.Protection.open(v.sealed, S2.Crypto.fromBase64(v.productKeyBase64))
      assert(data == C.fromBase64(v.dataBase64), shim .. " " .. v.name)
    end
    assert(S2.Protection.open(V.mustFail[3].sealed, C.fromBase64(V.mustFail[3].productKeyBase64)) == nil, shim)
  end
end)

print(("protection: %d tests passed (%s)"):format(passed, _VERSION))
