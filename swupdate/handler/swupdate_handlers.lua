--[[
 SWUpdate Lua handler "winbond-secure-flash".
 Thin adapter only: it stores the image stream in a temp file and calls w77q_fwtool, which uses
 QLIB to run the Winbond W77Q secure firmware update. Authentication, digest check and rollback
 protection are done by QLIB/W77Q, nothing is re-implemented here.

 sw-description (image entry):
   { filename = "zephyr.bin"; type = "winbond-secure-flash";
     properties: { manifest = "zephyr.manifest"-content is passed via a second image of type
                   "winbond-secure-flash-manifest" (see below) }
 Properties used:  keyfile (path on target), section (default 4), tool (default /usr/local/bin/w77q_fwtool)
 The manifest (digest/crc/version) is shipped as a "file"-less image of the same handler type with
 properties.role = "manifest"; the firmware image has properties.role = "firmware".
]]
local tmpdir = "/tmp/w77q-swupdate"
local state = {}

local function sh(cmd)
  local p = io.popen(cmd .. " 2>&1")
  local out = p:read("*a")
  local ok, _, code = p:close()
  return code or (ok and 0 or 1), out
end

function w77q_handler(image)
  os.execute("mkdir -p " .. tmpdir)
  local props = image.properties or {}
  local role = props.role or "firmware"
  local dst = tmpdir .. "/" .. role
  local err, msg = image:copy2file(dst)
  if err ~= 0 then
    swupdate.error("winbond-secure-flash: copy2file failed: " .. tostring(msg))
    return 1
  end
  if role == "manifest" then
    state.manifest = dst
    return 0
  end
  state.fw = dst
  if not state.manifest then
    swupdate.error("winbond-secure-flash: manifest image must precede the firmware image in sw-description")
    return 1
  end
  local tool    = props.tool or "/usr/local/bin/w77q_fwtool"
  local keyfile = props.keyfile or "/etc/w77q/full.key"
  local section = props.section or "4"
  local code, out = sh(string.format("%s install %s %s %s %s", tool, keyfile, state.fw, state.manifest, section))
  for line in out:gmatch("[^\n]+") do swupdate.info("w77q_fwtool: " .. line) end
  os.remove(state.fw); os.remove(state.manifest); state = {}
  if code ~= 0 then
    swupdate.error("winbond-secure-flash: update rejected/failed (exit " .. tostring(code) .. ")")
    return 1
  end
  return 0
end

swupdate.register_handler("winbond-secure-flash", w77q_handler, swupdate.HANDLER_MASK.IMAGE_HANDLER)
