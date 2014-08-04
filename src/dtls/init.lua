local dtls = require 'dtls.core'
local socket = require 'socket'

local M = {}

-- initialize dtls.core module
dtls.init()

-- secure receivefrom function
local function dtlsreceivefrom(udp,size)
  local data, ip, port, msg = udp:oreceivefrom()
  if data and ip and port then
    udp.dtls.data[ip..'_'..port] = ''
    udp.dtls.ctx:handle(ip,port,data)
    data = udp.dtls.data[ip..'_'..port]
  end
  return data, ip, port, msg
end

-- secure sendto function (do handshake automatically at first send)
local function dtlssendto(udp, datagram, ip, port)
  if not udp.dtls.connected then
    udp.dtls.ctx:connect(ip, port)
    repeat
      local data, ip, port, msg = udp:oreceivefrom()
      if data then
        udp.dtls.ctx:handle(ip,port,data)
      end
    until udp.dtls.connected
  end

  udp.dtls.ctx:write(ip,port,datagram);
end

-- secure close function
local function dtlsclose(udp)
  -- free dtls context
  udp.dtls.ctx:free()
  
  -- close udp socket
  udp:oclose()
  
  -- clean metatable
  local m = getmetatable(udp)
  m.additionaldata[udp] = nil
end

-- make an UDP socket (from luasocket) secure through DTLS 
function M.wrap(udp, security)
  -- wrap metatable
  local m = getmetatable(udp)

  -- add a map to store additional data
  if not m.additionaldata then
    m.additionaldata = {}

    -- wrap meta-table to be able to access easily to additional data
    m.o__index = m.__index;
    m.__index = function(t, key)
      local v = m.o__index[key]
      if v then return v end
      return m.additionaldata[udp][key];
    end
    m.__newindex = function(t, key, value)
      m.additionaldata[udp][key] = value
    end
  else
    if type(m.additionaldata) ~= "table" then return nil, "unable to wrap this udp object, unexpected metatable field." end
  end
  m.additionaldata[udp] = {}

  -- store old function
  udp.osendto = udp.sendto
  udp.oreceivefrom = udp.receivefrom
  udp.oclose = udp.close

  --create DTLS context
  local function cbsend(data,host,port)
    return udp:osendto(data,host,port)
  end
  local function cbreceive(data,host,port)
    if udp.dtls.connected and data and host and port then
      udp.dtls.data[host..'_'..port] = udp.dtls.data[host..'_'..port] .. data
    end
  end
  local function cbevent(event)
    if event == "connected" then udp.dtls.connected = true end
  end
  local ctx = dtls.newcontext(cbsend, cbreceive, cbevent, security)
  udp.dtls= {}
  udp.dtls.ctx = ctx;
  udp.dtls.data = {};

  -- wrap method
  m.o__index.sendto = dtlssendto
  m.o__index.receivefrom = dtlsreceivefrom
  m.o__index.close = dtlsclose
end


-- utility function to convert hexadecimal string to binary string
function M.hex2bin(str)
  return (str:gsub('..', function (cc)
    return string.char(tonumber(cc, 16))
  end))
end

return M