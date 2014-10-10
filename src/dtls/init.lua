local dtls = require 'dtls.core'
local socket = require 'socket'

local M = {}

-- initialize dtls.core module
dtls.init()

local function peerid(ip,port)
  return ip..'_'..port;
end

-- secure receivefrom function (do handshake automatically if not already connected)
local function dtlsreceivefrom(udp,size)
  repeat
    local data, ip, port = udp:oreceivefrom()
    
    -- manage timeout
    if not data and ip == "timeout" then
      return data, ip -- return timeout error
    end
    
    if data and ip and port then
      local session = udp.dtls.getsession(udp,ip,port)
      if not session.connected then
        session.connecting = true
        -- handle data to do handshake 
        udp.dtls.ctx:handle(ip,port,data)
      else
        -- send applicative data
        session.data = ''
        udp.dtls.ctx:handle(ip,port,data)
        data = session.data
        return data, ip, port
      end
    end    
  until false
end

-- secure sendto function (do handshake automatically if not already connected)
local function dtlssendto(udp, datagram, ip, port)
  if ip and port then
    local session = udp.dtls.getsession(udp,ip,port)
    
    -- if not connected do handshake
    if not session.connected and not session.connecting then
      udp.dtls.ctx:connect(ip, port)
      repeat
        local data, ip, port, msg = udp:oreceivefrom()
        -- manage timeout
        if not data and ip == "timeout" then
          return data, ip -- return timeout error
        end
        -- handle data
        if data then
          udp.dtls.ctx:handle(ip,port,data)
        end
      until session.connected
    end
    
    -- send applicative data
    udp.dtls.ctx:write(ip,port,datagram);
  end
end

-- secure close function
local function dtlsclose(udp, ip, port)
  if ip and port then
    -- if ip and port is precise,
    -- just close the dtls session for this  peer.
    if udp.dtls and not udp.dtls.ctx:closed(ip, port) then
      udp.dtls.session[peerid(ip,port)] = nil
      udp.dtls.ctx:close(ip, port)
    end
  else
    -- if no parameters,
    -- close the socket.
    
    -- free dtls context
    if udp.dtls then udp.dtls.ctx:free() end 
    
    -- close udp socket
    udp:oclose()
    
    -- clean dtls
    udp.dtls = nil 
    
    -- clean metatable
    local m = getmetatable(udp)
    m.additionaldata[udp] = nil    
  end
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

  --create DTLS node
  udp.dtls= {}
  
  -- create session handling function
  udp.dtls.session = {};
  udp.dtls.getsession = function (udp,host,port)
    local session = udp.dtls.session[peerid(host,port)] 
    if not session then
      session = {}
      udp.dtls.session[peerid(host,port)] = session
    end
    return session
  end
  
  -- create DTLS context
  local function cbsend(data,host,port)
    return udp:osendto(data,host,port)
  end
  local function cbreceive(data,host,port)
    if host and port then 
      local session = udp.dtls.getsession(udp,host,port)
      if session.connected then
        session.data = session.data .. data
      end
    end
  end
  local function cbevent(host, port, event)
    if host and port and event == "connected" then
        local session = udp.dtls.getsession(udp,host,port) 
        session.connected = true
        session.connecting = false
    end
  end
  udp.dtls.ctx = dtls.newcontext(cbsend, cbreceive, cbevent, security) 
  
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