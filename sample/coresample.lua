local dtlscore = require 'dtls.core'
local socket = require 'socket'

-- create UDP socket
local udp = socket.udp();
udp:setsockname('*', 5683)

-- initialize  DTLS core library
dtlscore.init()

-- declare call back
local function send (data,host,port)
  print("send encrypted data",data, host, port)
  return udp:sendto(data,host,port)
end
local function receive (data,host,port)
  print ("receive clear data ",data, host, port)
end
local function event (data,host,port)
  print ("connected")
end

-- define security config
local securityconfig = {security = "PSK", identity = "Client_identity", key = "secretPSK"}

-- create new DTLS context 
local ctx = dtlscore.newcontext(send, receive,event, securityconfig) 

-- connect and communicate
ctx:connect("127.0.0.1", 5684)
repeat
  local data, host, port, msg = udp:receivefrom()
  if data then
    ctx:handle(host,port,data)
  end
until false

ctx:write("127.0.0.1",5684,"my clear data");

-- free the DTLS context
ctx:free()
udp:close()