local dtls = require 'dtls'
local socket = require 'socket'

-- create UDP socket
local udp = socket.udp();
udp:setsockname('*', 5682)

-- change UDP socket in DTLS socket
dtls.wrap(udp, {security = "PSK", identity = "Client_identity", key = "secretPSK"})

-- DTLS handshake in automaticaly do at first sendto
udp:sendto("my clear data","127.0.0.1", 5683)
repeat
  local data, host, port, msg = udp:receivefrom()
  -- receive clear data
  print ("receive clear data",data, host, port)
until false

-- free the DTLS context and close the udp socket
udp:close()
