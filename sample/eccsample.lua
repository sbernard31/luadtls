local dtls = require 'dtls'
local socket = require 'socket'

-- create UDP socket
local udp = socket.udp();
udp:setsockname('*', 5682)

-- change UDP socket in DTLS socket
dtls.wrap(udp,{
  security = "ECC",
  privatekey = dtls.hex2bin("e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2"),
  xpublickey = dtls.hex2bin("89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5"),
  ypublickey = dtls.hex2bin("cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68")
})
-- to generate your key, you can use openssl command line :
--     openssl ecparam -out ec_key3.pem -name prime256v1 -genkey
-- to show the private and public key : 
--     openssl ec -in ec_key3.pem -text
-- /!\ if first byte of private key is 00 remove it !
-- /!\ the first byte of public key should be 04, remove it too => http://tools.ietf.org/html/rfc5480
-- /!\ the xpoint is the first 32 bytes, the ypoint the 32 last bytes.


-- DTLS handshake in automaticaly do at first sendto
udp:sendto("my clear data","127.0.0.1", 5683)
repeat
  local data, host, port, msg = udp:receivefrom()
  -- receive clear data
  print ("receive clear data",data, host, port)
until false

-- free the DTLS context and close the udp socket
udp:close()
