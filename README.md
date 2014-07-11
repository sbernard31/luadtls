luadtls
=======

**luadtls** is a lua binding for [**tinydtls**](http://tinydtls.sourceforge.net) library .

**luadtls** contains 2 modules :
* `dtls.core` which is a direct binding of dtls.c from tinydtls. see [dtls.c usage](http://tinydtls.sourceforge.net/group__dtls__usage.html).
* `dtls` to easily secure an [UDP socket](http://w3.impa.br/~diego/software/luasocket/udp.html) from [luasocket](http://w3.impa.br/~diego/software/luasocket/) with DTLS.


A `dtls`/`luasocket` sample :
``` lua
local dtls = require 'dtls'
local socket = require 'socket'

-- create UDP socket
local udp = socket.udp();
udp:setsockname('*', 5683)

-- change UDP socket in DTLS socket
dtls.wrap(udp,"PSK") -- ECC is managed too. (key is hard coded for now)

-- DTLS handshake in automaticaly do at first sendto
udp:sendto("my clear data","127.0.0.1", 5684)
repeat
  local data, host, port, msg = udp:receivefrom()
  -- receive clear data
  print ("receive clear data",data, host, port)
until false

```
More samples available in [sample folder](https://github.com/sbernard31/luadtls/tree/master/sample).


Compile & Test
--------------
Get the code : (*`--recursive` is need because of use of git submodule.*)
```
git clone --recursive git@github.com:sbernard31/luadtls.git luadtls
```


Compile it : (*You need cmake and autoconf -_-! ...*)
```
mkdir [builddir]
cd [builddir]
cmake [luadtls source directory]
make
```

Test it : (*Lua 5.1 and luasocket is needed.*)
```
lua sample.lua
```




Limitation
----------
**luadtls** binding is still in development.
For now, it is only compatible with Lua 5.1 and linux.
