/*
 MIT License (MIT)

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

#include "lua5.1/lua.h"
#include "lua5.1/lauxlib.h"
#include "lua5.1/lualib.h"

#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>

#include "tinydtls.h"
#include "global.h"
#include "debug.h"
#include "dtls.h"

void stackdump_g(lua_State* l) {
	int i;
	int top = lua_gettop(l);

	printf(" ============== >total in stack %d\n", top);

	for (i = 1; i <= top; i++) { /* repeat for each level */
		int t = lua_type(l, i);
		switch (t) {
		case LUA_TSTRING: /* strings */
			printf("string: '%s'\n", lua_tostring(l, i));
			break;
		case LUA_TBOOLEAN: /* booleans */
			printf("boolean %s\n", lua_toboolean(l, i) ? "true" : "false");
			break;
		case LUA_TNUMBER: /* numbers */
			printf("number: %g\n", lua_tonumber(l, i));
			break;
		default: /* other values */
			printf("%s\n", lua_typename(l, t));
			break;
		}
		printf("  "); /* put a separator */
	}
	printf("\n"); /* end the listing */
}

typedef struct ldtls_ctxuserdata {
	lua_State * L;
	dtls_context_t * ctx;
	int sendCallbackRef;
	int receiveCallbackRef;
	int eventCallbackRef;
	int securiryTableRef;
	dtls_handler_t cb;
#ifdef DTLS_PSK
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
	dtls_psk_key_t pskkey;
	unsigned char psk_id[PSK_ID_MAXLEN];
	unsigned char psk_key[PSK_MAXLEN];
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
#define ECC_MAXLEN 128
	dtls_ecdsa_key_t ecdsakey;
	unsigned char priv_key[ECC_MAXLEN]; /** < private key as bytes > */
	unsigned char pub_key_x[ECC_MAXLEN]; /** < x part of the public key for the given private key > */
	unsigned char pub_key_y[ECC_MAXLEN]; /** < y part of the public key for the given private key > */
#endif /* DTLS_ECC */
} ldtls_ctxuserdata;

static ldtls_ctxuserdata * checklctx(lua_State * L, const char * functionname) {
	ldtls_ctxuserdata* ctxud = (ldtls_ctxuserdata*) luaL_checkudata(L, 1,
			"luadtls.ctx");

	if (ctxud->ctx == NULL)
		luaL_error(L,
				"bad argument #1 to '%s' (lua DTLS context object is closed)",
				functionname);

	return ctxud;
}

int getsockaddr(const char * ip, const char * port, session_t *dst) {
	int err;
	struct addrinfo aireq;
	struct addrinfo * aires;

	// Get addrinfo.
	memset(&aireq, 0, sizeof(aireq));
	aireq.ai_socktype = SOCK_DGRAM;
	aireq.ai_family = AF_UNSPEC;
	err = getaddrinfo(ip, port, &aireq, &aires);
	if (err)
		return err;

	// copy it in sockaddr struct
	memcpy(&dst->addr.sa, aires->ai_addr, aires->ai_addrlen);
	dst->size = aires->ai_addrlen;
	return 0;
}

int getip(session_t *dst, char * ip, char * portstr) {
	int err;
	// Get IP/port.
	err = getnameinfo(&dst->addr.sa, dst->size, ip, INET6_ADDRSTRLEN, portstr,
			6,
			NI_NUMERICHOST | NI_NUMERICSERV);
	return err;
}

int read_from_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data,
		size_t len) {
	// Get lua context userdata.
	ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ldu->L;

	// Get host and port
	char addrstr[INET6_ADDRSTRLEN];
	char portstr[6];
	int err = getip(session, addrstr, portstr);
	if (err)
		luaL_error(L, "Unable to get host/port for receive callback : %s",
				gai_strerror(err));

	// Call receive callback
	lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->receiveCallbackRef); // stack: ..., function
	lua_pushlstring(L, data, len); // stack: ..., function, data
	lua_pushstring(L, addrstr); // stack: ..., function, data, ip
	lua_pushnumber(L, (int) strtol(portstr, (char **) NULL, 10)); // stack: ..., function, data, ip, port
	lua_call(L, 3, 2); // stack: ..., ret1, ret2

	// Manage error
	if (lua_isnil(L,-2) && lua_isstring(L, -1)) {
		char * err = lua_tostring(L, -1);
		luaL_error(L, "Receive callback failed with error: %s", err);
	}

	lua_pop(L, 2); // clean the stack

	return 0;
}

int send_to_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data,
		size_t len) {
	// Get lua context userdata.
	ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ldu->L;

	// Get host and port
	char addrstr[INET6_ADDRSTRLEN];
	char portstr[6];
	int err = getip(session, addrstr, portstr);
	if (err)
		luaL_error(L, "Unable to get host/port for send callback : %s",
				gai_strerror(err));

	// Call send callback
	lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->sendCallbackRef); // stack: ..., function
	lua_pushlstring(L, data, len); // stack: ..., function, data
	lua_pushstring(L, addrstr); // stack: ..., function, data, ip
	lua_pushnumber(L, (int) strtol(portstr, (char **) NULL, 10)); // stack: ..., function, data, ip, port
	lua_call(L, 3, 2); // stack: ..., ret1, ret2

	// Manage error
	if (lua_isnil(L,-2) && lua_isstring(L, -1)) {
		char * err = lua_tostring(L, -1);
		luaL_error(L, "Send callback failed with error: %s", err);
		return -1;
	} else {
		lua_pop(L, 2);
		return len;
	}
}

int handle_event(struct dtls_context_t *ctx, session_t *session,
		dtls_alert_level_t level, unsigned short code) {

	// Get lua context userdata.
	ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ldu->L;

	// Get Event
	char * event = NULL;
	if (code == DTLS_EVENT_CONNECTED) {
		event = "connected";
	} else if (code == DTLS_EVENT_CONNECT) {
		event = "connect";
	} else if (code == DTLS_EVENT_RENEGOTIATE) {
		event = "renegotiate";
	} else {
		dtls_emerg("Unsupported/Unexpected event!\n");
	}

	// Call event callback
	lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->eventCallbackRef); // stack: ..., function
	lua_pushstring(L, event); // stack: ..., function, event
	lua_call(L, 1, 2); // stack: ..., ret1, ret2

	// Manage error
	if (lua_isnil(L,-2) && lua_isstring(L, -1)) {
		char * err = lua_tostring(L, -1);
		luaL_error(L, "Event callback failed with error: %s", err);
	}

	lua_pop(L, 2); // clean the stack

	return 0;
}

#ifdef DTLS_PSK
static int psksupported(lua_State *L, ldtls_ctxuserdata * ctxud) {
	// get security table
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctxud->securiryTableRef); //stack :..., securitytable

	// get the security field
	lua_getfield(L, -1, "security"); //stack : ...,securitytable, securityfield
	size_t size;
	const char * securitymode = lua_tolstring(L, -1, &size);

	// check if PSK is supported
	int res = securitymode != NULL && (strcmp(securitymode, "PSK") == 0);

	// clean the stack
	lua_pop(L, 2);
	return res;
}

static int get_psk_key(struct dtls_context_t *ctx, const session_t *session,
		const unsigned char *id, size_t id_len, const dtls_psk_key_t **result) {

	// Get lua context userdata.
	ldtls_ctxuserdata * ctxud = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ctxud->L;

	// get security table
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctxud->securiryTableRef); //stack :..., securitytable

	// get the identify field
	lua_getfield(L, -1, "identity"); //stack :..., securitytable, identityfield
	size_t identity_length;
	const char * identity = lua_tolstring(L, -1, &identity_length);
	if (identity == NULL || identity_length > PSK_ID_MAXLEN) {
		lua_pop(L, 2);
		return -1;
	}

	// get the key field
	lua_getfield(L, -2, "key"); //stack :...,securitytable, identityfield, keyfield
	size_t key_length;
	const char * key = lua_tolstring(L, -1, &key_length);
	if (key == NULL || key_length > PSK_MAXLEN) {
		lua_pop(L, 3);
		return -1;
	}

	// store Key in memory
	memcpy(ctxud->psk_id, identity, identity_length);
	memcpy(ctxud->psk_key, key, key_length);

	ctxud->pskkey.id = ctxud->psk_id;
	ctxud->pskkey.id_length = identity_length;
	ctxud->pskkey.key = ctxud->psk_key;
	ctxud->pskkey.key_length = key_length;

	//clean the stack
	lua_pop(L, 3);
	*result = &ctxud->pskkey;
	return 0;
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int eccsupported(lua_State *L, ldtls_ctxuserdata * ctxud) {
	// get security table
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctxud->securiryTableRef); //stack : ..., securitytable

	// get the security field
	lua_getfield(L, -1, "security"); //stack : ..., securitytable, securityfield
	size_t size;
	const char * securitymode = lua_tolstring(L, -1, &size);

	// check if PSK is supported
	int res = securitymode != NULL && (strcmp(securitymode, "ECC") == 0);

	// clean the stack
	lua_pop(L, 2);
	return res;
}

static int get_ecdsa_key(struct dtls_context_t *ctx, const session_t *session,
		const dtls_ecdsa_key_t **result) {

	// Get lua context userdata.
	ldtls_ctxuserdata * ctxud = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ctxud->L;

	// get security table
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctxud->securiryTableRef); //stack : ..., securitytable

	// get the private key field
	lua_getfield(L, -1, "privatekey"); //stack : ..., securitytable, privatekeyfield
	size_t private_length;
	const char * private = lua_tolstring(L, -1, &private_length);
	if (private == NULL || private_length > ECC_MAXLEN) {
		lua_pop(L, 2);
		return -1;
	}

	// get the x public key field
	lua_getfield(L, -2, "xpublickey"); //stack : ..., securitytable, privatekeyfield, xpublickeyfield
	size_t xpublic_length;
	const char * xpublic = lua_tolstring(L, -1, &xpublic_length);
	if (xpublic == NULL || xpublic_length > ECC_MAXLEN) {
		lua_pop(L, 3);
		return -1;
	}

	// get the x public key field
	lua_getfield(L, -3, "ypublickey"); //stack : ..., securitytable, privatekeyfield, xpublickeyfield, ypublickeyfield
	size_t ypublic_length;
	const char * ypublic = lua_tolstring(L, -1, &ypublic_length);
	if (ypublic == NULL || ypublic_length > ECC_MAXLEN) {
		lua_pop(L, 4);
		return -1;
	}

	// store Key in memory
	memcpy(ctxud->priv_key, private, private_length);
	memcpy(ctxud->pub_key_x, xpublic, xpublic_length);
	memcpy(ctxud->pub_key_y, ypublic, ypublic_length);

	ctxud->ecdsakey.curve = DTLS_ECDH_CURVE_SECP256R1;
	ctxud->ecdsakey.priv_key = ctxud->priv_key;
	ctxud->ecdsakey.pub_key_x = ctxud->pub_key_x;
	ctxud->ecdsakey.pub_key_y = ctxud->pub_key_y;

	//clean the stack
	lua_pop(L, 4);
	*result = &ctxud->ecdsakey;

	return 0;
}

static int verify_ecdsa_key(struct dtls_context_t *ctx,
		const session_t *session, const unsigned char *other_pub_x,
		const unsigned char *other_pub_y, size_t key_size) {
	// TODO Implement it...
	return 0;
}
#endif /* DTLS_ECC */

static int ldtls_init(lua_State *L) {
	dtls_init();
	//dtls_set_log_level(LOG_DEBUG);
	return 0;
}

static int ldtls_newcontext(lua_State *L) {
	// 1st parameter : should be a callback (send).
	luaL_checktype(L, 1, LUA_TFUNCTION);

	// 2nd parameter : should be a callback (receive).
	luaL_checktype(L, 2, LUA_TFUNCTION);

	// 3rd parameter : should be a callback (event).
	luaL_checktype(L, 3, LUA_TFUNCTION);

	// 4th parameter : should be a table (security config).
	luaL_checktype(L, 4, LUA_TTABLE);

	// Create llwm userdata object and set its metatable.
	ldtls_ctxuserdata * ctxud = lua_newuserdata(L, sizeof(ldtls_ctxuserdata)); // stack: sendcallback, receivecallback, eventcallback, securitytable, ctxud
	ctxud->L = L;
	ctxud->sendCallbackRef = LUA_NOREF;
	ctxud->receiveCallbackRef = LUA_NOREF;
	ctxud->eventCallbackRef = LUA_NOREF;
	ctxud->securiryTableRef = LUA_NOREF;
	ctxud->ctx = NULL;
	luaL_getmetatable(L, "luadtls.ctx"); // stack: sendcallback, receivecallback, eventcallback, securitytable, ctxud, metatable
	lua_setmetatable(L, -2); // stack: sendcallback, receivecallback, eventcallback, securitytable, ctxud
	lua_insert(L, 1); // stack: ctxud, sendcallback, receivecallback, eventcallback, securitytable

	// Create DTLS context.
	dtls_context_t * dtls_context = dtls_new_context(ctxud);
	if (!dtls_context) {
		luaL_error(L, "Unable to create context.");
	}

	// Store the callbacks in Lua registry to keep a reference on it.
	int securiryTableRef = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud, sendcallback, receivecallback, eventcallback
	int eventCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud, sendcallback, receivecallback
	int receiveCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud, sendcallback
	int sendCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud

	// Store it in userdata context.
	ctxud->ctx = dtls_context;
	ctxud->sendCallbackRef = sendCallbackref;
	ctxud->receiveCallbackRef = receiveCallbackref;
	ctxud->eventCallbackRef = eventCallbackref;
	ctxud->securiryTableRef = securiryTableRef;

	// initialize the callback handler for this context
	ctxud->cb.write = send_to_peer;
	ctxud->cb.read = read_from_peer;
	ctxud->cb.event = handle_event;

	// Manage security.
#ifdef DTLS_PSK
	if (psksupported(L, ctxud)) {
		ctxud->cb.get_psk_key = get_psk_key;
	} else {
		ctxud->cb.get_psk_key = NULL;
	}
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
	if (eccsupported(L, ctxud)) {
		ctxud->cb.get_ecdsa_key = get_ecdsa_key;
		ctxud->cb.verify_ecdsa_key = verify_ecdsa_key;
	} else {
		ctxud->cb.get_ecdsa_key = NULL;
		ctxud->cb.verify_ecdsa_key = NULL;
	}
#endif  /* DTLS_ECC */

	// set callback for this handler
	dtls_set_handler(dtls_context, &ctxud->cb);

	return 1;
}

static int ldtls_connect(lua_State *L) {
	// Get lua DTLS context object
	ldtls_ctxuserdata* ctxud = checklctx(L, "connect");

	// Get peer address.
	const char * host = luaL_checkstring(L, 2);
	const char * port = luaL_checkstring(L, 3);

	// Find session object.
	session_t dst;
	memset(&dst, 0, sizeof(session_t));
	int err;
	err = getsockaddr(host, port, &dst);
	if (err) {
		luaL_error(L, "Unable to get sockaddr to connect to peer %s:%s : %s",
				host, port, gai_strerror(err));
	}
	// Try to connect.
	int res = dtls_connect(ctxud->ctx, &dst);
	if (res < 0) {
		luaL_error(L, "Unable to connect to peer : %s:%s", host, port);
	}

	return 0;
}

static int ldtls_handle(lua_State *L) {
	// Get lua DTLS context object
	ldtls_ctxuserdata* ctxud = checklctx(L, "handle");

	// Get peer address.
	const char * host = luaL_checkstring(L, 2);
	const char * port = luaL_checkstring(L, 3);

	// Get data buffer.
	size_t length;
	uint8_t * buffer = (uint8_t*) luaL_checklstring(L, 4, &length);

	// Find session object.
	session_t dst;
	memset(&dst, 0, sizeof(session_t));
	int err;
	err = getsockaddr(host, port, &dst);
	if (err) {
		luaL_error(L,
				"Unable to get sockaddr to handle data from peer %s:%s : %s",
				host, port, gai_strerror(err));
	}

	// Handle data
	err = dtls_handle_message(ctxud->ctx, &dst, buffer, length);
	if (err < 0) {
		luaL_error(L, "Unable to handle data from peer : %s:%s", host, port);
	}
	return 0;
}

static int ldtls_write(lua_State *L) {
	// Get lua DTLS context object.
	ldtls_ctxuserdata* ctxud = checklctx(L, "write");

	// Get peer address.
	const char * host = luaL_checkstring(L, 2);
	const char * port = luaL_checkstring(L, 3);

	// Get data buffer.
	size_t length;
	uint8_t * buffer = (uint8_t*) luaL_checklstring(L, 4, &length);

	// Find session object.
	session_t dst;
	memset(&dst, 0, sizeof(session_t));
	int err;
	err = getsockaddr(host, port, &dst);
	if (err) {
		luaL_error(L,
				"Unable to get sockaddr to write data to peer %s:%s : %s",
				host, port, gai_strerror(err));
	}

	// Write data
	err = dtls_write(ctxud->ctx, &dst, buffer, length);
	if (err<0){
		luaL_error(L, "Unable to write data to peer : %s:%s", host, port);
	}

	return 0;
}

static int ldtls_free_context(lua_State *L) {
	// Get lua DTLS context object.
	ldtls_ctxuserdata* ctxud = checklctx(L, "c");

	// Free the context.
	dtls_free_context(ctxud->ctx);

	// Release callbacks and tables.
	luaL_unref(L, LUA_REGISTRYINDEX, ctxud->sendCallbackRef);
	ctxud->sendCallbackRef = LUA_NOREF;
	luaL_unref(L, LUA_REGISTRYINDEX, ctxud->receiveCallbackRef);
	ctxud->receiveCallbackRef = LUA_NOREF;
	luaL_unref(L, LUA_REGISTRYINDEX, ctxud->eventCallbackRef);
	ctxud->eventCallbackRef = LUA_NOREF;
	luaL_unref(L, LUA_REGISTRYINDEX, ctxud->securiryTableRef);
	ctxud->securiryTableRef = LUA_NOREF;

	// Free lua DTLS context object
	free(ctxud);

	return 0;
}

static const struct luaL_Reg ldtls_objmeths[] = { { "connect", ldtls_connect },
		{ "handle", ldtls_handle }, { "write", ldtls_write }, { "free",
				ldtls_free_context }, {
		NULL, NULL } };

static const struct luaL_Reg ldtls_modulefuncs[] = { { "init", ldtls_init }, {
		"newcontext", ldtls_newcontext }, {
NULL, NULL } };

int luaopen_dtls_core(lua_State *L) {
	// Define dtls context object metatable.
	luaL_newmetatable(L, "luadtls.ctx"); // stack: metatable

	// Do : metatable.__index = metatable.
	lua_pushvalue(L, -1); // stack: metatable, metatable
	lua_setfield(L, -2, "__index"); // stack: metatable

	// Register llwm object methods : set methods to table on top of the stack
	luaL_register(L, NULL, ldtls_objmeths); // stack: metatable

	// Register module functions.
	luaL_register(L, "dtls.core", ldtls_modulefuncs); // stack: functable
	return 1;
}
