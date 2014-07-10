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
	// Get ip port.
	err = getnameinfo(&dst->addr.sa, dst->size, ip,
	INET6_ADDRSTRLEN, portstr, 6, NI_NUMERICHOST | NI_NUMERICSERV);
	return err;
}

int read_from_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data,
		size_t len) {
	// Get lua context userdata.
	ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ldu->L;

	lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->receiveCallbackRef);
	lua_pushlstring(L, data, len);

	char addrstr[INET6_ADDRSTRLEN];
	char portstr[6];
	int res = getip(session, addrstr, portstr);
	if (res)
		dtls_emerg("cannot receive to peer \n");

	//get host and port
	lua_pushstring(L, addrstr);
	lua_pushnumber(L, (int) strtol(portstr, (char **) NULL, 10));
	lua_call(L, 3, 0);
	return 0;
}

int send_to_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data,
		size_t len) {
	// Get lua context userdata.
	ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
	lua_State * L = ldu->L;

	lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->sendCallbackRef);
	lua_pushlstring(L, data, len);

	char addrstr[INET6_ADDRSTRLEN];
	char portstr[6];
	int err = getip(session, addrstr, portstr);
	if (err)
		dtls_emerg( "cannot send to peer \n");

	//get host and port
	lua_pushstring(L, addrstr);
	lua_pushnumber(L, (int) strtol(portstr, (char **) NULL, 10));
	lua_call(L, 3, 1);

	// TODO manage error
	int res = luaL_checkint(L, -1);

	return res;
}

int handle_event(struct dtls_context_t *ctx, session_t *session,
		dtls_alert_level_t level, unsigned short code) {

	if (code == DTLS_EVENT_CONNECTED) {	// Get lua context userdata.
		ldtls_ctxuserdata * ldu = (ldtls_ctxuserdata *) dtls_get_app_data(ctx);
		lua_State * L = ldu->L;

		lua_rawgeti(L, LUA_REGISTRYINDEX, ldu->eventCallbackRef);

		//get host and port
		lua_call(L, 0, 0);
	}
	return 0;
}

#ifdef DTLS_PSK
#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"

/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static unsigned char psk_key[PSK_MAXLEN];

static dtls_psk_key_t psk = { .id = psk_id, .id_length = 0, .key = psk_key,
		.key_length = 0 };

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
static int get_psk_key(struct dtls_context_t *ctx UNUSED_PARAM,
		const session_t *session UNUSED_PARAM,
		const unsigned char *id UNUSED_PARAM, size_t id_len UNUSED_PARAM,
		const dtls_psk_key_t **result) {

	psk.id_length = strlen(PSK_DEFAULT_IDENTITY);
	psk.key_length = strlen(PSK_DEFAULT_KEY);
	memcpy(psk.id, PSK_DEFAULT_IDENTITY, psk.id_length);
	memcpy(psk.key, PSK_DEFAULT_KEY, psk.key_length);

	*result = &psk;
	return 0;
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static const unsigned char ecdsa_priv_key[] = { 0x41, 0xC1, 0xCB, 0x6B, 0x51,
		0x24, 0x7A, 0x14, 0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14, 0x89,
		0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA, 0x40, 0x14, 0x55, 0xA1, 0x94,
		0xA9, 0x49, 0xFA };

static const unsigned char ecdsa_pub_key_x[] = { 0x36, 0xDF, 0xE2, 0xC6, 0xF9,
		0xF2, 0xED, 0x29, 0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91, 0x63,
		0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5, 0xE4, 0x7C, 0xFB, 0xF2, 0x5F,
		0xA5, 0x8F, 0x52 };

static const unsigned char ecdsa_pub_key_y[] = { 0x71, 0xA0, 0xD4, 0xFC, 0xDE,
		0x1A, 0xB8, 0x78, 0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB, 0xE9,
		0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B, 0x4F, 0xAB, 0xC3, 0x6F, 0xC7,
		0x72, 0xF8, 0x29 };

static int get_ecdsa_key(struct dtls_context_t *ctx, const session_t *session,
		const dtls_ecdsa_key_t **result) {
	static const dtls_ecdsa_key_t ecdsa_key = { .curve =
			DTLS_ECDH_CURVE_SECP256R1, .priv_key = ecdsa_priv_key, .pub_key_x =
			ecdsa_pub_key_x, .pub_key_y = ecdsa_pub_key_y };

	*result = &ecdsa_key;
	return 0;
}

static int verify_ecdsa_key(struct dtls_context_t *ctx,
		const session_t *session, const unsigned char *other_pub_x,
		const unsigned char *other_pub_y, size_t key_size) {
	return 0;
}
#endif /* DTLS_ECC */

static dtls_handler_t cb = { .write = send_to_peer, .read = read_from_peer,
		.event = handle_event,
#ifdef DTLS_PSK
		.get_psk_key = get_psk_key,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
		.get_ecdsa_key = get_ecdsa_key, .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
		};

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

	// 3nd parameter : should be a callback (event).
	luaL_checktype(L, 3, LUA_TFUNCTION);

	// 4nd parameter : should be a string).
	const char * security = luaL_checkstring(L, 4);

	lua_pop(L,1);

	// Create llwm userdata object and set its metatable.
	ldtls_ctxuserdata * ctxud = lua_newuserdata(L, sizeof(ldtls_ctxuserdata)); // stack: sendcallback, receivecallback, ctxud
	ctxud->L = L;
	ctxud->sendCallbackRef = LUA_NOREF;
	ctxud->receiveCallbackRef = LUA_NOREF;
	ctxud->eventCallbackRef = LUA_NOREF;
	ctxud->ctx = NULL;
	luaL_getmetatable(L, "luadtls.ctx"); // stack: sendcallback, receivecallback, ctxud, metatable
	lua_setmetatable(L, -2); // stack: sendcallback, receivecallback, ctxud
	lua_insert(L, 1); // stack: ctxud, sendcallback, receivecallback

	// Store the callbacks in Lua registry to keep a reference on it.
	int eventCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud,
	int receiveCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud, sendcallback
	int sendCallbackref = luaL_ref(L, LUA_REGISTRYINDEX); // stack: ctxud

	// Create DTLS context.
	dtls_context_t * dtls_context = dtls_new_context(ctxud);

	// Manage security.
	if (strcmp(security, "ECC") == 0) {
#ifdef DTLS_PSK
		cb.get_psk_key = NULL;
#endif /* DTLS_PSK */
	} else {
#ifdef DTLS_ECC
		cb.get_ecdsa_key = NULL;
		cb.verify_ecdsa_key = NULL;
#endif  /* DTLS_ECC */
	}

	dtls_set_handler(dtls_context, &cb);
	if (!dtls_context) {
		// TODO manage error
		dtls_emerg( "cannot create context\n");
		exit(-1);
	}

	// Store it in userdata context.
	ctxud->ctx = dtls_context;
	ctxud->sendCallbackRef = sendCallbackref;
	ctxud->receiveCallbackRef = receiveCallbackref;
	ctxud->eventCallbackRef = eventCallbackref;

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
	if (err)
		dtls_emerg( "cannot connect \n");

	// Try to connect.
	int res = dtls_connect(ctxud->ctx, &dst);
	if (!res)
		dtls_emerg( "cannot connect \n");
	return 1;
}

static int ldtls_handle(lua_State *L) {
	// Get lua DTLS context object
	ldtls_ctxuserdata* ctxud = checklctx(L, "handle");

	// Get peer address.
	const char* host = luaL_checkstring(L, 2);
	const char *port = luaL_checkstring(L, 3);

	// Get data buffer.
	size_t length;
	uint8_t * buffer = (uint8_t*) luaL_checklstring(L, 4, &length);

	// Find session object.
	session_t dst;
	memset(&dst, 0, sizeof(session_t));
	int err;
	err = getsockaddr(host, port, &dst);
	if (err)
		dtls_emerg( "cannot handle \n");

	dtls_handle_message(ctxud->ctx, &dst, buffer, length);
	return 0;
}

static int ldtls_write(lua_State *L) {
	// Get lua DTLS context object
	ldtls_ctxuserdata* ctxud = checklctx(L, "write");

	// Get peer address.
	const char* host = luaL_checkstring(L, 2);
	const char *port = luaL_checkstring(L, 3);

	// Get data buffer.
	size_t length;
	uint8_t * buffer = (uint8_t*) luaL_checklstring(L, 4, &length);

	// Find session object.
	session_t dst;
	memset(&dst, 0, sizeof(session_t));
	int err;
	err = getsockaddr(host, port, &dst);
	if (err)
		dtls_emerg( "cannot write \n");

	dtls_write(ctxud->ctx, &dst, buffer, length);
	return 0;
}

static const struct luaL_Reg ldtls_objmeths[] = { { "connect", ldtls_connect },
		{ "handle", ldtls_handle }, { "write", ldtls_write }, {
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
