#ifndef CONFIG_H
#define CONFIG_H

#define DEBUG_LEVEL 1

#define XMPP_ASK_PASSWORD 0
#define XMPP_SSL 1	// 0 - no ssl, 1 - use ssl, 2 - require ssl
static const char *xmpp_username = "user";
static const char *xmpp_server = "jabber.ru";
static const guint xmpp_port = 5222;
#if !XMPP_ASK_PASSWORD
static const char *xmpp_password = "secret";
#endif
static const char *xmpp_resource = "xmppbnc";
static const char *xmpp_priority = "0";

char *acl[] = {
	"lexszero@jabber.ru",
	"lexszer0@jabber.ru",
	NULL
};

#endif /* CONFIG_H */
