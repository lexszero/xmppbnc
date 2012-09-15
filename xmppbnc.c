#include "common.h"

#define XMLNS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define XMLNS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define NODE_COMMANDS "http://jabber.org/protocol/commands"
#define NODE_RC_FORWARD "http://jabber.org/protocol/rc#forward"

GMainLoop *main_loop;
GMainContext *context;

LmConnection *connection;
#ifdef XMPP_SSL
LmSSL *ssl;
#endif

static void cb_connection_close(LmConnection *connection, LmDisconnectReason reason, gpointer data) {
	LOGFD();
}

static LmHandlerResult cb_msg_presence(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer data) {
	LOGFD();
}

static LmHandlerResult cb_msg_message(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer data) {
	LOGFD();
}

static LmHandlerResult cb_msg_iq(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer data) {
	LOGFD();
	
	LmMessageNode *query, *item;
	LmMessage *reply;

	char *type = lm_message_node_get_attribute(m->node, "type");
	LOGFD("type=%s", type);
	if (strcmp(type, "get") == 0) {
		query = lm_message_node_get_child(m->node, "query");
		if (!query) {
			lm_message_unref(m);
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
		char *xmlns = lm_message_node_get_attribute(query, "xmlns");
		char *node = lm_message_node_get_attribute(query, "node");
		LOGFD("node=%s xmlns=%s", node, xmlns);
		
		reply = lm_message_new_with_sub_type(
				lm_message_node_get_attribute(m->node, "from"),
				LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_RESULT);
		lm_message_node_set_attribute(reply->node, "id", lm_message_node_get_attribute(m->node, "id"));
		query = lm_message_node_add_child(reply->node, "query", NULL);
		lm_message_node_set_attribute(query, "xmlns", xmlns);
		if (node)
			lm_message_node_set_attribute(query, "node", node);

		if (strcmp(xmlns, XMLNS_DISCO_ITEMS) == 0) {
			if (!node) {
				lm_message_node_set_attributes(
						lm_message_node_add_child(query, "item", NULL),
						"jid", lm_message_node_get_attribute(m->node, "to"),
						"name", "Remote control",
						"node", NODE_COMMANDS,
						NULL);
				lm_connection_send(connection, reply, NULL);
			}
			else if (strcmp(node, NODE_COMMANDS) == 0) {
				lm_message_node_set_attributes(
						lm_message_node_add_child(query, "item", NULL),
						"jid", lm_message_node_get_attribute(m->node, "to"),
						"name", "Forward unread messages",
						"node", NODE_RC_FORWARD,
						NULL);
				lm_connection_send(connection, reply, NULL);
			}
		}
		else if (strcmp(xmlns, XMLNS_DISCO_INFO) == 0) {
			if (!node) {
				lm_message_node_set_attribute(
						lm_message_node_add_child(query, "feature", NULL),
						"var", NODE_COMMANDS);
				lm_connection_send(connection, reply, NULL);
			}
			else if (strcmp(node, NODE_COMMANDS) == 0) {
				lm_message_node_set_attributes(
						lm_message_node_add_child(query, "identity", NULL),
						"name", "Remote control",
						"category", "automation",
						"type", "command-list",
						NULL);
				lm_connection_send(connection, reply, NULL);
			}
			else if (strcmp(node, NODE_RC_FORWARD) == 0) {
				lm_message_node_set_attributes(
						lm_message_node_add_child(query, "identity", NULL),
						"name", "Forward unread messages",
						"category", "automation",
						"type", "command-node",
						NULL);
				lm_message_node_set_attribute(
						lm_message_node_add_child(query, "feature", NULL),
						"var", NODE_COMMANDS);
				lm_message_node_set_attribute(
						lm_message_node_add_child(query, "feature", NULL),
						"var", "jabber:x:data");
				lm_connection_send(connection, reply, NULL);
			}
		}
		lm_message_unref(reply);
	}
	else if (strcmp(type, "set") == 0) {
		query = lm_message_node_get_child(m->node, "command");
		if (!query) {
			lm_message_unref(m);
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
		char *node = lm_message_node_get_attribute(query, "node");
		LOGFD("node=%s", node);
		if (strcmp(lm_message_node_get_attribute(query, "action"), "execute") == 0) {
			LOGFD("action=execute");
			if (strcmp(node, "http://jabber.org/protocol/rc#forward") == 0) {
				reply = lm_message_new_with_sub_type(
						lm_message_node_get_attribute(m->node, "from"), LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_RESULT);
				lm_message_node_set_attribute(reply->node, "id", lm_message_node_get_attribute(m->node, "id"));
				query = lm_message_node_add_child(reply->node, "command", NULL);
				lm_message_node_set_attribute(query, "xmlns", "http://jabber.org/protocol/commands");
				lm_message_node_set_attribute(query, "node", "http://jabber.org/protocol/rc#forward");
				lm_message_node_set_attribute(query, "statuc", "completed");
				lm_connection_send(connection, reply, NULL);
				lm_message_unref(reply);
			}
		}
	}
	lm_message_unref(m);
	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

static int xmpp_connect() {
	assert(!lm_connection_is_open(connection));
	
	lm_connection_register_message_handler(
			connection,
			lm_message_handler_new(cb_msg_message, NULL, NULL),
			LM_MESSAGE_TYPE_MESSAGE,
			LM_HANDLER_PRIORITY_NORMAL);
	lm_connection_register_message_handler(
			connection,
			lm_message_handler_new(cb_msg_presence, NULL, NULL),
			LM_MESSAGE_TYPE_PRESENCE,
			LM_HANDLER_PRIORITY_NORMAL);
	lm_connection_register_message_handler(
			connection,
			lm_message_handler_new(cb_msg_iq, NULL, NULL),
			LM_MESSAGE_TYPE_IQ,
			LM_HANDLER_PRIORITY_NORMAL);
	lm_connection_set_disconnect_function(connection, cb_connection_close, NULL, g_free);

	lm_connection_set_port(connection, xmpp_port);
#if XMPP_SSL
	ssl = lm_ssl_new(NULL, NULL, NULL, NULL);
	assert(ssl);

	lm_ssl_use_starttls(ssl, true, XMPP_SSL == 2 ? true : false);
	lm_connection_set_ssl(connection, ssl);
#endif

	char *jid = malloc(3071); // see rfc3920bis
	strcpy(jid, xmpp_username);
	strcat(jid, "@");
	strcat(jid, lm_connection_get_server(connection));
	lm_connection_set_jid(connection, jid); 
	free(jid);

#if XMPP_ASK_PASSWORD
#error not implemented
#endif

	GError *err = NULL;
//	if (!lm_connection_open(connection, (LmResultFunction) cb_connection_open, NULL, g_free, &err)) {
	if (!lm_connection_open_and_block(connection, &err)) {
		LOGF("%s", err->message);
		g_clear_error(&err);
		return -1;
	}

	if (!lm_connection_authenticate_and_block(connection, xmpp_username, xmpp_password, xmpp_resource, &err)) {
		LOGF("%s", err->message);
		g_clear_error(&err);
		return -2;
	}

	LmMessage *msg = lm_message_new(NULL, LM_MESSAGE_TYPE_PRESENCE);
	lm_message_node_add_child(msg->node, "priority", xmpp_priority);
	lm_connection_send(connection, msg, NULL);
	lm_message_unref(msg);

	return 1;
}

int main(int argc, char *argv[]) {
	LOGFD("hello");

	context = g_main_context_new();
	main_loop = g_main_loop_new(context, FALSE);

	connection = lm_connection_new_with_context(xmpp_server, context);
	assert(connection);

	if (xmpp_connect() >= 0) {
		LOGF("succesfully connected");
	}
	g_main_loop_run(main_loop);
/*	while (1) {
		sleep(1);
	}*/
}
