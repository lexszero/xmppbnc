#include "common.h"

#define XMLNS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define XMLNS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define XMLNS_ADDRESS "http://jabber.org/protocol/address"
#define XMLNS_DELAY "urn:xmpp:delay"
#define XMLNS_DATA "jabber:x:data"
#define NODE_COMMANDS "http://jabber.org/protocol/commands"
#define NODE_RC_FORWARD "http://jabber.org/protocol/rc#forward"
#define NODE_RC_JOINMUC "http://jabber.org/protocol/rc#joinmuc"

GMainLoop *main_loop;
GMainContext *context;

char *ourjid;

LmConnection *connection;
#ifdef XMPP_SSL
LmSSL *ssl;
#endif

GQueue *queue;
typedef struct msg_s {
	LmMessageNode *node;
	GDateTime *time;
} msg_t;

static bool access_allowed(char *jid) {
	return (strncmp(jid, ourjid, (strchr(ourjid, '/') - ourjid)) == 0);
}

static msg_t * msg_new(LmMessageNode *node) {
	msg_t *msg = malloc(sizeof(msg_t));
	msg->node = node;
	msg->time = g_date_time_new_now_utc();
	return msg;
}

static void msg_free(msg_t *msg) {
	lm_message_node_unref(msg->node);
	g_date_time_unref(msg->time);
	free(msg);
}

static void cb_connection_close(LmConnection *connection, LmDisconnectReason reason,
		gpointer data) {
	char *str;
	switch (reason) {
		case LM_DISCONNECT_REASON_OK:
			str = "User requested disconnect.";
			break;
		case LM_DISCONNECT_REASON_PING_TIME_OUT:
			str = "Connection to the server timed out";
			break;
		case LM_DISCONNECT_REASON_HUP:
			str = "The socket emitted that the connection was hung up.";
			break;
		case LM_DISCONNECT_REASON_ERROR:
			str = "A generic error somewhere in the transport layer.";
			break;
		case LM_DISCONNECT_REASON_RESOURCE_CONFLICT:
			str = "Another connection was made to the server with the same resource.";
			break;
		case LM_DISCONNECT_REASON_INVALID_XML:
			str = "Invalid XML was sent from the client.";
			break;
		case LM_DISCONNECT_REASON_UNKNOWN:
			str = "An unknown error.";
	}
	LOGF("Disconnected. Reason: %s\n", str);
	g_main_loop_quit(main_loop);
}

static LmHandlerResult cb_msg_message(LmMessageHandler *handler,
		LmConnection *connection, LmMessage *m, gpointer data) {
	LOGFD();

	lm_message_node_ref(m->node);

	msg_t *msg = msg_new(m->node);
	g_queue_push_head(queue, (gpointer)msg);

	lm_message_unref(m);
	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

static bool send_and_unref(LmMessage *msg) {
	GError *err = NULL;
	if (!lm_connection_send(connection, msg, &err)) {
		LOGF("%s", err->message);
		g_clear_error(&err);
		lm_message_unref(msg);
		return false;
	}
	lm_message_unref(msg);
	return true;
}

static bool join_muc(char *jid, char *nick, char *password) {
	LOGF("Joining %s as %s", jid, nick);
	return true;
}

static LmMessage * make_msg_reply(char *to, char *id) {
	LmMessage *msg = lm_message_new_with_sub_type(to,
			LM_MESSAGE_TYPE_IQ,	LM_MESSAGE_SUB_TYPE_RESULT);
	lm_message_node_set_attribute(msg->node, "id", id);
	return msg;
}

static LmMessageNode * make_query(LmMessageNode *root, char *xmlns, char *node) {
	LmMessageNode *query = lm_message_node_add_child(root, "query", NULL);
	if (node)
		lm_message_node_set_attribute(query, "node", node);
	if (xmlns)
		lm_message_node_set_attribute(query, "xmlns", xmlns);
	return query;
}

static void make_items_root(LmMessageNode *query) {
	lm_message_node_set_attributes(
			lm_message_node_add_child(query, "item", NULL),
			"jid", ourjid,
			"name", "Remote control",
			"node", NODE_COMMANDS,
			NULL);
}

static void make_items_commands(LmMessageNode *query) {
	lm_message_node_set_attributes(
			lm_message_node_add_child(query, "item", NULL),
			"jid", ourjid,
			"name", "Forward unread messages",
			"node", NODE_RC_FORWARD,
			NULL);
	lm_message_node_set_attributes(
			lm_message_node_add_child(query, "item", NULL),
			"jid", ourjid,
			"name", "Join MUC",
			"node", NODE_RC_JOINMUC,
			NULL);
}

static void make_features(LmMessageNode *query) {
	lm_message_node_set_attribute(
			lm_message_node_add_child(query, "feature", NULL),
			"var", NODE_COMMANDS);
}

static void make_identity_command_list(LmMessageNode *query) {
	lm_message_node_set_attributes(
			lm_message_node_add_child(query, "identity", NULL),
			"name", "Remote control",
			"category", "automation",
			"type", "command-list",
			NULL);
}

static void make_identity_command_node(LmMessageNode *query, char *name) {
	lm_message_node_set_attributes(
			lm_message_node_add_child(query, "identity", NULL),
			"name", name,
			"category", "automation",
			"type", "command-node",
			NULL);
	lm_message_node_set_attribute(
			lm_message_node_add_child(query, "feature", NULL),
			"var", NODE_COMMANDS);
	lm_message_node_set_attribute(
			lm_message_node_add_child(query, "feature", NULL),
			"var", XMLNS_DATA);
}

static void process_cmd_forward(char *to, char *id) {
	LmMessage *reply;
	msg_t *msg;
	char *stamp;
	LmMessageNode *addresses;
	while (msg = (msg_t *)g_queue_pop_tail(queue)) {
		LOGFD("forwarding msg from %s",
				lm_message_node_get_attribute(msg->node, "from"));
		reply = lm_message_new(to, LM_MESSAGE_TYPE_MESSAGE);
		lm_message_node_set_attribute(reply->node,
				"type", lm_message_node_get_attribute(msg->node, "type"));
		reply->node->children = msg->node->children;
		addresses = lm_message_node_add_child(reply->node, "addresses", NULL);
		lm_message_node_set_attribute(addresses, "xmlns", XMLNS_ADDRESS);
		lm_message_node_set_attributes(
				lm_message_node_add_child(addresses, "address", NULL),
				"type", "ofrom",
				"jid", lm_message_node_get_attribute(msg->node, "from"),
				NULL);
		stamp = g_date_time_format(msg->time, "%Y-%m-%dT%H:%M:%SZ");
		lm_message_node_set_attributes(
				lm_message_node_add_child(reply->node, "delay", NULL),
				"xmlns", XMLNS_DELAY,
				"from", ourjid,
				"stamp", stamp,
				NULL);
		send_and_unref(reply);
		g_free(stamp);
		msg_free(msg);
	}
	reply = make_msg_reply(to, id);
	lm_message_node_set_attributes(
			lm_message_node_add_child(reply->node, "command", NULL),
			"xmlns", NODE_COMMANDS,
			"node", NODE_RC_FORWARD,
			"status", "completed",
			//"sessionid", lm_message_node_get_attribute(query, "sessionid"),
			NULL);
	send_and_unref(reply);
}

static void process_cmd_joinmuc(char *to, char *id, LmMessageNode *request) {
	LmMessage *reply;
	LmMessageNode *x;
	char *action;
	action = lm_message_node_get_attribute(request, "action");
	if (action && (strcmp(action, "execute") == 0)) {
		reply = make_msg_reply(to, id);
		x = lm_message_node_add_child(reply->node, "command", NULL);
		lm_message_node_set_attributes(x,
				"xmlns", NODE_COMMANDS,
				"node", NODE_RC_JOINMUC,
				"sessionid", "stub_sessionid",
				"status", "executing",
				NULL);
		x = lm_message_node_add_child(x, "x", NULL);
		lm_message_node_set_attributes(x,
				"xmlns", XMLNS_DATA,
				"type", "form",
				NULL);
		lm_message_node_add_child(x, "title", "Join MUC");
		lm_message_node_set_attributes(
				lm_message_node_add_child(x, "field", NULL),
				"type", "text-single",
				"label", "MUC JID",
				"var", "muc_jid",
				NULL);
		lm_message_node_set_attributes(
				lm_message_node_add_child(x, "field", NULL),
				"type", "text-single",
				"label", "Nick",
				"var", "muc_nick",
				NULL);
		lm_message_node_set_attributes(
				lm_message_node_add_child(x, "field", NULL),
				"type", "text-private",
				"label", "Password",
				"var", "muc_password",
				NULL);
		send_and_unref(reply);
	}
	else if (!action || (action && (strcmp(action, "complete") == 0))) {
		x = lm_message_node_get_child(request, "x");
		if (!x) {
			LOGFD("shit rcvd");
			return;
		}
		LmMessageNode *field;
		char *name, *value, *muc_jid, *muc_nick, *muc_password;
		for (field = x->children; field; field = field->next) {
			name = lm_message_node_get_attribute(field, "var");
			value = lm_message_node_get_value(
					lm_message_node_get_child(field, "value"));
			LOGFD("%s=%s", name, value);
			if (strcmp(name, "muc_jid") == 0)
				muc_jid = value;
			if (strcmp(name, "muc_nick") == 0)
				muc_nick = value;
			if (strcmp(name, "muc_password") == 0)
				muc_password = value;
		}

		reply = make_msg_reply(to, id);
		x = lm_message_node_add_child(reply->node, "command", NULL);
		lm_message_node_set_attributes(x,
				"xmlns", NODE_COMMANDS,
				"node", NODE_RC_JOINMUC,
				"sessionid", lm_message_node_get_attribute(
					request, "sessionid"),
				"status", "completed",
				NULL);
		x = lm_message_node_add_child(x, "x", NULL);
		lm_message_node_set_attributes(x,
				"xmlns", XMLNS_DATA,
				"type", "form",
				NULL);
		lm_message_node_add_child(x, "title", "Join MUC");

		if (join_muc(muc_jid, muc_nick, muc_password)) {
			lm_message_node_add_child(x, "instructions", "Success");
		}
		else {
			lm_message_node_add_child(x, "instructions", "Fail");
		}
		send_and_unref(reply);
	}
}

static LmHandlerResult cb_msg_iq(LmMessageHandler *handler, LmConnection *connection,
		LmMessage *m, gpointer data) {
	LOGFD();
	
	LmMessage *reply;
	char *reply_to, *reply_id, *type, *xmlns, *node;
	
	reply_to = lm_message_node_get_attribute(m->node, "from");
	
	if (!reply_to) {
		lm_message_unref(m);
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;
	}

	if (!access_allowed(reply_to)) {
		LOGF("Access denied for %s", reply_to);
		lm_message_unref(m);
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;
	}

	reply_id = lm_message_node_get_attribute(m->node, "id"); 
	type = lm_message_node_get_attribute(m->node, "type");
	LOGFD("type=%s", type);
	if (strcmp(type, "get") == 0) {
		LmMessageNode *query = lm_message_node_get_child(m->node, "query");
		if (!query) {
			lm_message_unref(m);
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
		xmlns = lm_message_node_get_attribute(query, "xmlns");
		node = lm_message_node_get_attribute(query, "node");
		LOGFD("node=%s xmlns=%s", node, xmlns);

		reply = make_msg_reply(reply_to, reply_id);
		query = make_query(reply->node, xmlns, node);
		if (strcmp(xmlns, XMLNS_DISCO_ITEMS) == 0) {
			if (!node) {
				make_items_root(query);
				send_and_unref(reply);
			}
			else if (strcmp(node, NODE_COMMANDS) == 0) {
				make_items_commands(query);
				send_and_unref(reply);
			}
		}
		else if (strcmp(xmlns, XMLNS_DISCO_INFO) == 0) {
			if (!node) {
				make_features(query);
				send_and_unref(reply);
			}
			else if (strcmp(node, NODE_COMMANDS) == 0) {
				make_identity_command_list(query);
				send_and_unref(reply);
			}
			else if (strcmp(node, NODE_RC_FORWARD) == 0) {
				make_identity_command_node(query, "Forward unread messages");
				send_and_unref(reply);
			}
			else if (strcmp(node, NODE_RC_JOINMUC) == 0) {
				make_identity_command_node(query, "Join MUC");
				send_and_unref(reply);
			}
		}
	}
	else if (strcmp(type, "set") == 0) {
		LmMessageNode *command = lm_message_node_get_child(m->node, "command");
		if (!command) {
			lm_message_unref(m);
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
		xmlns = lm_message_node_get_attribute(command, "xmlns");
		node = lm_message_node_get_attribute(command, "node");
		LOGFD("node=%s", node);
		if (strcmp(node, NODE_RC_FORWARD) == 0) {
			process_cmd_forward(reply_to, reply_id);
		}
		else if (strcmp(node, NODE_RC_JOINMUC) == 0) {
			process_cmd_joinmuc(reply_to, reply_id, command);
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
			lm_message_handler_new(cb_msg_iq, NULL, NULL),
			LM_MESSAGE_TYPE_IQ,
			LM_HANDLER_PRIORITY_NORMAL);
	lm_connection_set_disconnect_function(connection, cb_connection_close,
			NULL, g_free);

	lm_connection_set_port(connection, xmpp_port);
#if XMPP_SSL
	ssl = lm_ssl_new(NULL, NULL, NULL, NULL);
	assert(ssl);

	lm_ssl_use_starttls(ssl, true, XMPP_SSL == 2 ? true : false);
	lm_connection_set_ssl(connection, ssl);
#endif

	ourjid = malloc(3071); // see rfc3920bis
	strcpy(ourjid, xmpp_username);
	strcat(ourjid, "@");
	strcat(ourjid, lm_connection_get_server(connection));
	lm_connection_set_jid(connection, ourjid);
	strcat(ourjid, "/");
	strcat(ourjid, xmpp_resource);

#if XMPP_ASK_PASSWORD
#error not implemented
#endif

	GError *err = NULL;
	if (!lm_connection_open_and_block(connection, &err)) {
		LOGF("%s", err->message);
		g_clear_error(&err);
		return -1;
	}

	if (!lm_connection_authenticate_and_block(connection,
				xmpp_username, xmpp_password, xmpp_resource, &err)) {
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
	context = g_main_context_new();
	main_loop = g_main_loop_new(context, FALSE);

	queue = g_queue_new();

	connection = lm_connection_new_with_context(xmpp_server, context);
	assert(connection);

	while (1) {
		if (xmpp_connect() >= 0) {
			LOGF("succesfully connected");
		}
		g_main_loop_run(main_loop);
	}

	return 0;
}
