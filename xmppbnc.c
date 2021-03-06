#define _POSIX_C_SOURCE 200809L

#include "common.h"

#define XMLNS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define XMLNS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define XMLNS_ADDRESS "http://jabber.org/protocol/address"
#define XMLNS_DELAY "urn:xmpp:delay"
#define XMLNS_DATA "jabber:x:data"
#define XMLNS_MUC "http://jabber.org/protocol/muc"
#define XMLNS_PRIVATE "jabber:iq:private"
#define XMLNS_BOOKMARKS "storage:bookmarks"
#define NODE_COMMANDS "http://jabber.org/protocol/commands"
#define NODE_RC_FORWARD "http://jabber.org/protocol/rc#forward"
#define NODE_RC_JOINMUC "http://jabber.org/protocol/rc#joinmuc"

enum {
	JID_MAX = 3071 // see rfc3920bis
};

GMainLoop *main_loop;
GMainContext *context;

bool connected = false;
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

GHashTable *mucs;
typedef struct muc_s {
	char *password;
	char *req_from;
	char *req_id;
	char *req_sessionid;
	enum muc_status_e {
		MUC_UNEXPECTED = 0,
		MUC_UNJOINED,
		MUC_WAIT_RESPONSE,
		MUC_JOINED
	} status;
} muc_t;

static void destroy_muc_entry(void *muc_) {
	muc_t *muc = (muc_t *)muc_;
	free(muc->password);
	free(muc->req_from);
	free(muc->req_id);
	free(muc->req_sessionid);
	free(muc);
}

static bool access_allowed(const char *jid) {
	char *acl_jid;
	int i;
	for (i = 0, acl_jid = acl[i]; acl_jid; i++, acl_jid = acl[i]) {
		if (strncmp(acl_jid, jid, strlen(acl_jid)) == 0)
			return true;
	}
	return false;
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

static LmMessage * make_msg_reply(const char *to, const char *id) {
	LmMessage *msg = lm_message_new_with_sub_type(to,
			LM_MESSAGE_TYPE_IQ,	LM_MESSAGE_SUB_TYPE_RESULT);
	lm_message_node_set_attribute(msg->node, "id", id);
	return msg;
}
static LmMessageNode * make_query(LmMessageNode *root, const char *xmlns, const char *node) {
	LmMessageNode *query = lm_message_node_add_child(root, "query", NULL);
	if (node)
		lm_message_node_set_attribute(query, "node", node);
	if (xmlns)
		lm_message_node_set_attribute(query, "xmlns", xmlns);
	return query;
}

static void each_muc_leave(gpointer key, gpointer value, gpointer data) {
	(void)key;
	(void)data;
	muc_t *muc = (muc_t *)value;
	muc->status = MUC_UNJOINED;
}

static void cb_connection_close(LmConnection *connection, LmDisconnectReason reason,
		gpointer data) {
	(void)connection;
	(void)data;

	const char *str;
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
	g_hash_table_foreach(mucs, each_muc_leave, NULL);
	g_main_loop_quit(main_loop);
}

static LmHandlerResult cb_msg_message(LmMessageHandler *handler,
		LmConnection *connection, LmMessage *m, gpointer data) {
	(void)connection;
	(void)data;
	(void)handler;

	if (!lm_message_node_get_child(m->node, "event")) {
		LOGFD("storing message from %s",
				lm_message_node_get_attribute(m->node, "from"));
		lm_message_node_ref(m->node);
		msg_t *msg = msg_new(m->node);
		g_queue_push_head(queue, (gpointer)msg);
	}

	lm_message_unref(m);
	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

static void request_join_muc(const char *full_jid, muc_t *muc) {
	LOGF("Joining %s", full_jid);

	LmMessage *msg;
	LmMessageNode *x;

	msg = lm_message_new(full_jid, LM_MESSAGE_TYPE_PRESENCE);
	x = lm_message_node_add_child(msg->node, "x", NULL);
	lm_message_node_set_attribute(x, "xmlns", XMLNS_MUC);
	if (muc->password && strlen(muc->password)) {
		lm_message_node_add_child(x, "password", muc->password);
	}
	send_and_unref(msg);
	muc->status = MUC_WAIT_RESPONSE;
}

static muc_t * join_muc(const char *jid, const char *nick, const char *password, const char *req_from,
		const char *req_id, const char *req_sessionid) {

	nick = nick ? nick : xmpp_username;
	char *full_jid = malloc(JID_MAX);
	snprintf(full_jid, JID_MAX, "%s/%s", jid, nick);
	full_jid = realloc(full_jid, strlen(full_jid)+1);

	muc_t *muc = malloc(sizeof(muc_t));
	muc->status = MUC_UNJOINED;
	muc->password = password ? strdup(password) : NULL;
	muc->req_from = req_from ? strdup(req_from) : NULL;
	muc->req_id = req_id ? strdup(req_id) : NULL;
	muc->req_sessionid = req_sessionid ? strdup(req_sessionid) : NULL;

	g_hash_table_insert(mucs, full_jid, muc);

	request_join_muc(full_jid, muc);
	return muc;
}

static void join_muc_send_response(const muc_t *muc, const char *message) {
	LOGF("MUC join result: %s", message);

	LmMessage *reply;
	LmMessageNode *x;

	reply = make_msg_reply(muc->req_from, muc->req_id);
	x = lm_message_node_add_child(reply->node, "command", NULL);
	lm_message_node_set_attributes(x,
			"xmlns", NODE_COMMANDS,
			"node", NODE_RC_JOINMUC,
			"sessionid", muc->req_sessionid,
			"status", "completed",
			NULL);
	x = lm_message_node_add_child(x, "x", NULL);
	lm_message_node_set_attributes(x,
			"xmlns", XMLNS_DATA,
			"type", "form",
			NULL);
	lm_message_node_add_child(x, "title", "Join MUC");
	lm_message_node_add_child(x, "instructions", message);

	send_and_unref(reply);
}

static void each_muc_rejoin(gpointer key, gpointer value, gpointer data) {
	(void)data;
	char *full_jid = (char *)key;
	muc_t *muc = (muc_t *)value;
	assert(muc->status == MUC_UNJOINED);
	request_join_muc(full_jid, muc);
}

static void request_bookmarks() {
	LmMessage *msg = lm_message_new(NULL, LM_MESSAGE_TYPE_IQ);
	lm_message_node_set_attribute(msg->node, "type", "get");

	LmMessageNode *query = make_query(msg->node, XMLNS_PRIVATE, NULL);
	lm_message_node_set_attribute(lm_message_node_add_child(query, "storage", NULL),
			"xmlns", XMLNS_BOOKMARKS);

	send_and_unref(msg);
}

static void save_muc_to_bookmarks(const char *jid, const char *nick, const char *password,
		bool autojoin) {
	LmMessage *msg = lm_message_new(NULL, LM_MESSAGE_TYPE_IQ);
	lm_message_node_set_attribute(msg->node, "type", "set");

	LmMessageNode *node = make_query(msg->node, XMLNS_PRIVATE, NULL);
	node = lm_message_node_add_child(node, "storage", NULL);
	lm_message_node_set_attribute(node, "xmlns", XMLNS_BOOKMARKS);
	node = lm_message_node_add_child(node, "conference", NULL);
/* TODO
	lm_message_node_set_attributes(node,
			"autojoin", 
*/
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

static void make_identity_command_node(LmMessageNode *query, const char *name) {
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

static void process_cmd_forward(const char *to, const char *id) {
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

static void process_cmd_joinmuc(const char *to, const char *id, LmMessageNode *request) {
	LmMessage *reply;
	LmMessageNode *x;

	const char *action = lm_message_node_get_attribute(request, "action");
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
		lm_message_node_set_attributes(
				lm_message_node_add_child(x, "field", NULL),
				"type", "boolean",
				"label", "Save to bookmarks",
				"var", "muc_save_to_bookmarks",
				NULL);
		lm_message_node_set_attributes(
				lm_message_node_add_child(x, "field", NULL),
				"type", "boolean",
				"label", "Autojoin",
				"var", "muc_autojoin",
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
		const char *name, *value, *muc_jid, *muc_nick, *muc_password;
		bool muc_save_to_bookmarks, muc_autojoin;
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
			if (strcmp(name, "muc_save_to_bookmarks") == 0)
				muc_save_to_bookmarks = (strcmp(value, "1") == 0);
			if (strcmp(name, "muc_autojoin") == 0)
				muc_autojoin = (strcmp(value, "1") == 0);
		}

		if (muc_save_to_bookmarks)
			save_muc_to_bookmarks(muc_jid, muc_nick, muc_password, muc_autojoin);

		join_muc(muc_jid, muc_nick, muc_password, to, id,
				lm_message_node_get_attribute(request, "sessionid"));
	}
}

static LmHandlerResult cb_msg_iq(LmMessageHandler *handler, LmConnection *connection,
		LmMessage *m, gpointer data) {
	(void)handler;
	(void)connection;
	(void)data;

	LmMessage *reply;
	const char *reply_to, *reply_id, *type, *xmlns, *node;
	
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
	else if (strcmp(type, "result") == 0) {
		LmMessageNode *query = lm_message_node_get_child(m->node, "query");
		if (!query) {
			lm_message_unref(m);
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
		xmlns = lm_message_node_get_attribute(query, "xmlns");
		if (strcmp(xmlns, XMLNS_PRIVATE) == 0) {
			LmMessageNode *conference = lm_message_node_get_child(query, "conference");
			if (!conference) {
				lm_message_unref(m);
				return LM_HANDLER_RESULT_REMOVE_MESSAGE;
			}
			const char *autojoin = lm_message_node_get_attribute(conference, "autojoin");
			if (autojoin && (strcmp(autojoin, "1") == 0)) {
				const char *muc_jid, *muc_nick, *muc_password;
				muc_jid = lm_message_node_get_attribute(conference, "jid");
				muc_nick = lm_message_node_get_value(
						lm_message_node_get_child(conference, "nick"));
				muc_password = lm_message_node_get_value(
						lm_message_node_get_child(conference, "password"));
				join_muc(muc_jid, muc_nick, muc_password, NULL, NULL, NULL);
			}
		}
	}
	lm_message_unref(m);
	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

static LmHandlerResult cb_msg_presence(LmMessageHandler *handler, LmConnection *connection,
		LmMessage *m, gpointer data) {
	(void)handler;
	(void)connection;
	(void)data;

	const char *from, *type, *error;
	from = lm_message_node_get_attribute(m->node, "from");
	type = lm_message_node_get_attribute(m->node, "type");
	
	muc_t *muc = g_hash_table_lookup(mucs, from);
	if (muc && muc->status == MUC_WAIT_RESPONSE) {
		if (type && (strcmp(type, "error") == 0)) {
			free(muc);
			g_hash_table_remove(mucs, from);
			error = lm_message_node_get_child(m->node, "error")->children->name;
			join_muc_send_response(muc, error);
		}
		else {
			muc->status = MUC_JOINED;
			join_muc_send_response(muc, "Success");
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
	lm_connection_register_message_handler(
			connection,
			lm_message_handler_new(cb_msg_presence, NULL, NULL),
			LM_MESSAGE_TYPE_PRESENCE,
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

	ourjid = malloc(JID_MAX);
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

	lm_connection_set_keep_alive_rate(connection, 10);

	connected = true;

	g_hash_table_foreach(mucs, each_muc_rejoin, NULL);
	return 1;
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	context = g_main_context_new();
	main_loop = g_main_loop_new(context, FALSE);

	queue = g_queue_new();
	assert(queue);

	mucs = g_hash_table_new_full(g_str_hash, g_str_equal, free, destroy_muc_entry);
	assert(mucs);

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
