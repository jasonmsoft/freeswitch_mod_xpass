#include <switch.h>
#include <ei.h>

#define MAX_ACL 100
#define CMD_BUFLEN 1024 * 1000
#define MAX_QUEUE_LEN 25000
#define MAX_MISSED 500
#define MAX_PID_CHARS 255
#define VERSION "mod_xpass v1.0"
#define MSG_BUF_LEN 2048
#define FETCH_REQUEST   "fetch_request"


#define API_COMMAND_DISCONNECT 0
#define API_COMMAND_REMOTE_IP 1
#define API_COMMAND_STREAMS 2
#define API_COMMAND_BINDINGS 3




/////////////////////////////
static char *MARKER = "1";

typedef enum {
	LFLAG_AUTHED = (1 << 0),
	LFLAG_RUNNING = (1 << 1),
	LFLAG_EVENTS = (1 << 2),
	LFLAG_LOG = (1 << 3),
	LFLAG_FULL = (1 << 4),
	LFLAG_MYEVENTS = (1 << 5),
	LFLAG_SESSION = (1 << 6),
	LFLAG_ASYNC = (1 << 7),
	LFLAG_STATEFUL = (1 << 8),
	LFLAG_OUTBOUND = (1 << 9),
	LFLAG_LINGER = (1 << 10),
	LFLAG_HANDLE_DISCO = (1 << 11),
	LFLAG_CONNECTED = (1 << 12),
	LFLAG_RESUME = (1 << 13),
	LFLAG_AUTH_EVENTS = (1 << 14),
	LFLAG_ALL_EVENTS_AUTHED = (1 << 15),
	LFLAG_ALLOW_LOG = (1 << 16)
} event_flag_t;

typedef enum {
	EVENT_FORMAT_PLAIN,
	EVENT_FORMAT_XML,
	EVENT_FORMAT_JSON
} event_format_t;


/*for socket event listener*/
struct listener {
	switch_socket_t *sock;
	switch_queue_t *event_queue;
	switch_queue_t *log_queue;
	switch_memory_pool_t *pool;
	event_format_t format;
	switch_mutex_t *flag_mutex;
	switch_mutex_t *filter_mutex;
	uint32_t flags;
	switch_log_level_t level;
	char *ebuf;
	uint8_t event_list[SWITCH_EVENT_ALL + 1];
	uint8_t allowed_event_list[SWITCH_EVENT_ALL + 1];
	switch_hash_t *event_hash;
	switch_hash_t *allowed_event_hash;
	switch_hash_t *allowed_api_hash;
	switch_thread_rwlock_t *rwlock;
	switch_core_session_t *session;
	int lost_events;
	int lost_logs;
	time_t last_flush;
	time_t expire_time;
	uint32_t timeout;
	uint32_t id;
	switch_sockaddr_t *sa;
	char remote_ip[50];
	switch_port_t remote_port;
	switch_event_t *filters;
	time_t linger_timeout;
	struct listener *next;
	switch_pollfd_t *pollfd;
	
};


typedef struct listener listener_t;

/*for config listener*/
struct config_listener{
    struct config_listener *next;
    uint32_t flags;
    switch_socket_t *sock;
    switch_xml_section_t section;
    char remote_ip[50];
	switch_port_t remote_port;
    
};

typedef struct config_listener config_listener_t;


struct config_listeners{
    config_listener_t * config_listeners;
    switch_mutex_t *config_listeners_mutex;
    switch_socket_t *sock;
    uint8_t ready;
    switch_memory_pool_t *pool;
};

typedef struct config_listeners config_listeners_list_t;


static struct {
	switch_mutex_t *listener_mutex;
	switch_event_node_t *node;
	int debug;
    switch_xml_binding_t *config_fetch_binding;
	switch_xml_binding_t *directory_fetch_binding;
	switch_xml_binding_t *dialplan_fetch_binding;
	switch_xml_binding_t *chatplan_fetch_binding;
	switch_xml_binding_t *channels_fetch_binding;
	
} globals;



static struct {
	switch_socket_t *sock;
	switch_mutex_t *sock_mutex;
	listener_t *listeners;
	uint8_t ready;
} listen_list;

#define MAX_ACL 100

static struct {
	switch_mutex_t *mutex;
	char *ip;
	uint16_t port;
	char *password;
	int done;
	int threads;
	char *acl[MAX_ACL];
	uint32_t acl_count;
	uint32_t id;
	int nat_map;
	int stop_on_bind_error;
	uint16_t config_port;
} prefs;


/////////////////////////////////////////////






typedef enum {
	LFLAG_RUNNING = (1 << 0)
} event_flag_t;

struct xpass_send_msg_s {
	char buf[MSG_BUF_LEN];
	uint16_t data_len;
};
typedef struct xpass_send_msg_s xpass_send_msg_t;

struct xpass_received_msg_s {
	char buf[MSG_BUF_LEN];
	uint16_t data_len;
};
typedef struct xpass_received_msg_s xpass_received_msg_t;

struct xpass_event_binding_s {
	char id[SWITCH_UUID_FORMATTED_LENGTH + 1];
	switch_event_node_t *node;
	switch_event_types_t type;
	const char *subclass_name;
	struct xpass_event_binding_s *next;
};
typedef struct xpass_event_binding_s xpass_event_binding_t;

struct xpass_event_stream_s {
	switch_memory_pool_t *pool;
	ei_event_binding_t *bindings;
	switch_queue_t *queue;
	switch_socket_t *acceptor;
	switch_pollset_t *pollset;
	switch_pollfd_t *pollfd;
	switch_socket_t *socket;
	switch_mutex_t *socket_mutex;
	switch_bool_t connected;
	char remote_ip[48];
	uint16_t remote_port;
	char local_ip[48];
	uint16_t local_port;
	erlang_pid pid;
	uint32_t flags;
	struct xpass_event_stream_s *next;
};
typedef struct xpass_event_stream_s xpass_event_stream_t;

struct xpass_node_s {
	switch_socket_t conn;
	switch_atomic_t pending_bgapi;
	switch_atomic_t receive_handlers;
	switch_memory_pool_t *pool;
	ei_event_stream_t *event_streams;
	switch_mutex_t *event_streams_mutex;
	switch_queue_t *send_msgs;
	switch_queue_t *received_msgs;
	switch_time_t created_time;
	switch_socket_t *socket;
	char remote_ip[25];
	uint16_t remote_port;
	char local_ip[25];
	uint16_t local_port;
	uint32_t flags;
	struct xpass_node_s *next;
};
typedef struct xpass_node_s xpass_node_t;

struct globals_s {
	switch_memory_pool_t *pool;
	switch_memory_pool_t *socket_pool;
	switch_atomic_t threads;
	switch_socket_t *acceptor;
	switch_thread_rwlock_t *xpass_nodes_lock;
	xpass_node_t *xpass_nodes;
	switch_xml_binding_t *config_fetch_binding;
	switch_xml_binding_t *directory_fetch_binding;
	switch_xml_binding_t *dialplan_fetch_binding;
	switch_xml_binding_t *chatplan_fetch_binding;
	switch_xml_binding_t *channels_fetch_binding;
	switch_hash_t *event_filter;
	int num_worker_threads;
	switch_bool_t nat_map;
	int ei_compat_rel; 
	char *ip;
	char *xpass_var_prefix;
	int var_prefix_length;
	uint32_t flags;
	int send_all_headers;
	int send_all_private_headers;
	int connection_timeout;
	int receive_timeout;
	int receive_msg_preallocate;
	int event_stream_preallocate;
	int send_msg_batch;
	short event_stream_framing;
	switch_port_t port;
};
typedef struct globals_s globals_t;
extern globals_t globals;

/* kazoo_node.c */
switch_status_t new_xpass_node(switch_socket_t conn);

/* kazoo_event_stream.c */
ei_event_stream_t *find_event_stream(ei_event_stream_t *event_streams, const erlang_pid *from);
ei_event_stream_t *new_event_stream(ei_event_stream_t **event_streams, const erlang_pid *from);
switch_status_t remove_event_stream(ei_event_stream_t **event_streams, const erlang_pid *from);
switch_status_t remove_event_streams(ei_event_stream_t **event_streams);
unsigned long get_stream_port(const ei_event_stream_t *event_stream);
switch_status_t add_event_binding(ei_event_stream_t *event_stream, const switch_event_types_t event_type, const char *subclass_name);
switch_status_t remove_event_binding(ei_event_stream_t *event_stream, const switch_event_types_t event_type, const char *subclass_name);
switch_status_t remove_event_bindings(ei_event_stream_t *event_stream);

/* kazoo_fetch_agent.c */
switch_status_t bind_fetch_agents();
switch_status_t unbind_fetch_agents();
switch_status_t remove_xml_clients(ei_node_t *ei_node);
switch_status_t add_fetch_handler(ei_node_t *ei_node, erlang_pid *from, switch_xml_binding_t *binding);
switch_status_t remove_fetch_handlers(ei_node_t *ei_node, erlang_pid *from);
switch_status_t fetch_reply(char *uuid_str, char *xml_str, switch_xml_binding_t *binding);
switch_status_t handle_api_command_streams(ei_node_t *ei_node, switch_stream_handle_t *stream);

/* kazoo_utils.c */
void close_socket(switch_socket_t **sock);
void close_socketfd(int *sockfd);
switch_socket_t *create_socket_with_port(switch_memory_pool_t *pool, switch_port_t port);
switch_socket_t *create_socket(switch_memory_pool_t *pool);
switch_status_t create_ei_cnode(const char *ip_addr, const char *name, struct ei_cnode_s *ei_cnode);
switch_status_t ei_compare_pids(const erlang_pid *pid1, const erlang_pid *pid2);
void ei_encode_switch_event_headers(ei_x_buff *ebuf, switch_event_t *event);
void ei_link(ei_node_t *ei_node, erlang_pid * from, erlang_pid * to);
void ei_encode_switch_event(ei_x_buff * ebuf, switch_event_t *event);
int ei_helper_send(ei_node_t *ei_node, erlang_pid* to, ei_x_buff *buf);
int ei_decode_atom_safe(char *buf, int *index, char *dst);
int ei_decode_string_or_binary_limited(char *buf, int *index, int maxsize, char *dst);
int ei_decode_string_or_binary(char *buf, int *index, char **dst);
switch_hash_t *create_default_filter();

/* kazoo_commands.c */
void add_kz_commands(switch_loadable_module_interface_t **module_interface, switch_api_interface_t *api_interface);

/* kazoo_dptools.c */
void add_kz_dptools(switch_loadable_module_interface_t **module_interface, switch_application_interface_t *app_interface);


char * encode_data(char * buf, char *data, int len);





#define _ei_x_encode_string(buf, string) { ei_x_encode_binary(buf, string, strlen(string)); }

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
