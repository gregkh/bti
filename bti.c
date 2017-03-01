/*
 * Copyright (C) 2008-2011 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2009 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Amir Mohammad Saied <amirsaied@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <json-c/json.h>
#include <pcre.h>
#include <termios.h>
#include <dlfcn.h>
#include <oauth.h>
#include "bti.h"

#define zalloc(size)	calloc(size, 1)

#define dbg(format, arg...)						\
	do {								\
		if (debug)						\
			fprintf(stdout, "bti: %s: " format , __func__ , \
				## arg);				\
	} while (0)


int debug;

static void display_help(void)
{
	fprintf(stdout, "bti - send tweet to twitter\n"
		"Version: %s\n"
		"Usage:\n"
		"  bti [options]\n"
		"options are:\n"
		"  --account accountname\n"
		"  --password password\n"
		"  --action action\n"
		"    ('update', 'friends', 'public', 'replies', 'user', or 'direct')\n"
		"  --user screenname\n"
		"  --proxy PROXY:PORT\n"
		"  --host HOST\n"
		"  --logfile logfile\n"
		"  --config configfile\n"
		"  --replyto ID\n"
		"  --retweet ID\n"
		"  --shrink-urls\n"
		"  --page PAGENUMBER\n"
		"  --column COLUMNWIDTH\n"
		"  --bash\n"
		"  --background\n"
		"  --debug\n"
		"  --verbose\n"
		"  --dry-run\n"
		"  --version\n"
		"  --help\n", VERSION);
}

static int strlen_utf8(char *s)
{
	int i = 0, j = 0;
	while (s[i]) {
		if ((s[i] & 0xc0) != 0x80)
			j++;
		i++;
	}
	return j;
}

static void display_version(void)
{
	fprintf(stdout, "bti - version %s\n", VERSION);
}

static char *get_string(const char *name)
{
	char *temp;
	char *string;

	string = zalloc(1000);
	if (!string)
		exit(1);
	if (name != NULL)
		fprintf(stdout, "%s", name);
	if (!fgets(string, 999, stdin)) {
		free(string);
		return NULL;
	}
	temp = strchr(string, '\n');
	if (temp)
		*temp = '\0';
	return string;
}

/*
 * Try to get a handle to a readline function from a variety of different
 * libraries.  If nothing is present on the system, then fall back to an
 * internal one.
 *
 * Logic originally based off of code in the e2fsutils package in the
 * lib/ss/get_readline.c file, which is licensed under the MIT license.
 *
 * This keeps us from having to relicense the bti codebase if readline
 * ever changes its license, as there is no link-time dependency.
 * It is a run-time thing only, and we handle any readline-like library
 * in the same manner, making bti not be a derivative work of any
 * other program.
 */
static void session_readline_init(struct session *session)
{
	/* Libraries we will try to use for readline/editline functionality */
	const char *libpath = "libreadline.so.6:libreadline.so.5:"
				"libreadline.so.4:libreadline.so:libedit.so.2:"
				"libedit.so:libeditline.so.0:libeditline.so";
	void *handle = NULL;
	char *tmp, *cp, *next;
	int (*bind_key)(int, void *);
	void (*insert)(void);

	/* default to internal function if we can't or won't find anything */
	session->readline = get_string;
	if (!isatty(0))
		return;
	session->interactive = 1;

	tmp = malloc(strlen(libpath)+1);
	if (!tmp)
		return;
	strcpy(tmp, libpath);
	for (cp = tmp; cp; cp = next) {
		next = strchr(cp, ':');
		if (next)
			*next++ = 0;
		if (*cp == 0)
			continue;
		handle = dlopen(cp, RTLD_NOW);
		if (handle) {
			dbg("Using %s for readline library\n", cp);
			break;
		}
	}
	free(tmp);
	if (!handle) {
		dbg("No readline library found.\n");
		return;
	}

	session->readline_handle = handle;
	session->readline = (char *(*)(const char *))dlsym(handle, "readline");
	if (session->readline == NULL) {
		/* something odd happened, default back to internal stuff */
		session->readline_handle = NULL;
		session->readline = get_string;
		return;
	}

	/*
	 * If we found a library, turn off filename expansion
	 * as that makes no sense from within bti.
	 */
	bind_key = (int (*)(int, void *))dlsym(handle, "rl_bind_key");
	insert = (void (*)(void))dlsym(handle, "rl_insert");
	if (bind_key && insert)
		bind_key('\t', insert);
}

static void session_readline_cleanup(struct session *session)
{
	if (session->readline_handle)
		dlclose(session->readline_handle);
}

static struct session *session_alloc(void)
{
	struct session *session;

	session = zalloc(sizeof(*session));
	if (!session)
		return NULL;
	return session;
}

static void session_free(struct session *session)
{
	if (!session)
		return;
	free(session->retweet);
	free(session->replyto);
	free(session->password);
	free(session->account);
	free(session->consumer_key);
	free(session->consumer_secret);
	free(session->access_token_key);
	free(session->access_token_secret);
	free(session->tweet);
	free(session->proxy);
	free(session->time);
	free(session->homedir);
	free(session->user);
	free(session->hosturl);
	free(session->hostname);
	free(session->configfile);
	free(session);
}

static struct bti_curl_buffer *bti_curl_buffer_alloc(enum action action)
{
	struct bti_curl_buffer *buffer;

	buffer = zalloc(sizeof(*buffer));
	if (!buffer)
		return NULL;

	/* start out with a data buffer of 1 byte to
	 * make the buffer fill logic simpler */
	buffer->data = zalloc(1);
	if (!buffer->data) {
		free(buffer);
		return NULL;
	}
	buffer->length = 0;
	buffer->action = action;
	return buffer;
}

static void bti_curl_buffer_free(struct bti_curl_buffer *buffer)
{
	if (!buffer)
		return;
	free(buffer->data);
	free(buffer);
}

const char twitter_host[]  = "https://api.twitter.com/1.1/statuses";
const char twitter_host_stream[]  = "https://stream.twitter.com/1.1/statuses"; /*this is not reset, and doesnt work */
const char twitter_host_simple[]  = "https://api.twitter.com/1.1";
const char twitter_name[]  = "twitter";

static const char twitter_request_token_uri[]  = "https://twitter.com/oauth/request_token?oauth_callback=oob";
static const char twitter_access_token_uri[]   = "https://twitter.com/oauth/access_token";
static const char twitter_authorize_uri[]      = "https://twitter.com/oauth/authorize?oauth_token=";
static const char custom_request_token_uri[]   = "/../oauth/request_token?oauth_callback=oob";
static const char custom_access_token_uri[]    = "/../oauth/access_token";
static const char custom_authorize_uri[]       = "/../oauth/authorize?oauth_token=";

static const char user_uri[]     = "/user_timeline.json";
static const char update_uri[]   = "/update.json";
static const char public_uri[]   = "/sample.json";
static const char friends_uri[]  = "/home_timeline.json";
static const char mentions_uri[] = "/mentions_timeline.json";
static const char replies_uri[]  = "/replies.xml";
static const char retweet_uri[]  = "/retweet/";
/*static const char direct_uri[]   = "/direct_messages/new.xml";*/
static const char direct_uri[]   = "/direct_messages/new.json";

static const char config_default[]	= "/etc/bti";
static const char config_xdg_default[] = ".config/bti";
static const char config_user_default[]	= ".bti";


static CURL *curl_init(void)
{
	CURL *curl;

	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Can not init CURL!\n");
		return NULL;
	}
	/* some ssl sanity checks on the connection we are making */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	return curl;
}

static void find_config_file(struct session *session)
{
	struct stat s;
	char *home;
	char *file;
	int homedir_size;

	/*
	 * Get the home directory so we can try to find a config file.
	 * If we have no home dir set up, look in /etc/bti
	 */
	home = getenv("HOME");
	if (!home) {
		/* No home dir, so take the defaults and get out of here */
		session->homedir = strdup("");
		session->configfile = strdup(config_default);
		return;
	}

	/* We have a home dir, so this might be a user */
	session->homedir = strdup(home);
	homedir_size = strlen(session->homedir);

	/*
	 * Try to find a config file, we do so in this order:
	 * ~/.bti		old-school config file
	 * ~/.config/bti	new-school config file
	 */
	file = zalloc(homedir_size + strlen(config_user_default) + 7);
	sprintf(file, "%s/%s", home, config_user_default);
	if (stat(file, &s) == 0) {
		/* Found the config file at ~/.bti */
		session->configfile = strdup(file);
		free(file);
		return;
	}

	free(file);
	file = zalloc(homedir_size + strlen(config_xdg_default) + 7);
	sprintf(file, "%s/%s", home, config_xdg_default);
	if (stat(file, &s) == 0) {
		/* config file is at ~/.config/bti */
		session->configfile = strdup(file);
		free(file);
		return;
	}

	/* No idea where the config file is, so punt */
	free(file);
	session->configfile = strdup("");
}

/* The final place data is sent to the screen/pty/tty */
static void bti_output_line(struct session *session, xmlChar *user,
			    xmlChar *id, xmlChar *created, xmlChar *text)
{
	if (session->verbose)
		printf("[%*s] {%s} (%.16s) %s\n", -session->column_output, user,
				id, created, text);
	else
		printf("[%*s] %s\n", -session->column_output, user, text);
}

static void parse_statuses(struct session *session,
			   xmlDocPtr doc, xmlNodePtr current)
{
	xmlChar *text = NULL;
	xmlChar *user = NULL;
	xmlChar *created = NULL;
	xmlChar *id = NULL;
	xmlNodePtr userinfo;

	current = current->xmlChildrenNode;
	while (current != NULL) {
		if (current->type == XML_ELEMENT_NODE) {
			if (!xmlStrcmp(current->name, (const xmlChar *)"created_at"))
				created = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
			if (!xmlStrcmp(current->name, (const xmlChar *)"text"))
				text = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
			if (!xmlStrcmp(current->name, (const xmlChar *)"id"))
				id = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
			if (!xmlStrcmp(current->name, (const xmlChar *)"user")) {
				userinfo = current->xmlChildrenNode;
				while (userinfo != NULL) {
					if ((!xmlStrcmp(userinfo->name, (const xmlChar *)"screen_name"))) {
						if (user)
							xmlFree(user);
						user = xmlNodeListGetString(doc, userinfo->xmlChildrenNode, 1);
					}
					userinfo = userinfo->next;
				}
			}

			if (user && text && created && id) {
				bti_output_line(session, user, id,
						created, text);
				xmlFree(user);
				xmlFree(text);
				xmlFree(created);
				xmlFree(id);
				user = NULL;
				text = NULL;
				created = NULL;
				id = NULL;
			}
		}
		current = current->next;
	}

	return;
}

static void parse_timeline(char *document, struct session *session)
{
	xmlDocPtr doc;
	xmlNodePtr current;

	doc = xmlReadMemory(document, strlen(document), "timeline.xml",
			    NULL, XML_PARSE_NOERROR);
	if (doc == NULL)
		return;

	current = xmlDocGetRootElement(doc);
	if (current == NULL) {
		fprintf(stderr, "empty document\n");
		xmlFreeDoc(doc);
		return;
	}

	if (xmlStrcmp(current->name, (const xmlChar *) "statuses")) {
		fprintf(stderr, "unexpected document type\n");
		xmlFreeDoc(doc);
		return;
	}

	current = current->xmlChildrenNode;
	while (current != NULL) {
		if ((!xmlStrcmp(current->name, (const xmlChar *)"status")))
			parse_statuses(session, doc, current);
		current = current->next;
	}
	xmlFreeDoc(doc);

	return;
}


/* avoids the c99 option */
#define json_object_object_foreach_alt(obj,key,val)		\
	char *key;						\
	struct json_object *val;				\
	struct lh_entry *entry;					\
	for (entry = json_object_get_object(obj)->head;		\
		({ if(entry && !is_error(entry)) {		\
			key = (char*)entry->k;			\
			val = (struct json_object*)entry->v;	\
		} ; entry; });					\
		entry = entry->next )


/* Forward Declaration */
static void json_parse(json_object * jobj, int nestlevel);

static void print_json_value(json_object *jobj, int nestlevel)
{
	enum json_type type;

	type = json_object_get_type(jobj);
	switch (type) {
	case json_type_boolean:
		printf("boolean   ");
		printf("value: %s\n", json_object_get_boolean(jobj)? "true": "false");
		break;
	case json_type_double:
		printf("double    ");
		printf("value: %lf\n", json_object_get_double(jobj));
		break;
	case json_type_int:
		printf("int       ");
		printf("value: %d\n", json_object_get_int(jobj));
		break;
	case json_type_string:
		printf("string    ");
		printf("value: %s\n", json_object_get_string(jobj));
		break;
	default:
		break;
	}
}

#define MAXKEYSTACK 20
char *keystack[MAXKEYSTACK];

static void json_parse_array(json_object *jobj, char *key, int nestlevel)
{
	enum json_type type;

	nestlevel++;
	/* Simply get the array */
	json_object *jarray = jobj;
	if (key) {
		/* Get the array if it is a key value pair */
		jarray = json_object_object_get(jobj, key);
	}

	/* Get the length of the array */
	int arraylen = json_object_array_length(jarray);
	if (debug)
		printf("Array Length: %d\n",arraylen);
	int i;
	json_object *jvalue;

	for (i = 0; i < arraylen; i++) {
		if (debug) {
			int j;
			for (j=0; j < nestlevel; ++j)
				printf("  ");
			printf("element[%d]\n",i);
		}

		/* Get the array element at position i */
		jvalue = json_object_array_get_idx(jarray, i);
		type = json_object_get_type(jvalue);
		if (type == json_type_array) {
			json_parse_array(jvalue, NULL, nestlevel);
		} else if (type != json_type_object) {
			if (debug) {
				printf("value[%d]: ", i);
				print_json_value(jvalue,nestlevel);
			}
		} else {
			/* printf("obj: "); */
			keystack[nestlevel%MAXKEYSTACK]="[]";
			json_parse(jvalue,nestlevel);
		}
	}
}


struct results {
	int code;
	char *message;
} results;

struct session *store_session;
struct tweetdetail {
	char *id;
	char *text;
	char *screen_name;
	char *created_at;
} tweetdetail;

static void json_interpret(json_object *jobj, int nestlevel)
{
	if (nestlevel == 3 &&
	    strcmp(keystack[1], "errors") == 0 &&
	    strcmp(keystack[2], "[]") == 0) {
		if (strcmp(keystack[3], "message") == 0) {
			if (json_object_get_type(jobj) == json_type_string)
				results.message = (char *)json_object_get_string(jobj);
		}
		if (strcmp(keystack[3], "code") == 0) {
			if (json_object_get_type(jobj) == json_type_int)
				results.code = json_object_get_int(jobj);
		}
	}

	if (nestlevel >= 2 &&
	    strcmp(keystack[1],"[]") == 0) {
		if (strcmp(keystack[2], "created_at") == 0) {
			if (debug)
				printf("%s : %s\n", keystack[2], json_object_get_string(jobj));
			tweetdetail.created_at = (char *)json_object_get_string(jobj);
		}
		if (strcmp(keystack[2], "text") == 0) {
			if (debug)
				printf("%s : %s\n", keystack[2], json_object_get_string(jobj));
			tweetdetail.text = (char *)json_object_get_string(jobj);
		}
		if (strcmp(keystack[2], "id") == 0) {
			if (debug)
				printf("%s : %s\n", keystack[2], json_object_get_string(jobj));
			tweetdetail.id = (char *)json_object_get_string(jobj);
		}
		if (nestlevel >= 3 &&
		    strcmp(keystack[2], "user") == 0) {
			if (strcmp(keystack[3], "screen_name") == 0) {
				if (debug)
					printf("%s->%s : %s\n", keystack[2], keystack[3], json_object_get_string(jobj));
				tweetdetail.screen_name=(char *)json_object_get_string(jobj);
				bti_output_line(store_session,
						(xmlChar *)tweetdetail.screen_name,
						(xmlChar *)tweetdetail.id,
						(xmlChar *)tweetdetail.created_at,
						(xmlChar *)tweetdetail.text);
				}
		}
	}
}

/* Parsing the json object */
static void json_parse(json_object * jobj, int nestlevel)
{
	int i;

	if (jobj==NULL) {
		fprintf(stderr,"jobj null\n");
		return;
	}
	nestlevel++;
	enum json_type type;
	json_object_object_foreach_alt(jobj, key, val) {
		/* work around pre10 */
		if (val)
			type = json_object_get_type(val);
		else
			type=json_type_null;
		if (debug)
			for (i = 0; i < nestlevel; ++i)
				printf("  ");
		if (debug)
			printf("key %-34s ", key);
		if (debug)
			for (i = 0; i < 8 - nestlevel; ++i)
				printf("  ");
		switch (type) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			if (debug) print_json_value(val,nestlevel);
			if (debug) for (i=0; i<nestlevel+1; ++i) printf("  ");
			if (debug) printf("(");
			if (debug) for (i=1; i<nestlevel; ++i) { printf("%s->",keystack[i]); }
			if (debug) printf("%s)\n",key);
			keystack[nestlevel%MAXKEYSTACK] = key;
			json_interpret(val,nestlevel);
			break;
		case json_type_object:
			if (debug) printf("json_type_object\n");
			keystack[nestlevel%MAXKEYSTACK] = key;
			json_parse(json_object_object_get(jobj, key), nestlevel);
			break;
		case json_type_array:
			if (debug) printf("json_type_array, ");
			keystack[nestlevel%MAXKEYSTACK] = key;
			json_parse_array(jobj, key, nestlevel);
			break;
		case json_type_null:
			if (debug) printf("null\n");
			break;
		default:
			if (debug) printf("\n");
			break;
		}
	}
}

static int parse_response_json(char *document, struct session *session)
{
	dbg("Got this json response:\n");
	dbg("%s\n",document);

	results.code=0;
	results.message=NULL;
	json_object *jobj = json_tokener_parse(document);

	/* make global for now */
	store_session = session;
	if (!is_error(jobj)) {
		/* guards against a json pre 0.10 bug */
		json_parse(jobj,0);
	}
	if (results.code && results.message != NULL) {
		if (debug)
			printf("Got an error code:\n  code=%d\n  message=%s\n",
				results.code, results.message);
		fprintf(stderr, "error condition detected: %d = %s\n",
			results.code, results.message);
		return -EIO;
	}
	return 0;
}

static void parse_timeline_json(char *document, struct session *session)
{
	dbg("Got this json response:\n");
	dbg("%s\n",document);
	results.code = 0;
	results.message = NULL;
	json_object *jobj = json_tokener_parse(document);

	/* make global for now */
	store_session = session;
	if (!is_error(jobj)) {
		/* guards against a json pre 0.10 bug */
		if (json_object_get_type(jobj)==json_type_array) {
			json_parse_array(jobj, NULL, 0);
		} else {
			json_parse(jobj,0);
		}
	}
	if (results.code && results.message != NULL) {
		if (debug)
			printf("Got an error code:\n  code=%d\n  message=%s\n",
				results.code, results.message);
		fprintf(stderr, "error condition detected: %d = %s\n",
			results.code, results.message);
	}
}

static size_t curl_callback(void *buffer, size_t size, size_t nmemb,
			    void *userp)
{
	struct bti_curl_buffer *curl_buf = userp;
	size_t buffer_size = size * nmemb;
	char *temp;

	if ((!buffer) || (!buffer_size) || (!curl_buf))
		return -EINVAL;

	/* add to the data we already have */
	temp = zalloc(curl_buf->length + buffer_size + 1);
	if (!temp)
		return -ENOMEM;

	memcpy(temp, curl_buf->data, curl_buf->length);
	free(curl_buf->data);
	curl_buf->data = temp;
	memcpy(&curl_buf->data[curl_buf->length], (char *)buffer, buffer_size);
	curl_buf->length += buffer_size;
	if (curl_buf->action)
		parse_timeline(curl_buf->data, curl_buf->session);

	dbg("%s\n", curl_buf->data);

	return buffer_size;
}

static int parse_osp_reply(const char *reply, char **token, char **secret)
{
	int rc;
	int retval = 1;
	char **rv = NULL;
	rc = oauth_split_url_parameters(reply, &rv);
	qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
	if (rc == 2 || rc == 4 || rc == 5) {
		if (!strncmp(rv[0], "oauth_token=", 11) &&
		    !strncmp(rv[1], "oauth_token_secret=", 18)) {
			if (token)
				*token = strdup(&(rv[0][12]));
			if (secret)
				*secret = strdup(&(rv[1][19]));

			retval = 0;
		}
	} else if (rc == 3) {
		if (!strncmp(rv[1], "oauth_token=", 11) &&
		    !strncmp(rv[2], "oauth_token_secret=", 18)) {
			if (token)
				*token = strdup(&(rv[1][12]));
			if (secret)
				*secret = strdup(&(rv[2][19]));

			retval = 0;
		}
	}

	dbg("token: %s\n", *token);
	dbg("secret: %s\n", *secret);

	if (rv)
		free(rv);

	return retval;
}

static int request_access_token(struct session *session)
{
	char *post_params = NULL;
	char *request_url = NULL;
	char *reply       = NULL;
	char *at_key      = NULL;
	char *at_secret   = NULL;
	char *verifier    = NULL;
	char at_uri[90];
	char token_uri[90];

	if (!session)
		return -EINVAL;

	if (session->host == HOST_TWITTER)
		request_url = oauth_sign_url2(
				twitter_request_token_uri, NULL,
				OA_HMAC, NULL, session->consumer_key,
				session->consumer_secret, NULL, NULL);
	else {
		sprintf(token_uri, "%s%s",
			session->hosturl, custom_request_token_uri);
		request_url = oauth_sign_url2(
				token_uri, NULL,
				OA_HMAC, NULL, session->consumer_key,
				session->consumer_secret, NULL, NULL);
	}
	reply = oauth_http_get(request_url, post_params);

	if (request_url)
		free(request_url);

	if (post_params)
		free(post_params);

	if (!reply)
		return 1;

	if (parse_osp_reply(reply, &at_key, &at_secret))
		return 1;

	free(reply);

	fprintf(stdout,
		"Please open the following link in your browser, and "
		"allow 'bti' to access your account. Then paste "
		"back the provided PIN in here.\n");
	if (session->host == HOST_TWITTER) {
		fprintf(stdout, "%s%s\nPIN: ", twitter_authorize_uri, at_key);
		verifier = session->readline(NULL);
		sprintf(at_uri, "%s?oauth_verifier=%s",
			twitter_access_token_uri, verifier);
	} else {
		fprintf(stdout, "%s%s%s\nPIN: ",
			session->hosturl, custom_authorize_uri, at_key);
		verifier = session->readline(NULL);
		sprintf(at_uri, "%s%s?oauth_verifier=%s",
			session->hosturl, custom_access_token_uri, verifier);
	}
	request_url = oauth_sign_url2(at_uri, NULL, OA_HMAC, NULL,
				      session->consumer_key,
				      session->consumer_secret,
				      at_key, at_secret);
	reply = oauth_http_get(request_url, post_params);

	if (!reply)
		return 1;

	if (parse_osp_reply(reply, &at_key, &at_secret))
		return 1;

	free(reply);

	fprintf(stdout,
		"Please put these two lines in your bti "
		"configuration file (%s):\n"
		"access_token_key=%s\n"
		"access_token_secret=%s\n",
		session->configfile, at_key, at_secret);

	return 0;
}

static int send_request(struct session *session)
{
	const int endpoint_size = 2000;
	char endpoint[endpoint_size];
	char user_password[500];
	char data[500];
	struct bti_curl_buffer *curl_buf;
	CURL *curl = NULL;
	CURLcode res;
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *slist = NULL;
	char *req_url = NULL;
	char *reply = NULL;
	char *postarg = NULL;
	char *escaped_tweet = NULL;
	int is_post = 0;

	if (!session)
		return -EINVAL;

	if (!session->hosturl)
		session->hosturl = strdup(twitter_host);

	if (session->no_oauth || session->guest) {
		curl_buf = bti_curl_buffer_alloc(session->action);
		if (!curl_buf)
			return -ENOMEM;
		curl_buf->session = session;

		curl = curl_init();
		if (!curl) {
			bti_curl_buffer_free(curl_buf);
			return -EINVAL;
		}

		if (!session->hosturl)
			session->hosturl = strdup(twitter_host);

		switch (session->action) {
		case ACTION_UPDATE:
			snprintf(user_password, sizeof(user_password), "%s:%s",
				 session->account, session->password);
			snprintf(data, sizeof(data), "status=\"%s\"",
				 session->tweet);
			curl_formadd(&formpost, &lastptr,
				     CURLFORM_COPYNAME, "status",
				     CURLFORM_COPYCONTENTS, session->tweet,
				     CURLFORM_END);

			curl_formadd(&formpost, &lastptr,
				     CURLFORM_COPYNAME, "source",
				     CURLFORM_COPYCONTENTS, "bti",
				     CURLFORM_END);

			if (session->replyto)
				curl_formadd(&formpost, &lastptr,
					     CURLFORM_COPYNAME,
					     "in_reply_to_status_id",
					     CURLFORM_COPYCONTENTS,
					     session->replyto,
					     CURLFORM_END);

			curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
			slist = curl_slist_append(slist, "Expect:");
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

			snprintf(endpoint, endpoint_size, "%s%s", session->hosturl, update_uri);
			curl_easy_setopt(curl, CURLOPT_URL, endpoint);
			curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);
			break;

		case ACTION_FRIENDS:
			snprintf(user_password, sizeof(user_password), "%s:%s",
				 session->account, session->password);
			snprintf(endpoint, endpoint_size, "%s%s?page=%d", session->hosturl,
					friends_uri, session->page);
			curl_easy_setopt(curl, CURLOPT_URL, endpoint);
			curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);
			break;

		case ACTION_USER:
			snprintf(endpoint, endpoint_size, "%s%s%s.xml?page=%d", session->hosturl,
				user_uri, session->user, session->page);
			curl_easy_setopt(curl, CURLOPT_URL, endpoint);
			break;

		case ACTION_REPLIES:
			snprintf(user_password, sizeof(user_password), "%s:%s",
				 session->account, session->password);
			snprintf(endpoint, endpoint_size, "%s%s?page=%d", session->hosturl,
				replies_uri, session->page);
			curl_easy_setopt(curl, CURLOPT_URL, endpoint);
			curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);
			break;

		case ACTION_PUBLIC:
			/*snprintf(endpoint, endpoint_size, "%s%s?page=%d", session->hosturl,*/
			snprintf(endpoint, endpoint_size, "%s%s", twitter_host_stream,
				public_uri);
			curl_easy_setopt(curl, CURLOPT_URL, endpoint);
			break;

		case ACTION_DIRECT:
		    /* NOT IMPLEMENTED - twitter requires authentication anyway */
			break;

		default:
			break;
		}

		if (session->proxy)
			curl_easy_setopt(curl, CURLOPT_PROXY, session->proxy);

		if (debug)
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

		dbg("user_password = %s\n", user_password);
		dbg("data = %s\n", data);
		dbg("proxy = %s\n", session->proxy);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl_buf);
		if (!session->dry_run) {
			res = curl_easy_perform(curl);
			if (!session->background) {
				xmlDocPtr doc;
				xmlNodePtr current;

				if (res) {
					fprintf(stderr,
						"error(%d) trying to perform operation\n",
						res);
					curl_easy_cleanup(curl);
					if (session->action == ACTION_UPDATE)
						curl_formfree(formpost);
					bti_curl_buffer_free(curl_buf);
					return -EINVAL;
				}

				doc = xmlReadMemory(curl_buf->data,
						    curl_buf->length,
						    "response.xml", NULL,
						    XML_PARSE_NOERROR);
				if (doc == NULL) {
					curl_easy_cleanup(curl);
					if (session->action == ACTION_UPDATE)
						curl_formfree(formpost);
					bti_curl_buffer_free(curl_buf);
					return -EINVAL;
				}

				current = xmlDocGetRootElement(doc);
				if (current == NULL) {
					fprintf(stderr, "empty document\n");
					xmlFreeDoc(doc);
					curl_easy_cleanup(curl);
					if (session->action == ACTION_UPDATE)
						curl_formfree(formpost);
					bti_curl_buffer_free(curl_buf);
					return -EINVAL;
				}

				if (xmlStrcmp(current->name, (const xmlChar *)"status")) {
					fprintf(stderr, "unexpected document type\n");
					xmlFreeDoc(doc);
					curl_easy_cleanup(curl);
					if (session->action == ACTION_UPDATE)
						curl_formfree(formpost);
					bti_curl_buffer_free(curl_buf);
					return -EINVAL;
				}

				xmlFreeDoc(doc);
			}
		}

		curl_easy_cleanup(curl);
		if (session->action == ACTION_UPDATE)
			curl_formfree(formpost);
		bti_curl_buffer_free(curl_buf);
	} else {
		switch (session->action) {
		case ACTION_UPDATE:
			/* dont test it here, let twitter return an error that we show */
			if (strlen_utf8(session->tweet) > 140 + 1000 ) {
				printf("E: tweet is too long!\n");
				goto skip_tweet;
			}

			/* TODO: add tweet crunching function. */
			escaped_tweet = oauth_url_escape(session->tweet);
			if (session->replyto) {
				sprintf(endpoint,
					"%s%s?status=%s&in_reply_to_status_id=%s",
					session->hosturl, update_uri,
					escaped_tweet, session->replyto);
			} else {
				sprintf(endpoint, "%s%s?status=%s",
					session->hosturl, update_uri,
					escaped_tweet);
			}

			is_post = 1;
			break;
		case ACTION_USER:
			sprintf(endpoint, "%s%s?screen_name=%s&page=%d",
				session->hosturl, user_uri, session->user,
				session->page);
			break;
		case ACTION_REPLIES:
			sprintf(endpoint, "%s%s?page=%d", session->hosturl,
				mentions_uri, session->page);
			break;
		case ACTION_PUBLIC:
			sprintf(endpoint, "%s%s", twitter_host_stream,
				public_uri);
			break;
		case ACTION_FRIENDS:
			sprintf(endpoint, "%s%s?page=%d", session->hosturl,
				friends_uri, session->page);
			break;
		case ACTION_RETWEET:
			sprintf(endpoint, "%s%s%s.xml", session->hosturl,
				retweet_uri, session->retweet);
			is_post = 1;
			break;
		case ACTION_DIRECT:
			escaped_tweet = oauth_url_escape(session->tweet);
			sprintf(endpoint, "%s%s?user=%s&text=%s", twitter_host_simple,
				direct_uri, session->user, escaped_tweet);
			is_post = 1;
			break;
		default:
			break;
		}

		dbg("%s\n", endpoint);
		if (!session->dry_run) {
			if (is_post) {
				req_url = oauth_sign_url2(endpoint, &postarg, OA_HMAC,
							  NULL, session->consumer_key,
							  session->consumer_secret,
							  session->access_token_key,
							  session->access_token_secret);
				reply = oauth_http_post(req_url, postarg);
			} else {
				req_url = oauth_sign_url2(endpoint, NULL, OA_HMAC, NULL,
							  session->consumer_key,
							  session->consumer_secret,
							  session->access_token_key,
							  session->access_token_secret);
				reply = oauth_http_get(req_url, postarg);
			}

			dbg("req_url:%s\n", req_url);
			dbg("reply:%s\n", reply);
			if (req_url)
				free(req_url);

			if (!reply) {
				fprintf(stderr, "Error retrieving from URL (%s)\n", endpoint);
				return -EIO;
			}

			if ((session->action != ACTION_UPDATE) &&
					(session->action != ACTION_RETWEET) &&
					(session->action != ACTION_DIRECT))
				parse_timeline_json(reply, session);

			if ((session->action == ACTION_UPDATE) ||
					(session->action == ACTION_DIRECT))
				/*return parse_response_xml(reply, session);*/
				return parse_response_json(reply, session);
		}

		skip_tweet: ;

	}
	return 0;
}

static void log_session(struct session *session, int retval)
{
	FILE *log_file;
	char *filename;

	/* Only log something if we have a log file set */
	if (!session->logfile)
		return;

	filename = alloca(strlen(session->homedir) +
			  strlen(session->logfile) + 3);

	sprintf(filename, "%s/%s", session->homedir, session->logfile);

	log_file = fopen(filename, "a+");
	if (log_file == NULL)
		return;

	switch (session->action) {
	case ACTION_UPDATE:
		if (retval)
			fprintf(log_file, "%s: host=%s tweet failed\n",
				session->time, session->hostname);
		else
			fprintf(log_file, "%s: host=%s tweet=%s\n",
				session->time, session->hostname,
				session->tweet);
		break;
	case ACTION_FRIENDS:
		fprintf(log_file, "%s: host=%s retrieving friends timeline\n",
			session->time, session->hostname);
		break;
	case ACTION_USER:
		fprintf(log_file, "%s: host=%s retrieving %s's timeline\n",
			session->time, session->hostname, session->user);
		break;
	case ACTION_REPLIES:
		fprintf(log_file, "%s: host=%s retrieving replies\n",
			session->time, session->hostname);
		break;
	case ACTION_PUBLIC:
		fprintf(log_file, "%s: host=%s retrieving public timeline\n",
			session->time, session->hostname);
		break;
	case ACTION_DIRECT:
		if (retval)
			fprintf(log_file, "%s: host=%s tweet failed\n",
				session->time, session->hostname);
		else
			fprintf(log_file, "%s: host=%s tweet=%s\n",
				session->time, session->hostname,
				session->tweet);
		break;
	default:
		break;
	}

	fclose(log_file);
}

static char *get_string_from_stdin(void)
{
	char *temp;
	char *string;

	string = zalloc(1000);
	if (!string)
		return NULL;

	if (!fgets(string, 999, stdin)) {
		free(string);
		return NULL;
	}
	temp = strchr(string, '\n');
	if (temp)
		*temp = '\0';
	return string;
}

static void read_password(char *buf, size_t len, char *host)
{
	char pwd[80];
	struct termios old;
	struct termios tp;

	tcgetattr(0, &tp);
	old = tp;

	tp.c_lflag &= (~ECHO);
	tcsetattr(0, TCSANOW, &tp);

	fprintf(stdout, "Enter password for %s: ", host);
	fflush(stdout);
	tcflow(0, TCOOFF);

	/*
	 * I'd like to do something with the return value here, but really,
	 * what can be done?
	 */
	(void)scanf("%79s", pwd);

	tcflow(0, TCOON);
	fprintf(stdout, "\n");

	tcsetattr(0, TCSANOW, &old);

	strncpy(buf, pwd, len);
	buf[len-1] = '\0';
}

static int find_urls(const char *tweet, int **pranges)
{
	/*
	 * magic obtained from
	 * http://www.geekpedia.com/KB65_How-to-validate-an-URL-using-RegEx-in-Csharp.html
	 */
	static const char *re_magic =
		"(([a-zA-Z][0-9a-zA-Z+\\-\\.]*:)/{1,3}"
		"[0-9a-zA-Z;/~?:@&=+$\\.\\-_'()%]+)"
		"(#[0-9a-zA-Z;/?:@&=+$\\.\\-_!~*'()%]+)?";
	pcre *re;
	const char *errptr;
	int erroffset;
	int ovector[10] = {0,};
	const size_t ovsize = sizeof(ovector)/sizeof(*ovector);
	int startoffset, tweetlen;
	int i, rc;
	int rbound = 10;
	int rcount = 0;
	int *ranges = malloc(sizeof(int) * rbound);

	re = pcre_compile(re_magic,
			PCRE_NO_AUTO_CAPTURE,
			&errptr, &erroffset, NULL);
	if (!re) {
		fprintf(stderr, "pcre_compile @%u: %s\n", erroffset, errptr);
		exit(1);
	}

	tweetlen = strlen(tweet);
	for (startoffset = 0; startoffset < tweetlen; ) {

		rc = pcre_exec(re, NULL, tweet, strlen(tweet), startoffset, 0,
				ovector, ovsize);
		if (rc == PCRE_ERROR_NOMATCH)
			break;

		if (rc < 0) {
			fprintf(stderr, "pcre_exec @%u: %s\n",
				erroffset, errptr);
			exit(1);
		}

		for (i = 0; i < rc; i += 2) {
			if ((rcount+2) == rbound) {
				rbound *= 2;
				ranges = realloc(ranges, sizeof(int) * rbound);
			}

			ranges[rcount++] = ovector[i];
			ranges[rcount++] = ovector[i+1];
		}

		startoffset = ovector[1];
	}

	pcre_free(re);

	*pranges = ranges;
	return rcount;
}

/**
 * bidirectional popen() call
 *
 * @param rwepipe - int array of size three
 * @param exe - program to run
 * @param argv - argument list
 * @return pid or -1 on error
 *
 * The caller passes in an array of three integers (rwepipe), on successful
 * execution it can then write to element 0 (stdin of exe), and read from
 * element 1 (stdout) and 2 (stderr).
 */
static int popenRWE(int *rwepipe, const char *exe, const char *const argv[])
{
	int in[2];
	int out[2];
	int err[2];
	int pid;
	int rc;

	rc = pipe(in);
	if (rc < 0)
		goto error_in;

	rc = pipe(out);
	if (rc < 0)
		goto error_out;

	rc = pipe(err);
	if (rc < 0)
		goto error_err;

	pid = fork();
	if (pid > 0) {
		/* parent */
		close(in[0]);
		close(out[1]);
		close(err[1]);
		rwepipe[0] = in[1];
		rwepipe[1] = out[0];
		rwepipe[2] = err[0];
		return pid;
	} else if (pid == 0) {
		/* child */
		close(in[1]);
		close(out[0]);
		close(err[0]);
		close(0);
		rc = dup(in[0]);
		close(1);
		rc = dup(out[1]);
		close(2);
		rc = dup(err[1]);

		execvp(exe, (char **)argv);
		exit(1);
	} else
		goto error_fork;

	return pid;

error_fork:
	close(err[0]);
	close(err[1]);
error_err:
	close(out[0]);
	close(out[1]);
error_out:
	close(in[0]);
	close(in[1]);
error_in:
	return -1;
}

static int pcloseRWE(int pid, int *rwepipe)
{
	int status;
	close(rwepipe[0]);
	close(rwepipe[1]);
	close(rwepipe[2]);
	(void)waitpid(pid, &status, 0);
	return status;
}

static char *shrink_one_url(int *rwepipe, char *big)
{
	int biglen = strlen(big);
	char *small;
	int smalllen;
	int rc;

	rc = dprintf(rwepipe[0], "%s\n", big);
	if (rc < 0)
		return big;

	smalllen = biglen + 128;
	small = malloc(smalllen);
	if (!small)
		return big;

	rc = read(rwepipe[1], small, smalllen);
	if (rc < 0 || rc > biglen)
		goto error_free_small;

	if (strncmp(small, "http://", 7))
		goto error_free_small;

	smalllen = rc;
	while (smalllen && isspace(small[smalllen-1]))
			small[--smalllen] = 0;

	free(big);
	return small;

error_free_small:
	free(small);
	return big;
}

static char *shrink_urls(char *text)
{
	int *ranges;
	int rcount;
	int i;
	int inofs = 0;
	int outofs = 0;
	const char *const shrink_args[] = {
		"bti-shrink-urls",
		NULL
	};
	int shrink_pid;
	int shrink_pipe[3];
	int inlen = strlen(text);

	dbg("before len=%u\n", inlen);

	shrink_pid = popenRWE(shrink_pipe, shrink_args[0], shrink_args);
	if (shrink_pid < 0)
		return text;

	rcount = find_urls(text, &ranges);
	if (!rcount)
		return text;

	for (i = 0; i < rcount; i += 2) {
		int url_start = ranges[i];
		int url_end = ranges[i+1];
		int long_url_len = url_end - url_start;
		char *url = strndup(text + url_start, long_url_len);
		int short_url_len;
		int not_url_len = url_start - inofs;

		dbg("long  url[%u]: %s\n", long_url_len, url);
		url = shrink_one_url(shrink_pipe, url);
		short_url_len = url ? strlen(url) : 0;
		dbg("short url[%u]: %s\n", short_url_len, url);

		if (!url || short_url_len >= long_url_len) {
			/* The short url ended up being too long
			 * or unavailable */
			if (inofs) {
				strncpy(text + outofs, text + inofs,
						not_url_len + long_url_len);
			}
			inofs += not_url_len + long_url_len;
			outofs += not_url_len + long_url_len;

		} else {
			/* copy the unmodified block */
			strncpy(text + outofs, text + inofs, not_url_len);
			inofs += not_url_len;
			outofs += not_url_len;

			/* copy the new url */
			strncpy(text + outofs, url, short_url_len);
			inofs += long_url_len;
			outofs += short_url_len;
		}

		free(url);
	}

	/* copy the last block after the last match */
	if (inofs) {
		int tail = inlen - inofs;
		if (tail) {
			strncpy(text + outofs, text + inofs, tail);
			outofs += tail;
		}
	}

	free(ranges);

	(void)pcloseRWE(shrink_pid, shrink_pipe);

	text[outofs] = 0;
	dbg("after len=%u\n", outofs);
	return text;
}

int main(int argc, char *argv[], char *envp[])
{
	static const struct option options[] = {
		{ "debug", 0, NULL, 'd' },
		{ "verbose", 0, NULL, 'V' },
		{ "account", 1, NULL, 'a' },
		{ "password", 1, NULL, 'p' },
		{ "host", 1, NULL, 'H' },
		{ "proxy", 1, NULL, 'P' },
		{ "action", 1, NULL, 'A' },
		{ "user", 1, NULL, 'u' },
		{ "logfile", 1, NULL, 'L' },
		{ "shrink-urls", 0, NULL, 's' },
		{ "help", 0, NULL, 'h' },
		{ "bash", 0, NULL, 'b' },
		{ "background", 0, NULL, 'B' },
		{ "dry-run", 0, NULL, 'n' },
		{ "page", 1, NULL, 'g' },
		{ "column", 1, NULL, 'o' },
		{ "version", 0, NULL, 'v' },
		{ "config", 1, NULL, 'c' },
		{ "replyto", 1, NULL, 'r' },
		{ "retweet", 1, NULL, 'w' },
		{ }
	};
	struct stat s;
	struct session *session;
	pid_t child;
	char *tweet;
	static char password[80];
	int retval = 0;
	int option;
	char *http_proxy;
	time_t t;
	int page_nr;

	debug = 0;

	session = session_alloc();
	if (!session) {
		fprintf(stderr, "no more memory...\n");
		return -1;
	}

	/* get the current time so that we can log it later */
	time(&t);
	session->time = strdup(ctime(&t));
	session->time[strlen(session->time)-1] = 0x00;

	find_config_file(session);

	/* Set environment variables first, before reading command line options
	 * or config file values. */
	http_proxy = getenv("http_proxy");
	if (http_proxy) {
		if (session->proxy)
			free(session->proxy);
		session->proxy = strdup(http_proxy);
		dbg("http_proxy = %s\n", session->proxy);
	}

	bti_parse_configfile(session);

	while (1) {
		option = getopt_long_only(argc, argv,
					  "dp:P:H:a:A:u:c:hg:o:G:sr:nVvw:",
					  options, NULL);
		if (option == -1)
			break;
		switch (option) {
		case 'd':
			debug = 1;
			break;
		case 'V':
			session->verbose = 1;
			break;
		case 'a':
			if (session->account)
				free(session->account);
			session->account = strdup(optarg);
			dbg("account = %s\n", session->account);
			break;
		case 'g':
			page_nr = atoi(optarg);
			dbg("page = %d\n", page_nr);
			session->page = page_nr;
			break;
		case 'o':
			session->column_output = atoi(optarg);
			dbg("column_output = %d\n", session->column_output);
			break;
		case 'r':
			session->replyto = strdup(optarg);
			dbg("in_reply_to_status_id = %s\n", session->replyto);
			break;
		case 'w':
			session->retweet = strdup(optarg);
			dbg("Retweet ID = %s\n", session->retweet);
			break;
		case 'p':
			if (session->password)
				free(session->password);
			session->password = strdup(optarg);
			dbg("password = %s\n", session->password);
			break;
		case 'P':
			if (session->proxy)
				free(session->proxy);
			session->proxy = strdup(optarg);
			dbg("proxy = %s\n", session->proxy);
			break;
		case 'A':
			if (strcasecmp(optarg, "update") == 0)
				session->action = ACTION_UPDATE;
			else if (strcasecmp(optarg, "friends") == 0)
				session->action = ACTION_FRIENDS;
			else if (strcasecmp(optarg, "user") == 0)
				session->action = ACTION_USER;
			else if (strcasecmp(optarg, "replies") == 0)
				session->action = ACTION_REPLIES;
			else if (strcasecmp(optarg, "public") == 0)
				session->action = ACTION_PUBLIC;
			else if (strcasecmp(optarg, "retweet") == 0)
				session->action = ACTION_RETWEET;
			else if (strcasecmp(optarg, "direct") == 0)
				session->action = ACTION_DIRECT;
			else
				session->action = ACTION_UNKNOWN;
			dbg("action = %d\n", session->action);
			break;
		case 'u':
			if (session->user)
				free(session->user);
			session->user = strdup(optarg);
			dbg("user = %s\n", session->user);
			break;

		case 'L':
			if (session->logfile)
				free(session->logfile);
			session->logfile = strdup(optarg);
			dbg("logfile = %s\n", session->logfile);
			break;
		case 's':
			session->shrink_urls = 1;
			break;
		case 'H':
			if (session->hosturl)
				free(session->hosturl);
			if (session->hostname)
				free(session->hostname);
			if (strcasecmp(optarg, "twitter") == 0) {
				session->host = HOST_TWITTER;
				session->hosturl = strdup(twitter_host);
				session->hostname = strdup(twitter_name);
			} else {
				session->host = HOST_CUSTOM;
				session->hosturl = strdup(optarg);
				session->hostname = strdup(optarg);
			}
			dbg("host = %d\n", session->host);
			break;
		case 'b':
			session->bash = 1;
			/* fall-through intended */
		case 'B':
			session->background = 1;
			break;
		case 'c':
			if (session->configfile)
				free(session->configfile);
			session->configfile = strdup(optarg);
			dbg("configfile = %s\n", session->configfile);
			if (stat(session->configfile, &s) == -1) {
				fprintf(stderr,
					"Config file '%s' is not found.\n",
					session->configfile);
				goto exit;
			}

			/*
			 * read the config file now.  Yes, this could override
			 * previously set options from the command line, but
			 * the user asked for it...
			 */
			bti_parse_configfile(session);
			break;
		case 'h':
			display_help();
			goto exit;
		case 'n':
			session->dry_run = 1;
			break;
		case 'v':
			display_version();
			goto exit;
		default:
			display_help();
			goto exit;
		}
	}

	session_readline_init(session);
	/*
	 * Show the version to make it easier to determine what
	 * is going on here
	 */
	if (debug)
		display_version();

	if (session->host == HOST_TWITTER) {
		if (!session->consumer_key || !session->consumer_secret) {
			if (session->action == ACTION_USER ||
					session->action == ACTION_PUBLIC) {
				/*
				 * Some actions may still work without
				 * authentication
				 */
				session->guest = 1;
			} else {
				fprintf(stderr,
						"Twitter no longer supports HTTP basic authentication.\n"
						"Both consumer key, and consumer secret are required"
						" for bti in order to behave as an OAuth consumer.\n");
				goto exit;
			}
		}
	} else {
		if (!session->consumer_key || !session->consumer_secret)
			session->no_oauth = 1;
	}

	if (session->no_oauth) {
		if (!session->account) {
			fprintf(stdout, "Enter account for %s: ",
				session->hostname);
			session->account = session->readline(NULL);
		}
		if (!session->password) {
			read_password(password, sizeof(password),
				      session->hostname);
			session->password = strdup(password);
		}
	} else if (!session->guest) {
		if (!session->access_token_key ||
		    !session->access_token_secret) {
			request_access_token(session);
			goto exit;
		}
	}

	if (session->action == ACTION_UNKNOWN) {
		fprintf(stderr, "Unknown action, valid actions are:\n"
			"'update', 'friends', 'public', 'replies', 'user' or 'direct'.\n");
		goto exit;
	}

	if (session->action == ACTION_RETWEET) {
		if (!session->retweet) {
			char *rtid;

			fprintf(stdout, "Status ID to retweet: ");
			rtid = get_string_from_stdin();
			session->retweet = zalloc(strlen(rtid) + 10);
			sprintf(session->retweet, "%s", rtid);
			free(rtid);
		}

		if (!session->retweet || strlen(session->retweet) == 0) {
			dbg("no retweet?\n");
			return -1;
		}

		dbg("retweet ID = %s\n", session->retweet);
	}

	if (session->action == ACTION_UPDATE || session->action == ACTION_DIRECT) {
		if (session->background || !session->interactive)
			tweet = get_string_from_stdin();
		else
			tweet = session->readline("tweet: ");
		if (!tweet || strlen(tweet) == 0) {
			dbg("no tweet?\n");
			return -1;
		}

		if (session->shrink_urls)
			tweet = shrink_urls(tweet);

		session->tweet = zalloc(strlen(tweet) + 10);
		if (session->bash)
			sprintf(session->tweet, "%c %s",
				getuid() ? '$' : '#', tweet);
		else
			sprintf(session->tweet, "%s", tweet);

		free(tweet);
		dbg("tweet = %s\n", session->tweet);
	}

	if (session->page == 0)
		session->page = 1;
	dbg("config file = %s\n", session->configfile);
	dbg("host = %d\n", session->host);
	dbg("action = %d\n", session->action);

	/* fork ourself so that the main shell can get on
	 * with it's life as we try to connect and handle everything
	 */
	if (session->background) {
		child = fork();
		if (child) {
			dbg("child is %d\n", child);
			exit(0);
		}
	}

	retval = send_request(session);
	if (retval && !session->background)
		fprintf(stderr, "operation failed\n");

	log_session(session, retval);
exit:
	session_readline_cleanup(session);
	session_free(session);
	return retval;
}
