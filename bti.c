/*
 * Copyright (C) 2008 Greg Kroah-Hartman <greg@kroah.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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
#include <curl/curl.h>
#include <readline/readline.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "bti_version.h"


#define zalloc(size)	calloc(size, 1)

#define dbg(format, arg...)						\
	do {								\
		if (debug)						\
			printf("%s: " format , __func__ , ## arg);	\
	} while (0)


static int debug;

enum host {
	HOST_TWITTER = 0,
	HOST_IDENTICA = 1,
};

enum action {
     ACTION_UPDATE = 0,
     ACTION_PUBLIC = 1,
     ACTION_FRIENDS = 2,
};

struct session {
	char *password;
	char *account;
	char *tweet;
	char *proxy;
	char *time;
	char *homedir;
	char *logfile;
	int bash;
	enum host host;
	enum action action;
};

struct bti_curl_buffer {
	char *data;
	enum action action;
	int length;
};

static void display_help(void)
{
	fprintf(stdout, "bti - send tweet to twitter\n");
	fprintf(stdout, "Version: " BTI_VERSION "\n");
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, "  bti [options]\n");
	fprintf(stdout, "options are:\n");
	fprintf(stdout, "  --account accountname\n");
	fprintf(stdout, "  --password password\n");
	fprintf(stdout, "  --proxy PROXY:PORT\n");
	fprintf(stdout, "  --host HOST\n");
	fprintf(stdout, "  --logfile logfile\n");
	fprintf(stdout, "  --bash\n");
	fprintf(stdout, "  --action action\n");
	fprintf(stdout, "  --debug\n");
	fprintf(stdout, "  --version\n");
	fprintf(stdout, "  --help\n");
}

static void display_version(void)
{
	fprintf(stdout, "bti - version %s\n", BTI_VERSION);
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
	free(session->password);
	free(session->account);
	free(session->tweet);
	free(session->proxy);
	free(session->time);
	free(session->homedir);
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

static const char *twitter_update_url  = "https://twitter.com/statuses/update.xml";
static const char *twitter_public_url  = "http://twitter.com/statuses/public_timeline.xml";
static const char *twitter_friends_url = "https://twitter.com/statuses/friends_timeline.xml";

static const char *identica_update_url  = "http://identi.ca/api/statuses/update.xml";
static const char *identica_public_url  = "http://identi.ca/api/statuses/public_timeline.xml";
static const char *identica_friends_url = "http://identi.ca/api/statuses/friends_timeline.xml";

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

void parse_statuses(xmlDocPtr doc, xmlNodePtr current)
{
	xmlChar *text;
	xmlChar *user;
	xmlNodePtr userinfo;
	current = current->xmlChildrenNode;
	while (current != NULL) {
		if (current->type == XML_ELEMENT_NODE) {
			if (!xmlStrcmp(current->name, (const xmlChar *)"text")) {
				text = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
				printf("%s", text);
				xmlFree(text);
			}
			if (!xmlStrcmp(current->name, (const xmlChar *)"user")) {
				userinfo = current->xmlChildrenNode;
				while (userinfo != NULL) {
					if ((!xmlStrcmp(userinfo->name, (const xmlChar *)"screen_name"))) {
						user = xmlNodeListGetString(doc, userinfo->xmlChildrenNode, 1);
						printf(" [%s]\n", user);
						xmlFree(user);
					}

					userinfo = userinfo->next;
				}
			}
		}

		current = current->next;
	}

	return;
}

static void parse_timeline(char *document)
{
	xmlDocPtr doc;
	xmlNodePtr current;
	doc = xmlReadMemory(document, strlen(document), "timeline.xml", NULL, XML_PARSE_NOERROR);

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
			parse_statuses(doc, current);
		current = current->next;
	}
	xmlFreeDoc(doc);

	return;
}

size_t curl_callback(void *buffer, size_t size, size_t nmemb, void *userp)
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
	if ((curl_buf->action == ACTION_FRIENDS) ||
		(curl_buf->action == ACTION_PUBLIC))
		parse_timeline(curl_buf->data);

	dbg("%s\n", curl_buf->data);

	return buffer_size;
}

static int send_request(struct session *session)
{
	char user_password[500];
	char data[500];
	struct bti_curl_buffer *curl_buf;
	CURL *curl = NULL;
	CURLcode res;
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *slist = NULL;

	if (!session)
		return -EINVAL;

	curl_buf = bti_curl_buffer_alloc(session->action);
	if (!curl_buf)
		return -ENOMEM;

	curl = curl_init();
	if (!curl)
		return -EINVAL;

	switch (session->action) {
	case ACTION_UPDATE:
		snprintf(user_password, sizeof(user_password), "%s:%s",
			 session->account, session->password);
		snprintf(data, sizeof(data), "status=\"%s\"", session->tweet);
		curl_formadd(&formpost, &lastptr,
			     CURLFORM_COPYNAME, "status",
			     CURLFORM_COPYCONTENTS, session->tweet,
			     CURLFORM_END);

		curl_formadd(&formpost, &lastptr,
			     CURLFORM_COPYNAME, "source",
			     CURLFORM_COPYCONTENTS, "bti",
			     CURLFORM_END);

		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		slist = curl_slist_append(slist, "Expect:");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
		switch (session->host) {
		case HOST_TWITTER:
			curl_easy_setopt(curl, CURLOPT_URL, twitter_update_url);
			break;
		case HOST_IDENTICA:
			curl_easy_setopt(curl, CURLOPT_URL, identica_update_url);
			break;
		}
		curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);

		break;
	case ACTION_FRIENDS:
		snprintf(user_password, sizeof(user_password), "%s:%s",
			 session->account, session->password);
		switch (session->host) {
		case HOST_TWITTER:
			curl_easy_setopt(curl, CURLOPT_URL, twitter_friends_url);
			break;
		case HOST_IDENTICA:
			curl_easy_setopt(curl, CURLOPT_URL, identica_friends_url);
			break;
		}
		curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);

		break;
	case ACTION_PUBLIC:
		switch (session->host) {
		case HOST_TWITTER:
			curl_easy_setopt(curl, CURLOPT_URL, twitter_public_url);
			break;
		case HOST_IDENTICA:
			curl_easy_setopt(curl, CURLOPT_URL, identica_public_url);
			break;
		}

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
	res = curl_easy_perform(curl);
	if (res && !session->bash) {
		fprintf(stderr, "error(%d) trying to perform operation\n", res);
		return -EINVAL;
	}

	curl_easy_cleanup(curl);
	if (session->action == ACTION_UPDATE)
		curl_formfree(formpost);
	bti_curl_buffer_free(curl_buf);
	return 0;
}

static void parse_configfile(struct session *session)
{
	FILE *config_file;
	char *line = NULL;
	size_t len = 0;
	char *account = NULL;
	char *password = NULL;
	char *host = NULL;
	char *proxy = NULL;
	char *logfile = NULL;
	char *action = NULL;
	char *file;

	/* config file is ~/.bti  */
	file = alloca(strlen(session->homedir) + 7);

	sprintf(file, "%s/.bti", session->homedir);

	config_file = fopen(file, "r");

	/* No error if file does not exist or is unreadable.  */
	if (config_file == NULL)
		return;

	do {
		ssize_t n = getline(&line, &len, config_file);
		if (n < 0)
			break;
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		/* Parse file.  Format is the usual value pairs:
		   account=name
		   passwort=value
		   # is a comment character
		*/
		*strchrnul(line, '#') = '\0';
		char *c = line;
		while (isspace(*c))
			c++;
		/* Ignore blank lines.  */
		if (c[0] == '\0')
			continue;

		if (!strncasecmp(c, "account", 7) && (c[7] == '=')) {
			c += 8;
			if (c[0] != '\0')
				account = strdup(c);
		} else if (!strncasecmp(c, "password", 8) &&
			   (c[8] == '=')) {
			c += 9;
			if (c[0] != '\0')
				password = strdup(c);
		} else if (!strncasecmp(c, "host", 4) &&
			   (c[4] == '=')) {
			c += 5;
			if (c[0] != '\0')
				host = strdup(c);
		} else if (!strncasecmp(c, "proxy", 5) &&
			   (c[5] == '=')) {
			c += 6;
			if (c[0] != '\0')
				proxy = strdup(c);
		} else if (!strncasecmp(c, "logfile", 7) &&
			   (c[7] == '=')) {
			c += 8;
			if (c[0] != '\0')
				logfile = strdup(c);
		} else if (!strncasecmp(c, "action", 6) &&
			   (c[6] == '=')) {
			c += 7;
			if (c[0] != '\0')
				action = strdup(c);
		}
	} while (!feof(config_file));

	if (password)
		session->password = password;
	if (account)
		session->account = account;
	if (host) {
		if (strcasecmp(host, "twitter") == 0)
			session->host = HOST_TWITTER;
		if (strcasecmp(host, "identica") == 0)
			session->host = HOST_IDENTICA;
		free(host);
	}
	if (proxy) {
		if (session->proxy)
			free(session->proxy);
		session->proxy = proxy;
	}
	if (logfile)
		session->logfile = logfile;
	if (action) {
		if (strcasecmp(action, "update") == 0)
			session->action = ACTION_UPDATE;
		if (strcasecmp(action, "friends") == 0)
			session->action = ACTION_FRIENDS;
		if (strcasecmp(action, "public") == 0)
			session->action = ACTION_PUBLIC;
		free(action);
	}

	/* Free buffer and close file.  */
	free(line);
	fclose(config_file);
}

static void log_session(struct session *session, int retval)
{
	FILE *log_file;
	char *filename;
	char *host;

	/* Only log something if we have a log file set */
	if (!session->logfile)
		return;

	filename = alloca(strlen(session->homedir) +
			  strlen(session->logfile) + 3);

	sprintf(filename, "%s/%s", session->homedir, session->logfile);

	log_file = fopen(filename, "a+");
	if (log_file == NULL)
		return;
	switch (session->host) {
	case HOST_TWITTER:
		host = "twitter";
		break;
	case HOST_IDENTICA:
		host = "identi.ca";
		break;
	default:
		host = "unknown";
		break;
	}

	if (session->action == ACTION_UPDATE) {
		if (retval)
			fprintf(log_file, "%s: host=%s tweet failed\n",
				session->time, host);
		else
			fprintf(log_file, "%s: host=%s tweet=%s\n",
				session->time, host, session->tweet);
	} else if (session->action == ACTION_FRIENDS) {
		fprintf(log_file, "%s: host=%s retrieving friends timeline\n",
			session->time, host);
	} else if (session->action == ACTION_PUBLIC) {
		fprintf(log_file, "%s: host=%s retrieving public timeline\n",
			session->time, host);
	}

	fclose(log_file);
}

int main(int argc, char *argv[], char *envp[])
{
	static const struct option options[] = {
		{ "debug", 0, NULL, 'd' },
		{ "account", 1, NULL, 'a' },
		{ "password", 1, NULL, 'p' },
		{ "host", 1, NULL, 'H' },
		{ "proxy", 1, NULL, 'P' },
		{ "action", 1, NULL, 'A' },
		{ "logfile", 1, NULL, 'L' },
		{ "help", 0, NULL, 'h' },
		{ "bash", 0, NULL, 'b' },
		{ "version", 0, NULL, 'v' },
		{ }
	};
	struct session *session;
	pid_t child;
	char *tweet;
	int retval = 0;
	int option;
	char *http_proxy;
	time_t t;

	debug = 0;
	rl_bind_key('\t', rl_insert);

	session = session_alloc();
	if (!session) {
		fprintf(stderr, "no more memory...\n");
		return -1;
	}

	/* get the current time so that we can log it later */
	time(&t);
	session->time = strdup(ctime(&t));
	session->time[strlen(session->time)-1] = 0x00;

	session->homedir = strdup(getenv("HOME"));

	curl_global_init(CURL_GLOBAL_ALL);

	/* Set environment variables first, before reading command line options
	 * or config file values. */
	http_proxy = getenv("http_proxy");
	if (http_proxy) {
		if (session->proxy)
			free(session->proxy);
		session->proxy = strdup(http_proxy);
		dbg("http_proxy = %s\n", session->proxy);
	}

	parse_configfile(session);

	while (1) {
		option = getopt_long_only(argc, argv, "dqe:p:P:H:a:A:h",
					  options, NULL);
		if (option == -1)
			break;
		switch (option) {
		case 'd':
			debug = 1;
			break;
		case 'a':
			if (session->account)
				free(session->account);
			session->account = strdup(optarg);
			dbg("account = %s\n", session->account);
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
			if (strcasecmp(optarg, "friends") == 0)
				session->action = ACTION_FRIENDS;
			if (strcasecmp(optarg, "public") == 0)
				session->action = ACTION_PUBLIC;
			dbg("action = %d\n", session->action);
			break;
		case 'L':
			if (session->logfile)
				free(session->logfile);
			session->logfile = strdup(optarg);
			dbg("logfile = %s\n", session->logfile);
			break;
		case 'H':
			if (strcasecmp(optarg, "twitter") == 0)
				session->host = HOST_TWITTER;
			if (strcasecmp(optarg, "identica") == 0)
				session->host = HOST_IDENTICA;
			dbg("host = %d\n", session->host);
			break;
		case 'b':
			session->bash = 1;
			break;
		case 'h':
			display_help();
			goto exit;
		case 'v':
			display_version();
			goto exit;
		default:
			display_help();
			goto exit;
		}
	}

	if (!session->account) {
		fprintf(stdout, "Enter twitter account: ");
		session->account = readline(NULL);
	}

	if (!session->password) {
		fprintf(stdout, "Enter twitter password: ");
		session->password = readline(NULL);
	}

	if (session->action == ACTION_UPDATE) {
		if (session->bash)
			tweet = readline(NULL);
		else
			tweet = readline("tweet: ");
		if (!tweet || strlen(tweet) == 0) {
			dbg("no tweet?\n");
			return -1;
		}

		session->tweet = zalloc(strlen(tweet) + 10);
		if (session->bash)
			sprintf(session->tweet, "$ %s", tweet);
		else
			sprintf(session->tweet, "%s", tweet);

		free(tweet);
		dbg("tweet = %s\n", session->tweet);
	}

	dbg("account = %s\n", session->account);
	dbg("password = %s\n", session->password);
	dbg("host = %d\n", session->host);
	dbg("action = %d\n", session->action);

	/* fork ourself so that the main shell can get on
	 * with it's life as we try to connect and handle everything
	 */
	if (session->bash) {
		child = fork();
		if (child) {
			dbg("child is %d\n", child);
			exit(0);
		}
	}

	retval = send_request(session);
	if (retval && !session->bash)
		fprintf(stderr, "operation failed\n");

	log_session(session, retval);
exit:
	session_free(session);
	return retval;;
}
