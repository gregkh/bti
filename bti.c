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
#include "bti_version.h"


#define zalloc(size)	calloc(size, 1)

#define dbg(format, arg...)						\
	do {								\
		if (debug)						\
			printf("%s: " format , __func__ , ## arg );	\
	} while (0)


static int debug = 0;

enum host {
	HOST_TWITTER = 0,
	HOST_IDENTICA = 1,
};

struct session {
	char *password;
	char *account;
	char *tweet;
	char *proxy;
	char *time;
	char *homedir;
	int bash;
	enum host host;
};

struct bti_curl_buffer {
	char *data;
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
	fprintf(stdout, "  --bash\n");
	fprintf(stdout, "  --debug\n");
	fprintf(stdout, "  --version\n");
	fprintf(stdout, "  --help\n");
}

static void display_version(void)
{
	fprintf(stdout, "bti - version %s\n", BTI_VERSION);
}

static char *get_string_from_stdin(void)
{
	static char *string = (char *)NULL;
	if (string) {
		free(string);
		string = (char *)NULL;
	}

	string = readline("tweet: ");

	return string;
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

static struct bti_curl_buffer *bti_curl_buffer_alloc(void)
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
	return buffer;
}

static void bti_curl_buffer_free(struct bti_curl_buffer *buffer)
{
	if (!buffer)
		return;
	free(buffer->data);
	free(buffer);
}

static const char *twitter_url = "https://twitter.com/statuses/update.xml";
static const char *identica_url = "http://identi.ca/api/statuses/update.xml";

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

	dbg("%s\n", curl_buf->data);

	return buffer_size;
}

static int send_tweet(struct session *session)
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

	curl_buf = bti_curl_buffer_alloc();
	if (!curl_buf)
		return -ENOMEM;

	snprintf(user_password, sizeof(user_password), "%s:%s",
		 session->account, session->password);
	snprintf(data, sizeof(data), "status=\"%s\"", session->tweet);

	curl = curl_init();
	if (!curl)
		return -EINVAL;

	curl_formadd(&formpost, &lastptr,
		     CURLFORM_COPYNAME, "status",
		     CURLFORM_COPYCONTENTS, session->tweet,
		     CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

	switch (session->host) {
	case HOST_TWITTER:
		curl_easy_setopt(curl, CURLOPT_URL, twitter_url);
		/*
		 * twitter doesn't like the "Expect: 100-continue" header
		 * anymore, so turn it off.
		 */
		slist = curl_slist_append(slist, "Expect:");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
		break;
	case HOST_IDENTICA:
		curl_easy_setopt(curl, CURLOPT_URL, identica_url);
		break;
	}

	if (session->proxy)
		curl_easy_setopt(curl, CURLOPT_PROXY, session->proxy);

	if (debug)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_USERPWD, user_password);

	dbg("user_password = %s\n", user_password);
	dbg("data = %s\n", data);
	dbg("proxy = %s\n", session->proxy);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl_buf);
	res = curl_easy_perform(curl);
	if (res && !session->bash) {
		fprintf(stderr, "error(%d) trying to send tweet\n", res);
		return -EINVAL;
	}

	curl_easy_cleanup(curl);
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

	/* Free buffer and close file.  */
	free(line);
	fclose(config_file);
}

static void log_session(struct session *session, int retval)
{
	FILE *log_file;
	char *filename;
	char *host;

	/* logfile is ~/.bti.log  */
	filename = alloca(strlen(session->homedir) + 10);

	sprintf(filename, "%s/.bti.log", session->homedir);

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

	if (retval)
		fprintf(log_file, "%s: host=%s tweet failed\n", session->time, host);
	else
		fprintf(log_file, "%s: host=%s tweet=%s\n", session->time, host, session->tweet);

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
#if 0
	char *pwd = getenv("PWD");
	char *dir;
#endif

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
		option = getopt_long_only(argc, argv, "dqe:p:P:H:a:h",
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
		case 'H':
			if (strcasecmp(optarg, "twitter") == 0)
				session->host = HOST_TWITTER;
			if (strcasecmp(optarg, "identica") == 0)
				session->host = HOST_IDENTICA;
			dbg("host = %d\n", session->host);
			break;
		case 'b':
			session->bash= 1;
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
		session->account = get_string_from_stdin();
	}

	if (!session->password) {
		fprintf(stdout, "Enter twitter password: ");
		session->password = get_string_from_stdin();
	}
#if 0
	/* get the current working directory basename */
	if (strcmp(pwd, home) == 0)
		dir = "~";
	else {
		dir = strrchr(pwd, '/');
		if (dir)
			dir++;
		else
			dir = "?";
	}
#endif
	tweet = get_string_from_stdin();
	if (!tweet || strlen(tweet) == 0) {
		dbg("no tweet?\n");
		return -1;
	}

//	session->tweet = zalloc(strlen(tweet) + strlen(dir) + 10);
	session->tweet = zalloc(strlen(tweet) + 10);

	/* if --bash is specified, add the "PWD $ " to
	 * the start of the tweet. */
	if (session->bash)
//		sprintf(session->tweet, "%s $ %s", dir, tweet);
		sprintf(session->tweet, "$ %s", tweet);
	else
		sprintf(session->tweet, "%s", tweet);
	free(tweet);

	dbg("account = %s\n", session->account);
	dbg("password = %s\n", session->password);
	dbg("tweet = %s\n", session->tweet);
	dbg("host = %d\n", session->host);

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

	retval = send_tweet(session);
	if (retval && !session->bash)
		fprintf(stderr, "tweet failed\n");

//	log_session(session, retval);
exit:
	session_free(session);
	return retval;;
}
