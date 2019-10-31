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
#include <pcre.h>
#include <termios.h>
#include <dlfcn.h>
#include <oauth.h>
#include "bti.h"

typedef int (*config_function_callback)(struct session *session, char *value);

struct config_function {
	const char *key;
	config_function_callback callback;
};

/*
 * get_key function
 *
 * Read a line from the config file and assign it a key and a value.
 *
 * This logic taken almost identically from taken from udev's rule file parsing
 * logic in the file udev-rules.c, written by Kay Sievers and licensed under
 * the GPLv2+.  I hate writing parsers, so it makes sense to borrow working
 * logic from those smarter than I...
 */
static int get_key(struct session *session, char *line, char **key, char **value)
{
	char *linepos;
	char *temp;
	char terminator;

	linepos = line;
	if (linepos == NULL || linepos[0] == '\0')
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	*key = linepos;

	for (;;) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
	}

	/* remember the end of the key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* make sure this is a = operation */
	/*
	 * udev likes to check for += and == and lots of other complex
	 * assignments that we don't care about.
	 */
	if (linepos[0] == '=')
		linepos++;
	else
		return -1;

	/* terminate key */
	temp[0] = '\0';

	/* skip whitespace after opearator */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/*
	 * if the value is quoted, then terminate on a ", otherwise space is
	 * the terminator.
	 * */
	if (linepos[0] == '"') {
		terminator = '"';
		linepos++;
	} else
		terminator = ' ';

	/* get the value */
	*value = linepos;

	/* terminate */
	temp = strchr(linepos, terminator);
	if (temp) {
		temp[0] = '\0';
		temp++;
	} else {
		/*
		 * perhaps we just hit the end of the line, so there would not
		 * be a terminator, so just use the whole rest of the string as
		 * the value.
		 */
	}
	/* printf("%s = %s\n", *key, *value); */
	return 0;
}

static int session_string(char **field, char *value)
{
	char *string;

	string = strdup(value);
	if (string) {
		if (*field)
			free(*field);
		*field = string;
		return 0;
	}
	return -1;
}

static int session_bool(int *field, char *value)
{
	if ((strncasecmp(value, "true", 4) == 0) ||
	    strncasecmp(value, "yes", 3) == 0)
		*field = 1;
	return 0;
}

static int account_callback(struct session *session, char *value)
{
	return session_string(&session->account, value);
}

static int password_callback(struct session *session, char *value)
{
	return session_string(&session->password, value);
}

static int proxy_callback(struct session *session, char *value)
{
	return session_string(&session->proxy, value);
}

static int user_callback(struct session *session, char *value)
{
	return session_string(&session->user, value);
}

static int consumer_key_callback(struct session *session, char *value)
{
	return session_string(&session->consumer_key, value);
}

static int consumer_secret_callback(struct session *session, char *value)
{
	return session_string(&session->consumer_secret, value);
}

static int access_token_key_callback(struct session *session, char *value)
{
	return session_string(&session->access_token_key, value);
}

static int access_token_secret_callback(struct session *session, char *value)
{
	return session_string(&session->access_token_secret, value);
}

static int logfile_callback(struct session *session, char *value)
{
	return session_string(&session->logfile, value);
}

static int replyto_callback(struct session *session, char *value)
{
	return session_string(&session->replyto, value);
}

static int retweet_callback(struct session *session, char *value)
{
	return session_string(&session->retweet, value);
}

static int host_callback(struct session *session, char *value)
{
	if (strcasecmp(value, "twitter") == 0) {
		session->host = HOST_TWITTER;
		session->hosturl = strdup(twitter_host);
		session->hostname = strdup(twitter_name);
	} else {
		session->host = HOST_CUSTOM;
		session->hosturl = strdup(value);
		session->hostname = strdup(value);
	}
	return 0;
}

static int action_callback(struct session *session, char *value)
{
	if (strcasecmp(value, "update") == 0)
		session->action = ACTION_UPDATE;
	else if (strcasecmp(value, "friends") == 0)
		session->action = ACTION_FRIENDS;
	else if (strcasecmp(value, "user") == 0)
		session->action = ACTION_USER;
	else if (strcasecmp(value, "replies") == 0)
		session->action = ACTION_REPLIES;
	else if (strcasecmp(value, "public") == 0)
		session->action = ACTION_PUBLIC;
	else
		session->action = ACTION_UNKNOWN;
	return 0;
}

static int verbose_callback(struct session *session, char *value)
{
	return session_bool(&session->verbose, value);
}

static int machine_readable_callback(struct session *session, char *value)
{
	return session_bool(&session->machine_readable, value);
}

static int shrink_urls_callback(struct session *session, char *value)
{
	return session_bool(&session->shrink_urls, value);
}

/*
 * List of all of the config file options.
 *
 * To add a new option, just add a string for the key name, and the callback
 * function that will be called with the value read from the config file.
 *
 * Make sure the table is NULL terminated, otherwise bad things will happen.
 */
static struct config_function config_table[] = {
	{ "account", account_callback },
	{ "password", password_callback },
	{ "proxy", proxy_callback },
	{ "user", user_callback },
	{ "consumer_key", consumer_key_callback },
	{ "consumer_secret", consumer_secret_callback },
	{ "access_token_key", access_token_key_callback },
	{ "access_token_secret", access_token_secret_callback },
	{ "logfile", logfile_callback },
	{ "replyto", replyto_callback },
	{ "retweet", retweet_callback },
	{ "host", host_callback },
	{ "action", action_callback },
	{ "verbose", verbose_callback },
	{ "machine-readable", machine_readable_callback },
	{ "shrink-urls", shrink_urls_callback },
	{ NULL, NULL }
};

static void process_line(struct session *session, char *key, char *value)
{
	struct config_function *item;
	int result;

	if (key == NULL || value == NULL)
		return;

	item = &config_table[0];
	for (;;) {
		if (item->key == NULL || item->callback == NULL)
			break;

		if (strncasecmp(item->key, key, strlen(item->key)) == 0) {
			/*
			 * printf("calling %p, for key = '%s' and value = * '%s'\n",
			 *	  item->callback, key, value);
			 */
			result = item->callback(session, value);
			if (!result)
				return;
		}
		item++;
	}
}

void bti_parse_configfile(struct session *session)
{
	FILE *config_file;
	char *line = NULL;
	char *key = NULL;
	char *value = NULL;
	char *hashmarker;
	size_t len = 0;
	ssize_t n;
	char *c;

	config_file = fopen(session->configfile, "r");

	/* No error if file does not exist or is unreadable.  */
	if (config_file == NULL)
		return;

	do {
		n = getline(&line, &len, config_file);
		if (n < 0)
			break;
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';

		/*
		 * '#' is comment markers, like bash style but it is a valid
		 * character in some fields, so only treat it as a comment
		 * marker if it occurs at the beginning of the line, or after
		 * whitespace
		 */
		hashmarker = strchr(line, '#');
		if (line == hashmarker)
			line[0] = '\0';
		else {
			while (hashmarker != NULL) {
				--hashmarker;
				if (isblank(hashmarker[0])) {
					hashmarker[0] = '\0';
					break;
				} else {
					/*
					 * false positive; '#' occured
					 * within a string
					 */
					hashmarker = strchr(hashmarker+2, '#');
				}
			}
		}
		c = line;
		while (isspace(*c))
			c++;
		/* Ignore blank lines.  */
		if (c[0] == '\0')
			continue;

		/* parse the line into a key and value pair */
		get_key(session, c, &key, &value);

		process_line(session, key, value);
	} while (!feof(config_file));

	/* Free buffer and close file.  */
	free(line);
	fclose(config_file);
}

