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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

void bti_parse_configfile(struct session *session)
{
	FILE *config_file;
	char *line = NULL;
	size_t len = 0;
	char *account = NULL;
	char *password = NULL;
	char *consumer_key = NULL;
	char *consumer_secret = NULL;
	char *access_token_key = NULL;
	char *access_token_secret = NULL;
	char *host = NULL;
	char *proxy = NULL;
	char *logfile = NULL;
	char *action = NULL;
	char *user = NULL;
	char *replyto = NULL;
	char *retweet = NULL;
	int shrink_urls = 0;

	config_file = fopen(session->configfile, "r");

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
		} else if (!strncasecmp(c, "consumer_key", 12) &&
			   (c[12] == '=')) {
			c += 13;
			if (c[0] != '\0')
				consumer_key = strdup(c);
		} else if (!strncasecmp(c, "consumer_secret", 15) &&
			   (c[15] == '=')) {
			c += 16;
			if (c[0] != '\0')
				consumer_secret = strdup(c);
		} else if (!strncasecmp(c, "access_token_key", 16) &&
			   (c[16] == '=')) {
			c += 17;
			if (c[0] != '\0')
				access_token_key = strdup(c);
		} else if (!strncasecmp(c, "access_token_secret", 19) &&
			   (c[19] == '=')) {
			c += 20;
			if (c[0] != '\0')
				access_token_secret = strdup(c);
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
		} else if (!strncasecmp(c, "replyto", 7) &&
			   (c[7] == '=')) {
			c += 8;
			if (c[0] != '\0')
				replyto = strdup(c);
		} else if (!strncasecmp(c, "action", 6) &&
			   (c[6] == '=')) {
			c += 7;
			if (c[0] != '\0')
				action = strdup(c);
		} else if (!strncasecmp(c, "user", 4) &&
				(c[4] == '=')) {
			c += 5;
			if (c[0] != '\0')
				user = strdup(c);
		} else if (!strncasecmp(c, "shrink-urls", 11) &&
				(c[11] == '=')) {
			c += 12;
			if (!strncasecmp(c, "true", 4) ||
					!strncasecmp(c, "yes", 3))
				shrink_urls = 1;
		} else if (!strncasecmp(c, "verbose", 7) &&
				(c[7] == '=')) {
			c += 8;
			if (!strncasecmp(c, "true", 4) ||
					!strncasecmp(c, "yes", 3))
				session->verbose = 1;
		} else if (!strncasecmp(c,"retweet", 7) &&
				(c[7] == '=')) {
			c += 8;
			if (c[0] != '\0')
				retweet = strdup(c);
		}
	} while (!feof(config_file));

	if (password)
		session->password = password;
	if (account)
		session->account = account;
	if (consumer_key)
		session->consumer_key = consumer_key;
	if (consumer_secret)
		session->consumer_secret = consumer_secret;
	if (access_token_key)
		session->access_token_key = access_token_key;
	if (access_token_secret)
		session->access_token_secret = access_token_secret;
	if (host) {
		if (strcasecmp(host, "twitter") == 0) {
			session->host = HOST_TWITTER;
			session->hosturl = strdup(twitter_host);
			session->hostname = strdup(twitter_name);
		} else if (strcasecmp(host, "identica") == 0) {
			session->host = HOST_IDENTICA;
			session->hosturl = strdup(identica_host);
			session->hostname = strdup(identica_name);
		} else {
			session->host = HOST_CUSTOM;
			session->hosturl = strdup(host);
			session->hostname = strdup(host);
		}
		free(host);
	}
	if (proxy) {
		if (session->proxy)
			free(session->proxy);
		session->proxy = proxy;
	}
	if (logfile)
		session->logfile = logfile;
	if (replyto)
		session->replyto = replyto;
	if (retweet)
		session->retweet = retweet;
	if (action) {
		if (strcasecmp(action, "update") == 0)
			session->action = ACTION_UPDATE;
		else if (strcasecmp(action, "friends") == 0)
			session->action = ACTION_FRIENDS;
		else if (strcasecmp(action, "user") == 0)
			session->action = ACTION_USER;
		else if (strcasecmp(action, "replies") == 0)
			session->action = ACTION_REPLIES;
		else if (strcasecmp(action, "public") == 0)
			session->action = ACTION_PUBLIC;
		else if (strcasecmp(action, "group") == 0)
			session->action = ACTION_GROUP;
		else
			session->action = ACTION_UNKNOWN;
		free(action);
	}
	if (user)
		session->user = user;
	session->shrink_urls = shrink_urls;

	/* Free buffer and close file.  */
	free(line);
	fclose(config_file);
}


