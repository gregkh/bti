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

#ifndef __BTI_H
#define __BTI_H

enum host {
	HOST_TWITTER  = 0,
	HOST_CUSTOM   = 2
};

enum action {
	ACTION_UPDATE  = 0,
	ACTION_FRIENDS = 1,
	ACTION_USER    = 2,
	ACTION_REPLIES = 4,
	ACTION_PUBLIC  = 8,
	ACTION_RETWEET = 32,
	ACTION_DIRECT  = 64,
	ACTION_UNKNOWN = 128
};

struct session {
	char *password;
	char *account;
	char *consumer_key;
	char *consumer_secret;
	char *access_token_key;
	char *access_token_secret;
	char *tweet;
	char *proxy;
	char *time;
	char *homedir;
	char *logfile;
	char *user;
	char *hosturl;
	char *hostname;
	char *configfile;
	char *replyto;
	char *retweet;
	int bash;
	int background;
	int interactive;
	int shrink_urls;
	int dry_run;
	int page;
	int no_oauth;
	int guest;
	int verbose;
	int machine_readable;
	int column_output;
	enum host host;
	enum action action;
	void *readline_handle;
	char *(*readline)(const char *);
};

struct bti_curl_buffer {
	char *data;
	struct session *session;
	enum action action;
	int length;
};

extern const char twitter_host[];
extern const char twitter_name[];
extern int debug;

extern void bti_parse_configfile(struct session *session);

#define dbg(format, arg...)						\
	do {								\
		if (debug)						\
			fprintf(stdout, "bti: %s: " format , __func__ , \
				## arg);				\
	} while (0)


#endif
