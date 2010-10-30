/*
 * Copyright (C) 2008-2010 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2009 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009 Amir Mohammad Saied <amirsaied@gmail.com>
 * Copyright (C) 2010 Sun Ning <classicning@gmail.com>
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
#include <string.h>
#include <ctype.h>
#include <libxml/tree.h>

#include "colors.h"

/* Bash color controls */
const char *BASH_COLOR_RESET="\033[0m";
const char *BASH_COLOR_BOLD_YELLOW="\033[1;33m";
const char *BASH_COLOR_UNDERLINE_CYAN="\033[4;36m";
const char *BASH_COLOR_NORMAL_GREEN="\033[0;32m";
const char *BASH_COLOR_NORMAL_MAGENTA="\033[0;35m";

char* str_append(char *dest, const char *src);

/* concat and move dest */
char* str_append(char *dest, const char *src){
    char *s = (char *)src;
    while(*s != '\0'){
        *dest++ = *s++;
    }

    return dest;
}

/* highlight url, @userid and search string(#xxx !xxx) */
void colorfy_text(const char *text, char *colorfied){
    char *p = (char*)text;
    // previous char
    char *pp = p;
    char *copied = colorfied;

    while(*p != '\0'){
        // some characters start with a '#' or '!'. It must after a
        // none alnum or just at the beginning.
        if ((*p == '#' || *p == '!') && (!isalnum(*pp) || pp==p)){
            copied = str_append(copied, BASH_COLOR_NORMAL_MAGENTA);
            while(*p !='\0' && *p != ' ' && *p != ',' && *p != '.'){
                *copied++ = *p++;
            }
            copied = str_append(copied, BASH_COLOR_RESET);
        }

        if (*p == '@' && (!(isalnum(*pp)) || pp==p)) {
            copied = str_append(copied, BASH_COLOR_NORMAL_GREEN);
            while(*p !='\0' && *p != ' ' && *p != ':'){
                *copied++ = *p++;
            }
            copied = str_append(copied, BASH_COLOR_RESET);
        }

        if (strncmp(p, "http://", 7)==0 || strncmp(p, "https://", 8)==0){
            copied = str_append(copied, BASH_COLOR_UNDERLINE_CYAN);
            while(*p !='\0' && *p != ' '){
                *copied++ = *p++;
            }
            copied = str_append(copied, BASH_COLOR_RESET);
        }

        pp = p;
        *copied++ = *p++;
    }
    *copied = '\0';

}

void colorfy_print(xmlChar *name, xmlChar *text){
    char color_name[50];
    char color_text[500];
    
    sprintf(color_name, "%s%s%s", BASH_COLOR_BOLD_YELLOW, name, BASH_COLOR_RESET);
    colorfy_text((const char*)text, color_text);
    printf("[%s] %s\n", color_name, color_text);
}


void colorfy_verbose_print(xmlChar *name, xmlChar *id,
        xmlChar *created, xmlChar *text){
    char color_name[50];
    char color_text[500];

    sprintf(color_name, "%s%s%s", BASH_COLOR_BOLD_YELLOW, name, BASH_COLOR_RESET);
    colorfy_text((const char*)text, color_text);
    printf("[%s] {%s} (%.16s) %s\n", color_name, id, created, color_text);
}

