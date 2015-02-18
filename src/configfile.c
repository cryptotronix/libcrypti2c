/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of libcryptoauth.
 *
 * libcryptoauth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcryptoauth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

const char tok[] = " ";
char * token;

unsigned char cz[128] = {};

unsigned char c2h(char c)
{
    if (c >= 'A')
        return (c - 'A' + 10);
    else
        return (c - '0');
}

unsigned char a2b(char *ptr)
{
    return c2h( *ptr )*16 + c2h( *(ptr+1) );
}

void
parseStory (xmlDocPtr doc, xmlNodePtr cur) {

  xmlChar *key;
  char *key_cp;
  cur = cur->xmlChildrenNode;
  int x = 0;
  while (cur != NULL)
    {
	    /* if ((!xmlStrcmp(cur->name, (const xmlChar *)"Sn0to1"))) { */
	    /*         key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1); */
	    /*         printf("ConfigZone: %s\n", key); */
	    /*         xmlFree(key); */
 	    /* } */

      key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      if (NULL != key)
        {
          key_cp = strdup(key);
          token = strtok(key_cp, tok);

          while (token!=NULL)
            {
              printf("%s", token);
              cz[x] = a2b(token);
              x++;

              // get the next token
              token = strtok(NULL, tok);

            }
          printf("\n");

          printf("ConfigZone: %s\n", key);
          xmlFree(key);
          free(key_cp);
        }

      cur = cur->next;
    }
  return;
}

void
config2bin(char *docname) {

  xmlDocPtr doc;
  xmlNodePtr cur;

  doc = xmlParseFile(docname);

  if (doc == NULL)
    {
      fprintf(stderr,"Document not parsed successfully. \n");
      return;
    }

  cur = xmlDocGetRootElement(doc);

  if (cur == NULL)
    {
      fprintf(stderr,"empty document\n");
      xmlFreeDoc(doc);
      return;
    }

  if (xmlStrcmp(cur->name, (const xmlChar *) "ECC108Content.01"))
    {
      fprintf(stderr,"document of the wrong type, root node != ECC108Content.01");
      xmlFreeDoc(doc);
      return;
    }

  cur = cur->xmlChildrenNode;

  while (cur != NULL)
    {
      if ((!xmlStrcmp(cur->name, (const xmlChar *)"ConfigZone")))
        {
          printf("Parsing!\n");
          parseStory (doc, cur);
        }

      cur = cur->next;
    }

  xmlFreeDoc(doc);
  return;
}
