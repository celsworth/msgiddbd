/*-
 * Copyright (c) 2009 Thomas Hurst <tom@hur.st>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "html.h"

int 
html_entities_max_entity_size ()
{
	return MAX_ENTITY_SIZE;
}

char *
html_entities_ascii_buffer (len)
size_t len;
{
	return malloc((len * html_entities_max_entity_size()) + 1);
}

int 
html_entities_ascii (buf, len, escaped)
char *buf;
size_t len;
char *escaped;
{
	unsigned int i,j = 0;
	unsigned int *chunk;
	static char *hex = "0123456789ABCDEF";

	for (i = 0; i < len; i++)
	{
		// Checking longs is very fast, but only on data which contains
		// long strings of alphabetic characters without numbers or spaces.
		// Message-ID's usually contain numbers, with the occasional static
		// string like "powerpost", which we can reduce to "powe" "rpos" "t"
		while (len - i >= sizeof(unsigned int))
		{
			chunk = (unsigned int *)((char *)buf + i);
			// null check
			if ((*chunk - 0x01010101UL) & ~(*chunk) & 0x80808080UL) break;
			if ((*chunk & 0xc0c0c0c0) == 0x40404040)
			{
				//memcpy(escaped + j, chunk, sizeof(int));
				*(unsigned int *)(escaped + j) = *chunk;
				j += sizeof(int);
				i += sizeof(int);
			}
			else break;
		}

		if (i >= len) break;

		unsigned char c = buf[i];
		switch (c)
		{
			case '&':
				memcpy(escaped + j, "&amp;", 5);
				j += 5;
				break;
			case '<':
				memcpy(escaped + j, "&lt;", 4);
				j += 4;
				break;
			case '"':
				memcpy(escaped + j, "&quot;", 6);
				j += 6;
				break;
			case '\000':
				goto fin;
			default:
				if (c <= 8 || c == 0xb || c == 0xc ||
				   (c >= 0xe && c <= 0x1f) || (c >= 0x7f && 0x84) ||
				   (c >= 0x86 && c <= 0x9f))
				{
					escaped[j++] = '&';
					escaped[j++] = '#';
					escaped[j++] = 'x';
					// j += sprintf(..) reduces performance for some reason
					// Also, shorter sprintf's are faster.
				//	sprintf(escaped + j, "%.2X", c);
				//	j += 2;
					escaped[j++] = (hex[c >> 4 & 0x7f % 16]);
					escaped[j++] = (hex[c & 0x7f % 16]);
					escaped[j++] = ';';
				}
				else
					escaped[j++] = c;
		}
	}
fin:
	escaped[j] = '\000';
	return j;
}

#ifdef BUILD_TEST
int 
main ()
{
	//char *buf = "foof$&b\"ar\"\001@moo<moo>";
	//char *buf = "part1of201.i5WqnoDaVEHByaHWA&QmE@powerpost2000AA.local";
	char *buf = "part1of55.ghyV7aVQwwjNyrAVm4rg@pornk";
	//char *buf = "\001&\"\xff\xf3<>";
	size_t len = strlen(buf);
	size_t elen;
	char *e = html_entities_ascii_buffer(len);
	printf("in: %s (%ld bytes)\n", buf, len);
	elen = html_entities_ascii(buf, len, e);
	printf("out: %s (%ld bytes)\n", e, elen);

	int i;
	for (i=0; i < 1000000; i++)
	{
		html_entities_ascii(buf, len, e);
	}
	free(e);
	return 0;
}
#endif

