/*
 * RedisDBClient.c
 *
 *  Created on: Sep 13, 2015
 *      Author: suryaveer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RedisDBClient.h"

char* cache_host;
int cache_port;
redisContext *redis_context;

int cacheDBConnect(char* host, int port) {
	redisReply *reply;
	LM_NOTICE("Making connection with redis db.\n");
	cache_host = host;
	cache_port = port;
	redis_context = redisConnect(cache_host, cache_port);

	if (redis_context == NULL || redis_context->err) {
		if (redis_context) {
			LM_ERR("Connection error %s\n", redis_context->errstr);
			free(redis_context);
		} else {
			LM_ERR("Connection error. Can't allocate redis context.\n");
		}
		return -1;
	} else {
		reply = redisCommand(redis_context, "PING");
		LM_NOTICE("Reply from server.%s\n", reply->str);
		freeReplyObject(reply);
		return 1;
	}
}
int cacheDBReConnect() {
	LM_DBG("Attempting reconnect.");
	return cacheDBConnect(cache_host,cache_port);
}
void cacheDBDisConnect() {
	redisFree(redis_context);
}
