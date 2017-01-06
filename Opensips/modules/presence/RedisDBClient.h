/*
 * RedisDBClient.h
 *
 *  Created on: Sep 14, 2015
 *      Author: suryaveer
 */

#ifndef REDISDBCLIENT_H_
#define REDISDBCLIENT_H_
#include "../../dprint.h"
#include <hiredis/hiredis.h>

extern redisContext *redis_context;

int cacheDBConnect(char* host, int port) ;
void cacheDBDisConnect();
int cacheDBReConnect();



#endif /* REDISDBCLIENT_H_ */
