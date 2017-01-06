/*
 * Util.h
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */
#include "../../db/db_key.h"
#include "../../db/db_val.h"
#include "../../db/db_res.h"

#define FILTER "filter="
#define KEYS "keys="
#define NOT_REQ_KEYS "&np&keys={\"_id\":0}"


int db_print_single_json(char* _b, const db_key_t* _k, const db_val_t* _v, const int _n);
char* escapeXML(char *_b, char *_source);
void get_user_from_sip_uri(char *_u,char *_d, char *uri);
int parse_json_to_result(char *json, db_res_t** result);
int create_url(const db_key_t* _k, const db_val_t* _v, int _n, char* url, const char* _rt, const char* _ruri1, const char* _ruri2, const db_key_t* _kr, int _nr);
int free_result(db_res_t* r);
unsigned int get_hash(const char* s);

