/*
 * RepositoryHandler.h
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */
/* This function will insert the resource in the repository.
Input Parameters:
 db_key_t* _k: List of Columns.
 db_val_t* _v: List of Values
 int _n total: number of values
 char _rt: Type of resource (Presentity/Subscriber/ etc)
 char _r: Id of resource in case of PUT request. Optional.
*/

int insertResource(const db_key_t* _k, const db_val_t* _v, const int _n, const char *_rt, const char *_r, char *_b);

/* This function will insert the resource in the repository.
Input Parameters:
 db_key_t* _k: List of Columns.
 db_val_t* _v: List of Values
 int _n total: number of values
 db_res_t** _r: Pointer to structure where results will be stored.
 char _rt: Type of resource (Presentity/Subscriber/ etc)
 char _p: Id of resource. ex username@domain.com
*/

int getResource(const db_key_t* _k, const db_val_t* _v, const int _n, db_res_t** _r, const char *_rt, char* _u1, char* _u2, const db_key_t* _kr,  const int _nr);

/* This function will delete the resource in the repository.
Input Parameters:
 db_key_t* _k: List of Columns.
 db_val_t* _v: List of Values
 int _n total: number of values
 char _rt: Type of resource (Presentity/Subscriber/ etc)
 char _p: Id of resource. ex username@domain.com
*/

int deleteResource(const db_key_t* _k, const db_val_t* _v, const int _n, const char *_rt, char* _u1, char* _u2);

/* This function will check for the resource in the repository.
Input Parameters:
 db_key_t* _k: List of Columns.
 db_val_t* _v: List of Values
 int _n total: number of values
 char _rt: Type of resource (Presentity/Subscriber/ etc)
 char _p: Id of resource. ex username@domain.com
*/

int checkResource(const db_key_t* _k, const db_val_t* _v, const int _n, const char *_rt, char* _p);

/* This function will update the resource in the repository.
Input Parameters:
 db_key_t* _qk: List of query Columns.
 db_val_t* _qv: List of query Values
 int _qn total: number of query values
 db_key_t* _uk: List of update Columns.
 db_val_t* _uv: List of update Values
 int _un total: number of update values
 char _rt: Type of resource (Presentity/Subscriber/ etc)
 char _r: Id of resource in case of PUT request. Optional.
*/
int updateResource(const db_key_t* _qk, const db_val_t* _qv,
		const db_key_t* _uk, const db_val_t* _uv, const int _qn, const int _un,
		const char *_rt, char* _u1, char* _u2);
