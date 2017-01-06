/*
 * Common.h
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */



#define MAX_URL_LEN 4000
#define JSON_BUF_LEN 65536
#define PRESENTITY "presentity"
#define WATCHER "watcher"
#define SUBSCRIPTION "subscription"
#define INT_DIGITS 19

//#define ROOT_URL "http://192.168.254.1:8080/PresenceRepository/PresenceRepository/V1/"

extern int update_request;
extern int delete_request;
extern char *ROOT_URL;
extern char *subs_queue_msg; // used for publish to subscribe queue.
extern int micro_srv_arch;
extern int avail_subs; // temp variable to store status of subscriptions. IF available 1 else 0. Used in presence.c
extern int avail_pubs;
//#define ROOT_URL "http://presenceserverfe-presence.rhcloud.com/PresenceRepository/V1/"
static inline char* my_strcpy(char*dest, const char* src, int hasLen, int length) {
	if (!hasLen) {
		while ((*dest = *src++))
			++dest;

	} else {
		while (length-- && (*dest = *src++))
			++dest;
	}
	return dest;
}
static inline char* my_itoa(int i)
{
  /* Room for INT_DIGITS digits, - and '\0' */
	if(i < 0)
		i = i*-1;
  static char buf[INT_DIGITS + 2];
  char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    do {
      *--p = '0' + (i % 10);
      i /= 10;
    } while (i != 0);
  return p;
}
// for unsigned ints
static inline char* my_uitoa(unsigned int i)
{
  /* Room for INT_DIGITS digits, - and '\0' */
	if(i < 0)
		i = i*-1;
  static char buf[INT_DIGITS + 2];
  char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    do {
      *--p = '0' + (i % 10);
      i /= 10;
    } while (i != 0);
  return p;
}

static inline char* my_itoa_len(int i, int* len)
{
  /* Room for INT_DIGITS digits, - and '\0' */
  static char buf[INT_DIGITS + 2];
  char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    do {
      *--p = '0' + (i % 10);
      *len += 1;
      i /= 10;
    } while (i != 0);
  return p;
}
