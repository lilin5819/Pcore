#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/time.h>
#include <assert.h>
#include "sds.h"
#include "dict.h"
#include "fmacros.h"
#include "adlist.h"
#include "zmalloc.h"
#include "log.h"
#include "object.h"
// #include "redisassert.h"
LOG_DEF();

long long timeInMilliseconds(void);

    #define start_benchmark() start = timeInMilliseconds()
#define end_benchmark(msg) do { \
    elapsed = timeInMilliseconds()-start; \
    printf(msg ": %ld items in %lld ms\n", count, elapsed); \
} while(0);

/* dict-benchmark [count] */
int main(int argc, char **argv) {
    set_log_app((char*)argv[0]);
    set_log_level(3);
    set_log_mode(_MODE_VERBOSE);
    
    log_();

    long j;
    long long start, elapsed;
    dictEntry *de = NULL;
    log_();
    dict *sdsObjDict = dictSdsObjCreate();
    log_();
    long count = 0;

    if (argc == 2) {
        count = strtol(argv[1],NULL,10);
    } else {
        count = 100;
    }

    log_();
    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictAdd(sdsObjDict,key , objCreate(OBJ_STRING,sdsfromlonglong(j)) );
        assert(retval == DICT_OK);
    }
    for (j = 100+0; j < 100+count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictAdd(sdsObjDict,key , objCreate(OBJ_LIST,listCreate()) );
        assert(retval == DICT_OK);
    }
    for (j = 200+0; j < 200+count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictAdd(sdsObjDict,key , objCreate(OBJ_DICT,dictSdsObjCreate()) );
        assert(retval == DICT_OK);
    }
    for (j = 300+0; j < 300+count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictAdd(sdsObjDict,key , objCreate(OBJ_NUM,j) );
        assert(retval == DICT_OK);
    }
    end_benchmark("Inserting");
    assert((long)dictSize(sdsObjDict) == 4*count);
    log_int(zmalloc_used_memory());

    /* Wait for rehashing. */
    while (dictIsRehashing(sdsObjDict)) {
        dictRehashMilliseconds(sdsObjDict,100);
        printf("rehash\n");
    }
    log_int(zmalloc_used_memory());

    start_benchmark();
    dictObjDump(sdsObjDict);

    end_benchmark("Linear iter");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        de = dictFind(sdsObjDict,key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Linear access of existing elements (2nd round)");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(rand() % count);
        de = dictFind(sdsObjDict,key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Random access of existing elements");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(rand() % count);
        key[0] = 'X';
        de = dictFind(sdsObjDict,key);
        assert(de == NULL);
        sdsfree(key);
    }
    end_benchmark("Accessing missing");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictDelete(sdsObjDict,key);
        assert(retval == DICT_OK);
        key[0] += 17; /* Change first number to letter. */
        retval = dictAdd(sdsObjDict,key,objCreate(OBJ_STRING,sdsdup(key)) );
        assert(retval == DICT_OK);
    }
    end_benchmark("Removing and adding");
    log_int(zmalloc_used_memory());

    dictRelease(sdsObjDict);
    log_int(zmalloc_used_memory());

}