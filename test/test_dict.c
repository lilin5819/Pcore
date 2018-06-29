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
// #include "redisassert.h"

#define OBJ_NONE 0
#define OBJ_STRING 1
#define OBJ_NUM 2
#define OBJ_LIST 3
#define OBJ_DICT 4
#define OBJ_POINTER 5
#define OBJ_EXT 255

typedef struct object {
    uint8_t type;
    uint8_t extype; 
    uint16_t unused;
    void *ptr;
} object;

dict *objectMap = NULL;
/*====================== Hash table type implementation  ==================== */

/* This is a hash table type that uses the SDS dynamic strings library as
 * keys and redis objects as values (objects can hold SDS strings,
 * lists, sets). */

int objectGetType(void *ptr)
{
    if(!ptr) return 0;
    object *obj = (object *)ptr;
    return obj->type;
}

int objectGetExtype(void *ptr)
{
    if(!ptr) return 0;
    object *obj = (object *)ptr;
    return obj->extype;
}

object* objectCreate(char type,void *ptr)
{
    object *obj = zmalloc(sizeof(*obj));
    memset(obj,0,sizeof(*obj));
    obj->type = type;
    obj->ptr = ptr;
    return obj;
}

object* objectExCreate(int extype,void *ptr)
{
    object *obj = zmalloc(sizeof(*obj));
    memset(obj,0,sizeof(*obj));
    obj->type = OBJ_EXT;
    obj->extype = extype;
    obj->ptr = ptr;
    return obj;
}

int dictSdsKeyCompare(void *privdata, const void *key1,
        const void *key2)
{
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}

void dictListDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    listRelease((list*)val);
}

void dictDictDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    dictRelease((dict*)val);
}
/* A case insensitive version used for the command lookup table and other
 * places where case insensitive non binary-safe comparison is needed. */
int dictSdsKeyCaseCompare(void *privdata, const void *key1,
        const void *key2)
{
    DICT_NOTUSED(privdata);

    return strcasecmp(key1, key2) == 0;
}

void objectExDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; /* Lazy freeing will set value to NULL. */
    switch (objectGetExtype(val))
    {
        // case OBJ_STRING:
        //     sdsfree(val);
        // break;
        // case OBJ_LIST:
        //     listRelease(val);
        // break;
        // case OBJ_DICT:
        //     dictRelease(val);
        // break;
        // case OBJ_EXT:
        //     // objectExDestructor(privdata,val);
        // break;
    default:
        zfree(val);
        break;
    }
}

// TODO: switch case obj type , different free
void objectDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; /* Lazy freeing will set value to NULL. */
    switch (objectGetType(val))
    {
        case OBJ_STRING:
            sdsfree(val);
        break;
        case OBJ_LIST:
            listRelease(val);
        break;
        case OBJ_DICT:
            dictRelease(val);
        break;
        case OBJ_EXT:
            objectExDestructor(privdata,val);
        break;
    default:
        zfree(val);
        break;
    }
}

void dictSdsDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

// int objectKeyCompare(void *privdata, const void *key1,
//         const void *key2)
// {
//     const robj *o1 = key1, *o2 = key2;
//     return dictSdsKeyCompare(privdata,o1->ptr,o2->ptr);
// }

// uint64_t objectHash(const void *key) {
//     const robj *o = key;
//     return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
// }

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t dictSdsCaseHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

/* casesds --> obj */
dictType caseSdsDictType = {
    dictSdsCaseHash,            /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCaseCompare,      /* key compare */
    dictSdsDestructor,          /* key destructor */
    objectDestructor           /* val destructor */
};

/* sds --> obj */
dictType sdsDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    objectDestructor           /* val destructor */
};

long long timeInMilliseconds(void);

#define start_benchmark() start = timeInMilliseconds()
#define end_benchmark(msg) do { \
    elapsed = timeInMilliseconds()-start; \
    printf(msg ": %ld items in %lld ms\n", count, elapsed); \
} while(0);

/* dict-benchmark [count] */
int main(int argc, char **argv) {
    long j;
    long long start, elapsed;
    // dict *dict = dictCreate(&BenchmarkDictType,NULL);
    dict *dict = dictCreate(&sdsDictType,NULL);
    long count = 0;

    if (argc == 2) {
        count = strtol(argv[1],NULL,10);
    } else {
        count = 5000000;
    }

    start_benchmark();
    for (j = 0; j < count; j++) {
        // int retval = dictAdd(dict,sdsfromlonglong(j),(void*)j);
        int retval = dictAdd(dict,sdsfromlonglong(j),NULL);
        assert(retval == DICT_OK);
    }
    end_benchmark("Inserting");
    assert((long)dictSize(dict) == count);

    /* Wait for rehashing. */
    while (dictIsRehashing(dict)) {
        dictRehashMilliseconds(dict,100);
    }

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        dictEntry *de = dictFind(dict,key);
        // if(de)
        //     printf("val:%ld\n",de->v.s64);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Linear access of existing elements");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        dictEntry *de = dictFind(dict,key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Linear access of existing elements (2nd round)");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(rand() % count);
        dictEntry *de = dictFind(dict,key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Random access of existing elements");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(rand() % count);
        key[0] = 'X';
        dictEntry *de = dictFind(dict,key);
        assert(de == NULL);
        sdsfree(key);
    }
    end_benchmark("Accessing missing");

    start_benchmark();
    for (j = 0; j < count; j++) {
        sds key = sdsfromlonglong(j);
        int retval = dictDelete(dict,key);
        assert(retval == DICT_OK);
        key[0] += 17; /* Change first number to letter. */
        retval = dictAdd(dict,key,(void*)j);
        assert(retval == DICT_OK);
    }
    end_benchmark("Removing and adding");
}