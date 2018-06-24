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
// #include "redisassert.h"


#define zmalloc malloc
#define zcalloc calloc
#define zfree free

/*====================== Hash table type implementation  ==================== */

/* This is a hash table type that uses the SDS dynamic strings library as
 * keys and redis objects as values (objects can hold SDS strings,
 * lists, sets). */

void dictVanillaFree(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    zfree(val);
}

void dictListDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    listRelease((list*)val);
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

/* A case insensitive version used for the command lookup table and other
 * places where case insensitive non binary-safe comparison is needed. */
int dictSdsKeyCaseCompare(void *privdata, const void *key1,
        const void *key2)
{
    DICT_NOTUSED(privdata);

    return strcasecmp(key1, key2) == 0;
}

// void dictObjectDestructor(void *privdata, void *val)
// {
//     DICT_NOTUSED(privdata);

//     if (val == NULL) return; /* Lazy freeing will set value to NULL. */
//     decrRefCount(val);
// }

void dictSdsDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

// int dictObjKeyCompare(void *privdata, const void *key1,
//         const void *key2)
// {
//     const robj *o1 = key1, *o2 = key2;
//     return dictSdsKeyCompare(privdata,o1->ptr,o2->ptr);
// }

// uint64_t dictObjHash(const void *key) {
//     const robj *o = key;
//     return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
// }

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t dictSdsCaseHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

// int dictEncObjKeyCompare(void *privdata, const void *key1,
//         const void *key2)
// {
//     robj *o1 = (robj*) key1, *o2 = (robj*) key2;
//     int cmp;

//     if (o1->encoding == OBJ_ENCODING_INT &&
//         o2->encoding == OBJ_ENCODING_INT)
//             return o1->ptr == o2->ptr;

//     o1 = getDecodedObject(o1);
//     o2 = getDecodedObject(o2);
//     cmp = dictSdsKeyCompare(privdata,o1->ptr,o2->ptr);
//     decrRefCount(o1);
//     decrRefCount(o2);
//     return cmp;
// }

// uint64_t dictEncObjHash(const void *key) {
//     robj *o = (robj*) key;

//     if (sdsEncodedObject(o)) {
//         return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
//     } else {
//         if (o->encoding == OBJ_ENCODING_INT) {
//             char buf[32];
//             int len;

//             len = ll2string(buf,32,(long)o->ptr);
//             return dictGenHashFunction((unsigned char*)buf, len);
//         } else {
//             uint64_t hash;

//             o = getDecodedObject(o);
//             hash = dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
//             decrRefCount(o);
//             return hash;
//         }
//     }
// }

/* Generic hash table type where keys are Redis Objects, Values
 * dummy pointers. */
// dictType objectKeyPointerValueDictType = {
//     dictEncObjHash,            /* hash function */
//     NULL,                      /* key dup */
//     NULL,                      /* val dup */
//     dictEncObjKeyCompare,      /* key compare */
//     dictObjectDestructor, /* key destructor */
//     NULL                       /* val destructor */
// };

/* Set dictionary type. Keys are SDS strings, values are ot used. */
// dictType setDictType = {
//     dictSdsHash,               /* hash function */
//     NULL,                      /* key dup */
//     NULL,                      /* val dup */
//     dictSdsKeyCompare,         /* key compare */
//     dictSdsDestructor,         /* key destructor */
//     NULL                       /* val destructor */
// };

/* Sorted sets hash (note: a skiplist is used in addition to the hash table) */
// dictType zsetDictType = {
//     dictSdsHash,               /* hash function */
//     NULL,                      /* key dup */
//     NULL,                      /* val dup */
//     dictSdsKeyCompare,         /* key compare */
//     NULL,                      /* Note: SDS string shared & freed by skiplist */
//     NULL                       /* val destructor */
// };

/* Db->dict, keys are sds strings, vals are Redis objects. */
// dictType dbDictType = {
//     dictSdsHash,                /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCompare,          /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     dictObjectDestructor   /* val destructor */
// };          //TODO:

/* server.lua_scripts sha (as sds string) -> scripts (as robj) cache. */
// dictType shaScriptObjectDictType = {
//     dictSdsCaseHash,            /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCaseCompare,      /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     dictObjectDestructor        /* val destructor */
// };

/* Db->expires */
// dictType keyptrDictType = {
//     dictSdsHash,                /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCompare,          /* key compare */
//     NULL,                       /* key destructor */
//     NULL                        /* val destructor */
// };

/* Command table. sds string -> command struct pointer. */
dictType commandTableDictType = {
    dictSdsCaseHash,            /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCaseCompare,      /* key compare */
    dictSdsDestructor,          /* key destructor */
    NULL                        /* val destructor */
};

/* Hash type hash table (note that small hashes are represented with ziplists) */
dictType hashDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    dictSdsDestructor           /* val destructor */
};

/* Keylist hash table type has unencoded redis objects as keys and
 * lists as values. It's used for blocking operations (BLPOP) and to
 * map swapped keys to a list of clients waiting for this keys to be loaded. */
// dictType keylistDictType = {
//     dictObjHash,                /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictObjKeyCompare,          /* key compare */
//     dictObjectDestructor,       /* key destructor */
//     dictListDestructor          /* val destructor */
// };

/* Cluster nodes hash table, mapping nodes addresses 1.2.3.4:6379 to
 * clusterNode structures. */
// dictType clusterNodesDictType = {
//     dictSdsHash,                /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCompare,          /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     NULL                        /* val destructor */
// };

/* Cluster re-addition blacklist. This maps node IDs to the time
 * we can re-add this node. The goal is to avoid readding a removed
 * node for some time. */
// dictType clusterNodesBlackListDictType = {
//     dictSdsCaseHash,            /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCaseCompare,      /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     NULL                        /* val destructor */
// };

/* Cluster re-addition blacklist. This maps node IDs to the time
 * we can re-add this node. The goal is to avoid readding a removed
 * node for some time. */
// dictType modulesDictType = {
//     dictSdsCaseHash,            /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCaseCompare,      /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     NULL                        /* val destructor */
// };

// /* Migrate cache dict type. */
// dictType migrateCacheDictType = {
//     dictSdsHash,                /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCompare,          /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     NULL                        /* val destructor */
// };

/* Replication cached script dict (server.repl_scriptcache_dict).
 * Keys are sds SHA1 strings, while values are not used at all in the current
 * implementation. */
// dictType replScriptCacheDictType = {
//     dictSdsCaseHash,            /* hash function */
//     NULL,                       /* key dup */
//     NULL,                       /* val dup */
//     dictSdsKeyCaseCompare,      /* key compare */
//     dictSdsDestructor,          /* key destructor */
//     NULL                        /* val destructor */
// };



#include "sds.h"

uint64_t hashCallback(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

int compareCallback(void *privdata, const void *key1, const void *key2) {
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}

void freeCallback(void *privdata, void *val) {
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

dictType BenchmarkDictType = {
    hashCallback,
    NULL,
    NULL,
    compareCallback,
    freeCallback,
    NULL
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
    dict *dict = dictCreate(&BenchmarkDictType,NULL);
    long count = 0;

    if (argc == 2) {
        count = strtol(argv[1],NULL,10);
    } else {
        count = 5000000;
    }

    start_benchmark();
    for (j = 0; j < count; j++) {
        int retval = dictAdd(dict,sdsfromlonglong(j),(void*)j);
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
        if(de)
            printf("val:%ld\n",de->v.s64);
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