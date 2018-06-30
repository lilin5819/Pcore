#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/time.h>
#include <assert.h>
#include "dict.h"
#include "fmacros.h"
#include "adlist.h"
#include "zmalloc.h"
#include "log.h"
#include "object.h"
/*====================== Hash table type implementation  ==================== */

/* This is a hash table type that uses the SDS dynamic strings library as
 * keys and redis objects as values (objects can hold SDS strings,
 * lists, sets). */
dict *gExObjectMap = NULL;

int objectGetType(object *obj)
{
    if(!obj) return 0;
    return obj->type;
}

int objectGetExType(object *obj)
{
    if(!obj) return 0;
    return obj->extype;
}

void* objectGetVal(object *obj)
{
    if(!obj) return NULL;
    return obj->ptr;
}

void objectSdsPrint(object *obj)
{
    ok(obj && objectGetType(obj) == OBJ_STRING);
    log_s(objectGetVal(obj));
}

object* objectCreate(uint8_t type,void *ptr)
{
    object *obj = zmalloc(sizeof(*obj));
    memset(obj,0,sizeof(*obj));
    obj->type = type;
    obj->ptr = ptr;
    return obj;
}

object* objectExCreate(uint16_t extype,void *ptr)
{
    object *obj = zmalloc(sizeof(*obj));
    memset(obj,0,sizeof(*obj));
    obj->type = (ptr == NULL) ? OBJ_NONE : OBJ_EXT;
    obj->extype = extype;
    obj->ptr = ptr;

    dictEntry *de = NULL;
    exObject *objFun = NULL;

    if (!gExObjectMap) return NULL; /* Lazy freeing will set value to NULL. */
    if (ptr){
        obj->ptr = ptr;
        return obj;
    }

    de = dictFind(gExObjectMap,sdsfromlonglong(extype));
    ok( de != NULL);
    
    objFun = dictGetVal(de);
    
    objFun->alloc(ptr);
    return obj;
}

void objectSdsDestructor(void *privdata, void *val)
{
    log_();
    DICT_NOTUSED(privdata);
    sdsfree((sds)val);
}

void objectListDestructor(void *privdata, void *val)
{
    log_();
    DICT_NOTUSED(privdata);
    listRelease((list*)val);
}

void objectDictDestructor(void *privdata, void *val)
{
    log_();
    DICT_NOTUSED(privdata);
    dictRelease((dict*)val);
}

void dictExDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    dictEntry *de = NULL;
    exObject *objFun = NULL;

    if (!val || !gExObjectMap) return; /* Lazy freeing will set value to NULL. */
    de = dictFind(gExObjectMap,sdsfromlonglong(objectGetExType(val)));
    
    if(!de) return;
    objFun = dictGetVal(de);
    if(!objFun || !objFun->free) return;

    objFun->free(val);
}

// TODO: switch case obj type , different free
void objectDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; /* Lazy freeing will set value to NULL. */
    void * objVal = objectGetVal(val);
    switch (objectGetType(val))
    {
        case OBJ_NONE:
        break;
        case OBJ_STRING:
            objectSdsDestructor(privdata,objVal);
        break;
        case OBJ_LIST:
            objectListDestructor(privdata,objVal);
        break;
        case OBJ_DICT:
            objectDictDestructor(privdata,objVal);
        break;
        case OBJ_EXT:
            dictExDestructor(privdata,val);
        break;
        default:
            zfree(objVal);
        break;
    }
    zfree(val);
}

/* A case insensitive version used for the command lookup table and other
 * places where case insensitive non binary-safe comparison is needed. */
int dictSdsKeyCaseCompare(void *privdata, const void *key1, const void *key2)
{
    DICT_NOTUSED(privdata);

    return strcasecmp(key1, key2) == 0;
}


void dictPrintSdsPair(dictEntry *de)
{
    if(!de) return;
    object * obj = dictGetVal(de);
    ok(objectGetType(obj) != OBJ_STRING);
    if(objectGetType(obj) != OBJ_STRING) return;
    printf("key=\"%s\" val=\"%s\"\n",(char *)dictGetKey(de),(char *)objectGetVal(obj));
}

void dictDumpKVInfo(dictEntry *de)
{
    if(!de) return;
    object * obj = dictGetVal(de);
    switch(objectGetType(obj)){
        case OBJ_STRING:
            printf("type=OBJ_STRING ");
            break;
        case OBJ_LIST:
            printf("type=OBJ_LIST ");
            break;
        case OBJ_DICT:
            printf("type=OBJ_DICT ");
            break;
        case OBJ_EXT:
            printf("type=OBJ_EXT ");
            break;
        default: 
            printf("OBJ_UNKNOW ");
            break;
    }
    printf("key=\"%s\" ",(char*)dictGetKey(de));
    if(objectGetType(obj) == OBJ_STRING)
        printf("val=\"%s\"",(char*)objectGetVal(obj));
    printf("\n");
}

int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2)
{
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}


uint64_t dictCaseSdsHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}


/* sdscase --> obj */
dictType caseSdsDictType = {
    dictCaseSdsHash,            /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCaseCompare,      /* key compare */
    objectSdsDestructor,          /* key destructor */
    objectDestructor           /* val destructor */
};

/* sds --> obj */
dictType sdsDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    objectSdsDestructor,          /* key destructor */
    objectDestructor           /* val destructor */
};

dict *dictSdsCreate(void)
{
    return dictCreate(&sdsDictType,NULL);
}

dict *dictCaseSdsCreate(void)
{
    return dictCreate(&caseSdsDictType,NULL);
}

// ===========================================

int dictExObjectMapInit(void)
{
    if(!gExObjectMap)
        gExObjectMap = dictCreate(&sdsDictType,NULL);
    return (gExObjectMap != NULL) ? 1 : 0 ;
}

int dictExObjectMapReg(exObject *obj)
{
    return dictAdd(gExObjectMap,sdsdup(obj->name),obj);
}

void dictExObjectMapRelease(void)
{
    if(gExObjectMap)
        dictRelease(gExObjectMap);
}

// =============================================