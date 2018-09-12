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

int objGetType(object *obj)
{
    if(!obj) return 0;
    return obj->type;
}

void* objGetVal(object *obj)
{
    if(!obj) return NULL;
    return obj->ptr;
}

void objSdsPrint(object *obj)
{
    ok(obj && objGetType(obj) == OBJ_STRING);
    log_string(objGetVal(obj));
}

object* objCreate(uint32_t type,void *ptr)
{
    object *obj = zmalloc(sizeof(*obj));
    if(obj){
        obj->type = type;
        obj->ptr = ptr;
    }
    return obj;
}

void objSdsDestructor(void *privdata, void *val)
{
    // log_();
    DICT_NOTUSED(privdata);
    sdsfree((sds)val);
}

void objListDestructor(void *privdata, void *val)
{
    // log_();
    DICT_NOTUSED(privdata);
    listRelease((list*)val);
}

void objDictDestructor(void *privdata, void *val)
{
    // log_();
    DICT_NOTUSED(privdata);
    dictRelease((dict*)val);
}

// TODO: switch case obj type , different free
void objDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; /* Lazy freeing will set value to NULL. */
    void * objVal = objGetVal(val);
    switch (objGetType(val))
    {
        case OBJ_NONE:
        case OBJ_NUM:
        break;
        case OBJ_STRING:
            objSdsDestructor(privdata,objVal);
        break;
        case OBJ_LIST:
            objListDestructor(privdata,objVal);
        break;
        case OBJ_DICT:
            objDictDestructor(privdata,objVal);
        break;
        default:
            zfree(objVal);
        break;
    }
    zfree(val);
}

/* A case insensitive version used for the command lookup table and other
 * places where case insensitive non binary-safe comparison is needed. */
int keyCaseSdsCompare(void *privdata, const void *key1, const void *key2)
{
    DICT_NOTUSED(privdata);

    return strcasecmp(key1, key2) == 0;
}

static inline void objDumpInfo(dictEntry *de)
{
    if(!de) return;
    object * obj = dictGetVal(de);
    sds buf = sdsempty();
    buf = sdscatprintf(buf,"key=\"%s\" ",(char*)dictGetKey(de));
    switch(objGetType(obj)){
        case OBJ_STRING:
            buf = sdscat(buf,"type=OBJ_STRING ");
            break;
        case OBJ_NUM:
            buf = sdscat(buf,"type=OBJ_NUM ");
            break;
        case OBJ_LIST:
            buf = sdscat(buf,"type=OBJ_LIST ");
            break;
        case OBJ_DICT:
            buf = sdscat(buf,"type=OBJ_DICT ");
            break;
        default: 
            buf = sdscat(buf,"type=UNKNOW ");
            break;
    }
    if(objGetType(obj) == OBJ_STRING)
        buf = sdscatprintf(buf,"val=\"%s\"",(char*)objGetVal(obj));
    else if(objGetType(obj) == OBJ_NUM)
        buf = sdscatprintf(buf,"val=\"%d\"",(int)objGetVal(obj));
    
    buf = sdscat(buf,"\n");
    log_printf(buf);
    sdsfree(buf);
}

void dictObjDump(dict *objDict)
{
    dictEntry *de = NULL;
    dictIterator *it = dictGetIterator(objDict);
    while((de = dictNext(it)) != NULL){
        objDumpInfo(de);
    }
    dictReleaseIterator(it);
}

int keySdsCompare(void *privdata, const void *key1, const void *key2)
{
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}


uint64_t caseSdsHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t sdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}


/* sdscase --> obj */
dictType dictCaseSdsObjType = {
    caseSdsHash,            /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    keyCaseSdsCompare,      /* key compare */
    objSdsDestructor,          /* key destructor */
    objDestructor           /* val destructor */
};

/* sds --> obj */
dictType dictSdsObjType = {
    sdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    keySdsCompare,          /* key compare */
    objSdsDestructor,          /* key destructor */
    objDestructor           /* val destructor */
};

dict *dictSdsObjCreate(void)
{
    return dictCreate(&dictSdsObjType,NULL);
}

dict *dictCaseSdsObjCreate(void)
{
    return dictCreate(&dictCaseSdsObjType,NULL);
}