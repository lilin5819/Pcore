
#if !defined(_OBJECT_H_)
#define _OBJECT_H_

#include <stdint.h>
#include "sds.h"

#define OBJ_NONE 0
#define OBJ_STRING 1
#define OBJ_NUM 2
#define OBJ_LIST 3
#define OBJ_DICT 4
#define OBJ_POINTER 5
#define OBJ_EXT 255

typedef struct object {
    uint32_t type;
    void *ptr;
} object;

object* objectCreate(uint32_t type,void *ptr);
int objectGetType(object *obj);
void* objectGetVal(object *obj);
void objectSdsPrint(object *obj);
void objectDestructor(void *privdata, void *val);
void objectSdsDestructor(void *privdata, void *val);
void objectListDestructor(void *privdata, void *val);
void objectDictDestructor(void *privdata, void *val);

uint64_t dictSdsCaseHash(const void *key);
uint64_t dictSdsHash(const void *key);
void dictDumpKVInfo(dictEntry *de);
void dictDump(dict *dict);
void dictPrintSdsPair(dictEntry *de);
int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2);
int dictSdsKeyCaseCompare(void *privdata, const void *key1, const void *key2);

dict *dictSdsCreate(void);
dict *dictCaseSdsCreate(void);
// list *listObjectCreate(void);
// list *listObjectDump(void);

#endif // _OBJECT_H_
