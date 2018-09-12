
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

object* objCreate(uint32_t type,void *ptr);
int objGetType(object *obj);
void* objGetVal(object *obj);
void objSdsPrint(object *obj);

uint64_t caseSdsHash(const void *key);
uint64_t sdsHash(const void *key);

void objDestructor(void *privdata, void *val);
void objSdsDestructor(void *privdata, void *val);
void objListDestructor(void *privdata, void *val);
void objDictDestructor(void *privdata, void *val);

void dictSdsObjDump(dict *dict);
int keySdsCompare(void *privdata, const void *key1, const void *key2);
int keyCaseSdsCompare(void *privdata, const void *key1, const void *key2);

dict *dictSdsObjCreate(void);
dict *dictCaseSdsObjCreate(void);
// list *listObjectCreate(void);
// list *listObjectDump(void);

#endif // _OBJECT_H_
