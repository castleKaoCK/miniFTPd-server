#ifndef	_HASH_H_
#define	_HASH_H_

typedef struct hash hash_t;
typedef unsigned int (*hashfunc_t)(unsigned int, void *);


hash_t* hash_alloc(unsigned int buckets, hashfunc_t hash_func);	//创建哈希表
void* hash_lookup_entry(hash_t *hash, void *key, unsigned int key_size);	//在哈希表中查找
void hash_add_entry(hash_t *hash, void *key, unsigned int key_size, void *value, unsigned int value_size);	//在哈希表中添加一项
void hash_free_entry(hash_t *hash, void *key, unsigned int key_size);	//从哈希表中删除一项




#endif	//_HASH_H_

