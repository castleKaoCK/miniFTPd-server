#include "common.h"
#include "hash.h"
#include <assert.h>

//哈希节点
typedef struct hash_node{
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;

//哈希表结构
struct hash{
	unsigned int buckets;
	hashfunc_t hash_func;
	hash_node_t ** nodes;
};


hash_node_t ** hash_get_bucket(hash_t *hash, void *key);	//获取桶地址
hash_node_t * hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size);	//根据key获取哈希表中的一个节点


hash_t* hash_alloc(unsigned int buckets, hashfunc_t hash_func)	//创建哈希表
{
	hash_t *hash = (hash_t *)malloc(sizeof(hash_t));
	assert(hash != NULL);
	hash->buckets = buckets;		//指定桶大小
	hash->hash_func = hash_func;	//指定哈希函数
	int size = buckets * sizeof(hash_node_t*);
	hash->nodes = (hash_node_t **)malloc(size);	//创建桶集合
	memset(hash->nodes, 0, size);
	return hash;
}

void* hash_lookup_entry(hash_t *hash, void *key, unsigned int key_size)	//在哈希表中查找
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if(node == NULL)
	{
		return NULL;
	}

	return node->value;
}

void hash_add_entry(hash_t *hash, void *key, unsigned int key_size, void *value, unsigned int value_size)	//在哈希表中添加一项
{
	if(hash_lookup_entry(hash, key, key_size))
	{
		fprintf(stderr, "duplicate hash key\n");
		return ;
	}

	hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
	node->prev = NULL;
	node->next = NULL;

	node->key = malloc(key_size);
	memcpy(node->key, key, key_size);

	node->value = malloc(value_size);
	memcpy(node->value, value, value_size);

	hash_node_t ** bucket = hash_get_bucket(hash, key);	//获得插入桶的位置
	if(*bucket == NULL)
	{
		*bucket = node;
	}
	else
	{	
		//将新节点插入链表头部
		node->next = *bucket;
		(*bucket)->prev = node;
		*bucket = node;
	}
}

void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)	//从哈希表中删除一项
{
	hash_node_t * node = hash_get_node_by_key(hash, key, key_size);
	if(node == NULL)
	{
		return ;
	}

	free(node->key);
	free(node->value);

	if(node->prev)
		node->prev->next = node->next;
	else
	{
		//该节点为链表头节点
		hash_node_t **bucket = hash_get_bucket(hash, key);
		*bucket = node->next;
	}
	if(node->next)
		node->next->prev = node->prev;
	
	free(node);

}


hash_node_t ** hash_get_bucket(hash_t *hash, void *key)	//获取桶地址
{
	unsigned int bucket = hash->hash_func(hash->buckets, key);
	if(bucket >= hash->buckets)
	{
		fprintf(stderr, "bad bucket lookup\n");
		exit(EXIT_FAILURE);
	}

	return &hash->nodes[bucket];
}

hash_node_t * hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)	//根据key获取哈希表中的一个节点
{
	hash_node_t ** bucket = hash_get_bucket(hash, key);
	hash_node_t * node = *bucket;
	if(node == NULL)
	{
		return NULL;
	}

	while(node != NULL && memcmp(node->key, key, key_size) != 0)
	{
		node = node->next;
	}

	return node;
}
