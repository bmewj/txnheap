// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#ifndef TXNHEAP_BTREE_STATIC
#include "txnheap_btree.h"
#else
#define TXNHEAP_BTREE_EXTERN static
#endif

#ifndef TXNHEAP_BTREE_EXTERN
#define TXNHEAP_BTREE_EXTERN
#endif

enum btree_delact {
    BTREE_DELKEY, BTREE_POPFRONT, BTREE_POPBACK, BTREE_POPMAX,
};

static size_t btree_align_size(size_t size) {
    size_t boundary = sizeof(uintptr_t);
    return size < boundary ? boundary :
           size&(boundary-1) ? size+boundary-(size&(boundary-1)) : 
           size;
}

struct btree_node {
    bool leaf;
    size_t nitems:16;
    uint32_t children[];
};

struct btree_data {
    uint32_t root;
    uint32_t count;
    uint32_t height;
};

struct btree {
    TXP_txn *txn;
    struct btree_data *data;
    int (*compare)(const void *a, const void *b, void *udata);
    int (*searcher)(const void *items, size_t nitems, const void *key,
        bool *found, void *udata);
    bool (*item_clone)(const void *item, void *into, void *udata);
    void (*item_free)(const void *item, void *udata);
    void *udata;             // user data
    struct btree_node *root; // root node or NULL if empty tree
    size_t count;            // number of items in tree
    size_t height;           // height of tree from root to leaf
    size_t max_items;        // max items allowed per node before needing split
    size_t min_items;        // min items allowed per node before needing join
    size_t elsize;           // size of user item
    bool oom;                // last write operation failed due to no memory
    size_t spare_elsize;     // size of each spare element. This is aligned
    char spare_data[];       // spare element spaces for various operations
};

static void *btree_spare_at(const struct btree *btree, size_t index) {
    return (void*)(btree->spare_data+btree->spare_elsize*index);
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_set_searcher(struct btree *btree, 
    int (*searcher)(const void *items, size_t nitems, const void *key, 
        bool *found, void *udata))
{
    btree->searcher = searcher;
}

#define BTREE_NSPARES 4
#define BTREE_SPARE_RETURN btree_spare_at(btree, 0) // returned values
#define BTREE_SPARE_NODE   btree_spare_at(btree, 1) // clone in btree_node_copy
#define BTREE_SPARE_POPMAX btree_spare_at(btree, 2) // btree_delete popmax
#define BTREE_SPARE_CLONE  btree_spare_at(btree, 3) // cloned inputs 

static struct btree_node* btree_get_child_at(struct btree *btree, struct btree_node *node,
    size_t index)
{
    return txnheap_off_to_ptr(btree->txn, node->children[index]);
}

static struct btree_node* btree_set_child_at(struct btree *btree, struct btree_node *node,
    size_t index, struct btree_node *child)
{
    node->children[index] = txnheap_ptr_to_off(btree->txn, child);
}

static char *btree_get_items(const struct btree *btree, struct btree_node *node) {
    size_t items_offset = sizeof(struct btree_node);
    if (!node->leaf) {
        items_offset += sizeof(uint32_t)*(btree->max_items+1);
    }
    return (char*)node + items_offset;
}

static void *btree_get_item_at(struct btree *btree, struct btree_node *node, 
    size_t index)
{
    return btree_get_items(btree, node) + btree->elsize*index;
}

static void btree_set_item_at(struct btree *btree, struct btree_node *node,
    size_t index, const void *item) 
{
    void *slot = btree_get_item_at(btree, node, index);
    memcpy(slot, item, btree->elsize);
}

static void btree_swap_item_at(struct btree *btree, struct btree_node *node,
    size_t index, const void *item, void *into)
{ 
    void *ptr = btree_get_item_at(btree, node, index);
    memcpy(into, ptr, btree->elsize);
    memcpy(ptr, item, btree->elsize);
}

static void btree_copy_item_into(struct btree *btree, 
    struct btree_node *node, size_t index, void *into)
{ 
    memcpy(into, btree_get_item_at(btree, node, index), btree->elsize);
}

static void btree_node_shift_right(struct btree *btree, struct btree_node *node,
    size_t index)
{
    size_t num_items_to_shift = node->nitems - index;
    memmove(btree_get_items(btree, node) + btree->elsize*(index+1),
            btree_get_items(btree, node) + btree->elsize*index,
            num_items_to_shift*btree->elsize);
    if (!node->leaf) {
        memmove(&node->children[index+1], &node->children[index],
            (num_items_to_shift+1)*sizeof(*node->children));
    }
    node->nitems++;
}

static void btree_node_shift_left(struct btree *btree, struct btree_node *node,
    size_t index, bool for_merge) 
{
    size_t num_items_to_shift = node->nitems - index - 1;
    memmove(btree_get_items(btree, node) + btree->elsize*index,
            btree_get_items(btree, node) + btree->elsize*(index+1),
            num_items_to_shift*btree->elsize);
    if (!node->leaf) {
        if (for_merge) {
            index++;
            num_items_to_shift--;
        }
        memmove(&node->children[index], &node->children[index+1],
            (num_items_to_shift+1)*sizeof(*node->children));
    }
    node->nitems--;
}

static void btree_copy_item(struct btree *btree, struct btree_node *node_a,
    size_t index_a, struct btree_node *node_b, size_t index_b) 
{
    memcpy(btree_get_item_at(btree, node_a, index_a), 
        btree_get_item_at(btree, node_b, index_b), btree->elsize);
}

static void btree_node_join(struct btree *btree, struct btree_node *left,
    struct btree_node *right)
{
    memcpy(btree_get_items(btree, left) + btree->elsize*left->nitems,
           btree_get_items(btree, right),
           right->nitems*btree->elsize);
    if (!left->leaf) {
        memcpy(&left->children[left->nitems], &right->children[0],
            (right->nitems+1)*sizeof(*left->children));
    }
    left->nitems += right->nitems;
}

static int _btree_compare(const struct btree *btree, const void *a, 
    const void *b)
{
    return btree->compare(a, b, btree->udata);
}

static size_t btree_node_bsearch(const struct btree *btree,
    struct btree_node *node, const void *key, bool *found) 
{
    size_t i = 0;
    size_t n = node->nitems;
    while ( i < n ) {
        size_t j = (i + n) >> 1;
        void *item = btree_get_item_at((void*)btree, node, j);
        int cmp = _btree_compare(btree, key, item);
        if (cmp == 0) {
            *found = true;
            return j;
        } else if (cmp < 0) {
            n = j;
        } else {
            i = j+1;
        }
    }
    *found = false;
    return i;
}

static int btree_node_bsearch_hint(const struct btree *btree,
    struct btree_node *node, const void *key, bool *found, uint64_t *hint,
    int depth) 
{
    int low = 0;
    int high = node->nitems-1;
    if (hint && depth < 8) {
        size_t index = (size_t)((uint8_t*)hint)[depth];
        if (index > 0) {
            if (index > (size_t)(node->nitems-1)) {
                index = node->nitems-1;
            }
            void *item = btree_get_item_at((void*)btree, node, (size_t)index);
            int cmp = _btree_compare(btree, key, item);
            if (cmp == 0) {
                *found = true;
                return (int)index;
            }
            if (cmp > 0) {
                low = (int)(index+1);
            } else {
                high = (int)(index-1);
            }
        }
    }
    int index;
    while ( low <= high ) {
        int mid = (low + high) / 2;
        void *item = btree_get_item_at((void*)btree, node, (size_t)mid);
        int cmp = _btree_compare(btree, key, item);
        if (cmp == 0) {
            *found = true;
            index = mid;
            goto done;
        }
        if (cmp < 0) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    *found = false;
    index = low;
done:
    if (hint && depth < 8) {
        ((uint8_t*)hint)[depth] = (uint8_t)index;
    }
    return index;
}

static size_t btree_memsize(size_t elsize, size_t *spare_elsize) {
    size_t size = btree_align_size(sizeof(struct btree));
    size_t elsize_aligned = btree_align_size(elsize);
    size += elsize_aligned * BTREE_NSPARES;
    if (spare_elsize) *spare_elsize = elsize_aligned;
    return size;
}

TXNHEAP_BTREE_EXTERN
struct btree* txnheap_btree_new(size_t elsize, size_t max_items,
    int (*compare)(const void *a, const void *b, void *udata), void *udata)
{
    // normalize max_items
    size_t spare_elsize;
    size_t size = btree_memsize(elsize, &spare_elsize);
    struct btree *btree = malloc(size);
    if (!btree) {
        return NULL;
    }
    memset(btree, 0, size);
    size_t deg = max_items/2;
    deg = deg == 0 ? 128 : deg == 1 ? 2 : deg;
    btree->max_items = deg*2 - 1; // max items per node. max children is +1
    if (btree->max_items > 2045) {
        // there must be a reasonable limit.
        btree->max_items = 2045;
    }
    btree->min_items = btree->max_items / 2;
    btree->compare = compare;
    btree->elsize = elsize;
    btree->udata = udata;
    btree->spare_elsize = spare_elsize;
    return btree;
}

TXNHEAP_BTREE_EXTERN
void* txnheap_btree_create(TXP_txn *txn) {
    struct btree_data* data = txnheap_alloc(txn, sizeof(struct btree_data));
    memset(data, 0, sizeof(*data));
    return data;
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_open(struct btree *btree, TXP_txn *txn, void *data) {
    btree->txn = txn;
    btree->data = data;
    btree->root = txnheap_off_to_ptr(txn, btree->data->root);
    btree->count = btree->data->count;
    btree->height = btree->data->height;
}

TXNHEAP_BTREE_EXTERN
void* txnheap_btree_done(struct btree* btree) {
    struct btree_data data_new;
    data_new.root = txnheap_ptr_to_off(btree->txn, btree->root);
    data_new.count = (uint32_t)btree->count;
    data_new.height = (uint32_t)btree->height;

    if (memcmp(&data_new, btree->data, sizeof(data_new)) == 0) {
        return btree->data;
    }

    btree->data = txnheap_realloc(btree->txn, btree->data, sizeof(struct btree_data));
    *btree->data = data_new;
    return btree->data;
}

static size_t btree_node_size(struct btree *btree, bool leaf) {
    size_t size = sizeof(struct btree_node);
    if (!leaf) {
        // add children as flexible array
        size += sizeof(uint32_t)*(btree->max_items+1);
    }
    size += btree->elsize*btree->max_items;
    size = btree_align_size(size);
    return size;
}

static struct btree_node *btree_node_new(struct btree *btree, bool leaf) {
    size_t size = btree_node_size(btree, leaf);
    struct btree_node *node = txnheap_alloc(btree->txn, size);
    if (!node) {
        return NULL;
    }
    memset(node, 0, size);
    node->leaf = leaf;
    return node;
}

static void btree_node_free(struct btree *btree, struct btree_node *node) {
    if (!node->leaf) {
        for (size_t i = 0; i < (size_t)(node->nitems+1); i++) {
            btree_node_free(btree, btree_get_child_at(btree, node, i));
        }
    }
    if (btree->item_free) {
        for (size_t i = 0; i < node->nitems; i++) {
            void *item = btree_get_item_at(btree, node, i);
            btree->item_free(item, btree->udata);
        }
    }
    txnheap_free(btree->txn, node);
}

#define btree_node_mutate_or(bnode, code) { \
    struct btree_node *node1 = (bnode); \
    size_t size = btree_node_size(btree, node1->leaf); \
    struct btree_node *node2 = txnheap_realloc(btree->txn, node1, size); \
    if (!node2) { code; } \
    (bnode) = node2; \
}

#define btree_child_mutate_or(bnode, index, code) { \
    int child_idx = (int)(index); \
    struct btree_node *child1 = btree_get_child_at(btree, (bnode), child_idx); \
    size_t size = btree_node_size(btree, child1->leaf); \
    struct btree_node *child2 = txnheap_realloc(btree->txn, child1, size); \
    if (!child2) { code; } \
    btree_set_child_at(btree, (bnode), child_idx, child2); \
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_clear(struct btree *btree) {
    if (btree->root) {
        btree_node_free(btree, btree->root);
    }
    btree->oom = false;
    btree->root = NULL;
    btree->count = 0;
    btree->height = 0;
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_free(struct btree* btree) {
    free(btree);
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_destroy(struct btree *btree) {
    txnheap_btree_clear(btree);
    assert(0);
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_set_item_callbacks(struct btree *btree,
    bool (*clone)(const void *item, void *into, void *udata), 
    void (*free)(const void *item, void *udata))
{
    btree->item_clone = clone;
    btree->item_free = free;
}

static size_t btree_search(const struct btree *btree, struct btree_node *node,
    const void *key, bool *found, uint64_t *hint, int depth) 
{
    if (!hint && !btree->searcher) {
        return btree_node_bsearch(btree, node, key, found);
    }
    if (btree->searcher) {
        return btree->searcher(btree_get_items(btree, node), node->nitems, key, found,
            btree->udata);
    }
    return btree_node_bsearch_hint(btree, node, key, found, hint, depth);
}

enum btree_mut_result { 
    BTREE_NOCHANGE,
    BTREE_NOMEM,
    BTREE_MUST_SPLIT,
    BTREE_INSERTED,
    BTREE_REPLACED,
    BTREE_DELETED,
};

static void btree_node_split(struct btree *btree, struct btree_node *node,
    struct btree_node **right, void **median) 
{
    *right = btree_node_new(btree, node->leaf);
    if (!*right) {
        return; // NOMEM
    }
    size_t mid = btree->max_items / 2;
    *median = btree_get_item_at(btree, node, mid);
    (*right)->leaf = node->leaf;
    (*right)->nitems = node->nitems-(mid+1);
    memmove(btree_get_items(btree, *right),
            btree_get_items(btree, node) + btree->elsize*(mid+1),
            (*right)->nitems*btree->elsize);
    if (!node->leaf) {
        for (size_t i = 0; i <= (*right)->nitems; i++) {
            (*right)->children[i] = node->children[mid+1+i];
        }
    }
    node->nitems = mid;
}

static enum btree_mut_result btree_node_set(struct btree *btree,
    struct btree_node *node, const void *item, uint64_t *hint, int depth) 
{
    bool found = false;
    size_t i = btree_search(btree, node, item, &found, hint, depth);
    if (found) {
        btree_swap_item_at(btree, node, i, item, BTREE_SPARE_RETURN);
        return BTREE_REPLACED;
    }
    if (node->leaf) {
        if (node->nitems == btree->max_items) {
            return BTREE_MUST_SPLIT;
        }
        btree_node_shift_right(btree, node, i);
        btree_set_item_at(btree, node, i, item);
        return BTREE_INSERTED;
    }
    btree_child_mutate_or(node, i, return BTREE_NOMEM);
    enum btree_mut_result result = btree_node_set(btree, btree_get_child_at(btree, node, i),
        item, hint, depth+1);
    if (result == BTREE_INSERTED || result == BTREE_REPLACED) {
        return result;
    } else if (result == BTREE_NOMEM) {
        return BTREE_NOMEM;
    }
    // Split the child node
    if (node->nitems == btree->max_items) {
        return BTREE_MUST_SPLIT;
    }
    void *median = NULL;
    struct btree_node *right = NULL;
    btree_node_split(btree, btree_get_child_at(btree, node, i), &right, &median);
    if (!right) {
        return BTREE_NOMEM;
    }
    btree_node_shift_right(btree, node, i);
    btree_set_item_at(btree, node, i, median);
    btree_set_child_at(btree, node, i+1, right);
    return btree_node_set(btree, node, item, hint, depth);
}

static void *btree_set0(struct btree *btree, const void *item, uint64_t *hint,
    bool no_item_clone)
{
    btree->oom = false;
    bool item_cloned = false;
    if (btree->item_clone && !no_item_clone) {
        if (!btree->item_clone(item, BTREE_SPARE_CLONE, btree->udata)) {
            goto oom;
        }
        item = BTREE_SPARE_CLONE;
        item_cloned = true;
    }
    if (!btree->root) {
        btree->root = btree_node_new(btree, true);
        if (!btree->root) {
            goto oom;
        }
        btree_set_item_at(btree, btree->root, 0, item);
        btree->root->nitems = 1;
        btree->count++;
        btree->height++;
        return NULL;
    }
    btree_node_mutate_or(btree->root, goto oom);
    enum btree_mut_result result;
set:
    result = btree_node_set(btree, btree->root, item, hint, 0);
    if (result == BTREE_REPLACED) {
        if (btree->item_free) {
            btree->item_free(BTREE_SPARE_RETURN, btree->udata);
        }
        return BTREE_SPARE_RETURN;
    } else if (result == BTREE_INSERTED) {
        btree->count++;
        return NULL;
    } else if (result == BTREE_NOMEM) {
        goto oom;
    }
    void *old_root = btree->root;
    struct btree_node *new_root = btree_node_new(btree, false);
    if (!new_root) {
        goto oom;
    }
    struct btree_node *right = NULL;
    void *median = NULL;
    btree_node_split(btree, old_root, &right, &median);
    if (!right) {
        txnheap_free(btree->txn, new_root);
        goto oom;
    }
    btree->root = new_root;
    btree_set_child_at(btree, btree->root, 0, old_root);
    btree_set_item_at(btree, btree->root, 0, median);
    btree_set_child_at(btree, btree->root, 1, right);
    btree->root->nitems = 1;
    btree->height++;
    goto set;
oom:
    if (btree->item_free) {
        if (item_cloned) {
            btree->item_free(BTREE_SPARE_CLONE, btree->udata);
        }
    }
    btree->oom = true;
    return NULL;
}

static const void *btree_get0(const struct btree *btree, const void *key, 
    uint64_t *hint)
{
    struct btree_node *node = btree->root;
    if (!node) {
        return NULL;
    }
    bool found;
    int depth = 0;
    while (1) {
        size_t i = btree_search(btree, node, key, &found, hint, depth);
        if (found) {
            return btree_get_item_at((void*)btree, node, i);
        }
        if (node->leaf) {
            return NULL;
        }
        node = btree_get_child_at((void*)btree, node, i);
        depth++;
    }
}

static void btree_node_rebalance(struct btree *btree, struct btree_node *node,
    size_t i)
{
    if (i == node->nitems) {
        i--;
    }

    struct btree_node *left = btree_get_child_at(btree, node, i);
    struct btree_node *right = btree_get_child_at(btree, node, i+1);

    if (left->nitems + right->nitems < btree->max_items) {
        // Merges the left and right children nodes together as a single node
        // that includes (left,item,right), and places the contents into the
        // existing left node. Delete the right node altogether and move the
        // following items and child nodes to the left by one slot.

        // merge (left,item,right)
        btree_copy_item(btree, left, left->nitems, node, i);
        left->nitems++;
        btree_node_join(btree, left, right);
        txnheap_free(btree->txn, right);
        btree_node_shift_left(btree, node, i, true);
    } else if (left->nitems > right->nitems) {
        // move left -> right over one slot

        // Move the item of the parent node at index into the right-node first
        // slot, and move the left-node last item into the previously moved
        // parent item slot.
        btree_node_shift_right(btree, right, 0);
        btree_copy_item(btree, right, 0, node, i);
        if (!left->leaf) {
            btree_set_child_at(btree, right, 0, btree_get_child_at(btree, left, left->nitems));
        }
        btree_copy_item(btree, node, i, left, left->nitems-1);
        if (!left->leaf) {
            left->children[left->nitems] = 0;
        }
        left->nitems--;
    } else {
        // move right -> left

        // Same as above but the other direction
        btree_copy_item(btree, left, left->nitems, node, i);
        if (!left->leaf) {
            btree_set_child_at(btree, left, left->nitems+1, btree_get_child_at(btree, right, 0));
        }
        left->nitems++;
        btree_copy_item(btree, node, i, right, 0);
        btree_node_shift_left(btree, right, 0, false);
    }
}

static enum btree_mut_result btree_node_delete(struct btree *btree,
    struct btree_node *node, enum btree_delact act, size_t index,
    const void *key, void *prev, uint64_t *hint, int depth)
{
    size_t i = 0;
    bool found = false;
    if (act == BTREE_DELKEY) {
        i = btree_search(btree, node, key, &found, hint, depth);
    } else if (act == BTREE_POPMAX) {
        i = node->nitems-1;
        found = true;
    } else if (act == BTREE_POPFRONT) {
        i = 0;
        found = node->leaf;
    } else if (act == BTREE_POPBACK) {
        if (!node->leaf) {
            i = node->nitems;
            found = false;
        } else {
            i = node->nitems-1;
            found = true;
        }
    }
    if (node->leaf) {
        if (found) {
            // Item was found in leaf, copy its contents and delete it.
            // This might cause the number of items to drop below min_items,
            // and it so, the caller will take care of the rebalancing.
            btree_copy_item_into(btree, node, i, prev);
            btree_node_shift_left(btree, node, i, false);
            return BTREE_DELETED;
        }
        return BTREE_NOCHANGE;
    }
    enum btree_mut_result result;
    if (found) {
        if (act == BTREE_POPMAX) {
            // Popping off the max item into into its parent branch to maintain
            // a balanced tree.
            i++;
            btree_child_mutate_or(node, i, return BTREE_NOMEM);
            btree_child_mutate_or(node, i==node->nitems?i-1:i+1,
                return BTREE_NOMEM);
            result = btree_node_delete(btree, btree_get_child_at(btree, node, i), BTREE_POPMAX,
                0, NULL, prev, hint, depth+1);
            if (result == BTREE_NOMEM) {
                return BTREE_NOMEM;
            }
            result = BTREE_DELETED;
        } else {
            // item was found in branch, copy its contents, delete it, and 
            // begin popping off the max items in child nodes.
            btree_copy_item_into(btree, node, i, prev);
            btree_child_mutate_or(node, i, return BTREE_NOMEM);
            btree_child_mutate_or(node, i==node->nitems?i-1:i+1,
                return BTREE_NOMEM);
            result = btree_node_delete(btree, btree_get_child_at(btree, node, i), BTREE_POPMAX,
                0, NULL, BTREE_SPARE_POPMAX, hint, depth+1);
            if (result == BTREE_NOMEM) {
                return BTREE_NOMEM;
            }
            btree_set_item_at(btree, node, i, BTREE_SPARE_POPMAX);
            result = BTREE_DELETED;
        }
    } else {
        // item was not found in this branch, keep searching.
        btree_child_mutate_or(node, i, return BTREE_NOMEM);
        btree_child_mutate_or(node, i==node->nitems?i-1:i+1,
            return BTREE_NOMEM);
        result = btree_node_delete(btree, btree_get_child_at(btree, node, i), act, index, key,
            prev, hint, depth+1);
    }
    if (result != BTREE_DELETED) {
        return result;
    }
    if (btree_get_child_at(btree, node, i)->nitems < btree->min_items) {
        btree_node_rebalance(btree, node, i);
    }
    return BTREE_DELETED;
}

static void *btree_delete0(struct btree *btree, enum btree_delact act,
    size_t index, const void *key, uint64_t *hint) 
{
    btree->oom = false;
    if (!btree->root) {
        return NULL;
    }
    btree_node_mutate_or(btree->root, goto oom);
    enum btree_mut_result result = btree_node_delete(btree, btree->root, act,
        index, key, BTREE_SPARE_RETURN, hint, 0);
    if (result == BTREE_NOCHANGE) {
        return NULL;
    } else if (result == BTREE_NOMEM) {
        goto oom;
    }
    if (btree->root->nitems == 0) {
        struct btree_node *old_root = btree->root;
        if (!btree->root->leaf) {
            btree->root = btree_get_child_at(btree, btree->root, 0);
        } else {
            btree->root = NULL;
        }
        txnheap_free(btree->txn, old_root);
        btree->height--;
    }
    btree->count--;
    if (btree->item_free) {
        btree->item_free(BTREE_SPARE_RETURN, btree->udata);
    }
    return BTREE_SPARE_RETURN;
oom:
    btree->oom = true;
    return NULL;
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_set_hint(struct btree *btree, const void *item, 
    uint64_t *hint)
{
    return btree_set0(btree, item, hint, false);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_set(struct btree *btree, const void *item) {
    return btree_set0(btree, item, NULL, false);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_get_hint(const struct btree *btree, const void *key, 
    uint64_t *hint)
{
    return btree_get0(btree, key, hint);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_get(const struct btree *btree, const void *key) {
    return btree_get0(btree, key, NULL);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_delete_hint(struct btree *btree, const void *key, 
    uint64_t *hint)
{
    return btree_delete0(btree, BTREE_DELKEY, 0, key, hint);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_delete(struct btree *btree, const void *key) {
    return btree_delete0(btree, BTREE_DELKEY, 0, key, NULL);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_pop_min(struct btree *btree) {
    btree->oom = false;
    if (btree->root) {
        btree_node_mutate_or(btree->root, goto oom);
        struct btree_node *node = btree->root;
        while (1) {
            if (node->leaf) {
                if (node->nitems > btree->min_items) {
                    size_t i = 0;
                    btree_copy_item_into(btree, node, i, BTREE_SPARE_RETURN);
                    btree_node_shift_left(btree, node, i, false);
                    if (btree->item_free) {
                        btree->item_free(BTREE_SPARE_RETURN, btree->udata);
                    }
                    btree->count--;
                    return BTREE_SPARE_RETURN;
                }
                break;
            }
            btree_child_mutate_or(node, 0, goto oom);
            node = btree_get_child_at(btree, node, 0);
        }
    }
    return btree_delete0(btree, BTREE_POPFRONT, 0, NULL, NULL);
oom:
    btree->oom = true;
    return NULL;
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_pop_max(struct btree *btree) {
    btree->oom = false;
    if (btree->root) {
        btree_node_mutate_or(btree->root, goto oom);
        struct btree_node *node = btree->root;
        while (1) {
            if (node->leaf) {
                if (node->nitems > btree->min_items) {
                    size_t i = node->nitems-1;
                    btree_copy_item_into(btree, node, i, BTREE_SPARE_RETURN);
                    node->nitems--;
                    if (btree->item_free) {
                        btree->item_free(BTREE_SPARE_RETURN, btree->udata);
                    }
                    btree->count--;
                    return BTREE_SPARE_RETURN;
                }
                break;
            }
            btree_child_mutate_or(node, node->nitems, goto oom);
            node = btree_get_child_at(btree, node, node->nitems);
        }
    }
    return btree_delete0(btree, BTREE_POPBACK, 0, NULL, NULL);
oom:
    btree->oom = true;
    return NULL;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_oom(const struct btree *btree) {
    return !btree || btree->oom;
}

TXNHEAP_BTREE_EXTERN
size_t txnheap_btree_count(const struct btree *btree) {
    return btree->count;
}

TXNHEAP_BTREE_EXTERN
int txnheap_btree_compare(const struct btree *btree, const void *a, const void *b) {
    return _btree_compare(btree, a, b);
}

static bool btree_node_scan(const struct btree *btree, struct btree_node *node, 
    bool (*iter)(const void *item, void *udata), void *udata)
{
    if (node->leaf) {
        for (size_t i = 0; i < node->nitems; i++) {
            if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
                return false;
            }
        }
        return true;
    }
    for (size_t i = 0; i < node->nitems; i++) {
        if (!btree_node_scan(btree, btree_get_child_at((void*)btree, node, i), iter, udata)) {
            return false;
        }
        if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
            return false;
        }
    }
    return btree_node_scan(btree, btree_get_child_at((void*)btree, node, node->nitems), iter, udata);
}

static bool btree_node_ascend(const struct btree *btree,
    struct btree_node *node, 
    const void *pivot, bool (*iter)(const void *item, void *udata), 
    void *udata, uint64_t *hint, int depth) 
{
    bool found;
    size_t i = btree_search(btree, node, pivot, &found, hint, depth);
    if (!found) {
        if (!node->leaf) {
            if (!btree_node_ascend(btree, btree_get_child_at((void*)btree, node, i), pivot, iter, udata,
                hint, depth+1))
            {
                return false;
            }
        }
    }
    for (; i < node->nitems; i++) {
        if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
            return false;
        }
        if (!node->leaf) {
            if (!btree_node_scan(btree, btree_get_child_at((void*)btree, node, i+1), iter, udata)) {
                return false;
            }
        }
    }
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_ascend_hint(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata, uint64_t *hint) 
{
    if (btree->root) {
        if (!pivot) {
            return btree_node_scan(btree, btree->root, iter, udata);
        }
        return btree_node_ascend(btree, btree->root, pivot, iter, udata, hint, 
            0);
    }
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_ascend(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata) 
{
    return txnheap_btree_ascend_hint(btree, pivot, iter, udata, NULL);
}

static bool btree_node_reverse(const struct btree *btree,
    struct btree_node *node, 
    bool (*iter)(const void *item, void *udata), void *udata) 
{
    if (node->leaf) {
        size_t i = node->nitems - 1;
        while (1) {
            if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
                return false;
            }
            if (i == 0) break;
            i--;
        }
        return true;
    }
    if (!btree_node_reverse(btree, btree_get_child_at((void*)btree, node, node->nitems), iter,
        udata))
    {
        return false;
    }
    size_t i = node->nitems - 1;
    while (1) {
        if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
            return false;
        }
        if (!btree_node_reverse(btree, btree_get_child_at((void*)btree, node, i), iter, udata)) {
            return false;
        }
        if (i == 0) break;
        i--;
    }
    return true;
}

static bool btree_node_descend(const struct btree *btree, 
    struct btree_node *node, const void *pivot, 
    bool (*iter)(const void *item, void *udata), 
    void *udata, uint64_t *hint, int depth) 
{
    bool found;
    size_t i = btree_search(btree, node, pivot, &found, hint, depth);
    if (!found) {
        if (!node->leaf) {
            if (!btree_node_descend(btree, btree_get_child_at((void*)btree, node, i), pivot, iter,
                udata, hint, depth+1))
            {
                return false;
            }
        }
        if (i == 0) {
            return true;
        }
        i--;
    }
    while(1) {
        if (!iter(btree_get_item_at((void*)btree, node, i), udata)) {
            return false;
        }
        if (!node->leaf) {
            if (!btree_node_reverse(btree, btree_get_child_at((void*)btree, node, i), iter, udata)) {
                return false;
            }
        }
        if (i == 0) break;
        i--;
    }
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_descend_hint(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata, uint64_t *hint) 
{
    if (btree->root) {
        if (!pivot) {
            return btree_node_reverse(btree, btree->root, iter, udata);
        }
        return btree_node_descend(btree, btree->root, pivot, iter, udata, hint, 
            0);
    }
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_descend(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata) 
{
    return txnheap_btree_descend_hint(btree, pivot, iter, udata, NULL);
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_min(const struct btree *btree) {
    struct btree_node *node = btree->root;
    if (!node) {
        return NULL;
    }
    while (1) {
        if (node->leaf) {
            return btree_get_item_at((void*)btree, node, 0);
        }
        node = btree_get_child_at((void*)btree, node, 0);
    }
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_max(const struct btree *btree) {
    struct btree_node *node = btree->root;
    if (!node) {
        return NULL;
    }
    while (1) {
        if (node->leaf) {
            return btree_get_item_at((void*)btree, node, node->nitems-1);
        }
        node = btree_get_child_at((void*)btree, node, node->nitems);
    }
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_load(struct btree *btree, const void *item) {
    btree->oom = false;
    if (!btree->root) {
        return btree_set0(btree, item, NULL, false);
    }
    bool item_cloned = false;
    if (btree->item_clone) {
        if (!btree->item_clone(item, BTREE_SPARE_CLONE, btree->udata)) {
            goto oom;
        }
        item = BTREE_SPARE_CLONE;
        item_cloned = true;
    }
    btree_node_mutate_or(btree->root, goto oom);
    struct btree_node *node = btree->root;
    while (1) {
        if (node->leaf) {
            if (node->nitems == btree->max_items) break;
            void *litem = btree_get_item_at(btree, node, node->nitems-1);
            if (_btree_compare(btree, item, litem) <= 0) break;
            btree_set_item_at(btree, node, node->nitems, item);
            node->nitems++; 
            btree->count++;
            return NULL;
        }
        btree_child_mutate_or(node, node->nitems, goto oom);
        node = btree_get_child_at(btree, node, node->nitems);
    }
    const void *prev = btree_set0(btree, item, NULL, true);
    if (!btree->oom) {
        return prev;
    }
oom:
    if (btree->item_free && item_cloned) {
        btree->item_free(BTREE_SPARE_CLONE, btree->udata);
    }
    btree->oom = true;
    return NULL;
}

TXNHEAP_BTREE_EXTERN
size_t txnheap_btree_height(const struct btree *btree) {
    return btree->height;
}

struct btree_iter_stack_item {
    struct btree_node *node;
    int index;
};

struct btree_iter {
    struct btree *btree;
    void *item;
    bool seeked;
    bool atstart;
    bool atend;
    int nstack;
    struct btree_iter_stack_item stack[];
};

TXNHEAP_BTREE_EXTERN
struct btree_iter *txnheap_btree_iter_new(const struct btree *btree) {
    size_t vsize = btree_align_size(sizeof(struct btree_iter) + 
        sizeof(struct btree_iter_stack_item) * btree->height);
    struct btree_iter *iter = malloc(vsize + btree->elsize);
    if (iter) {
        memset(iter, 0, vsize + btree->elsize);
        iter->btree = (void*)btree;
        iter->item = (void*)((char*)iter + vsize);
    }
    return iter;
}

TXNHEAP_BTREE_EXTERN
void txnheap_btree_iter_free(struct btree_iter *iter) {
    free(iter);
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_iter_first(struct btree_iter *iter) {
    iter->atend = false;
    iter->atstart = false;
    iter->seeked = false;
    iter->nstack = 0;
    if (!iter->btree->root) {
        return false;
    }
    iter->seeked = true;
    struct btree_node *node = iter->btree->root;
    while (1) {
        iter->stack[iter->nstack++] = (struct btree_iter_stack_item) {
            .node = node,
            .index = 0,
        };
        if (node->leaf) {
            break;
        }
        node = btree_get_child_at(iter->btree, node, 0);
    }
    struct btree_iter_stack_item *stack = &iter->stack[iter->nstack-1];
    btree_copy_item_into(iter->btree, stack->node, stack->index, iter->item);
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_iter_last(struct btree_iter *iter) {
    iter->atend = false;
    iter->atstart = false;
    iter->seeked = false;
    iter->nstack = 0;
    if (!iter->btree->root) {
        return false;
    }
    iter->seeked = true;
    struct btree_node *node = iter->btree->root;
    while (1) {
        iter->stack[iter->nstack++] = (struct btree_iter_stack_item) {
            .node = node,
            .index = node->nitems,
        };
        if (node->leaf) {
            iter->stack[iter->nstack-1].index--;
            break;
        }
        node = btree_get_child_at(iter->btree, node, node->nitems);
    }
    struct btree_iter_stack_item *stack = &iter->stack[iter->nstack-1];
    btree_copy_item_into(iter->btree, stack->node, stack->index, iter->item);
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_iter_next(struct btree_iter *iter) {
    if (!iter->seeked) {
        return txnheap_btree_iter_first(iter);
    }
    struct btree_iter_stack_item *stack = &iter->stack[iter->nstack-1];
    stack->index++;
    if (stack->node->leaf) {
        if (stack->index == stack->node->nitems) {
            while (1) {
                iter->nstack--;
                if (iter->nstack == 0) {
                    iter->atend = true;
                    return false;
                }
                stack = &iter->stack[iter->nstack-1];
                if (stack->index < stack->node->nitems) {
                    break;
                }
            }
        }
    } else {
        struct btree_node *node = btree_get_child_at(iter->btree, stack->node, stack->index);
        while (1) {
            iter->stack[iter->nstack++] = (struct btree_iter_stack_item) {
                .node = node,
                .index = 0,
            };
            if (node->leaf) {
                break;
            }
            node = btree_get_child_at(iter->btree, node, 0);
        }
    }
    stack = &iter->stack[iter->nstack-1];
    btree_copy_item_into(iter->btree, stack->node, stack->index, iter->item);
    return true;
}

TXNHEAP_BTREE_EXTERN
bool txnheap_btree_iter_prev(struct btree_iter *iter) {
    if (!iter->seeked) {
        return false;
    }
    struct btree_iter_stack_item *stack = &iter->stack[iter->nstack-1];
    if (stack->node->leaf) {
        stack->index--;
        if (stack->index == -1) {
            while (1) {
                iter->nstack--;
                if (iter->nstack == 0) {
                    iter->atstart = true;
                    return false;
                }
                stack = &iter->stack[iter->nstack-1];
                stack->index--;
                if (stack->index > -1) {
                    break;
                }
            }
        }
    } else {
        struct btree_node *node = btree_get_child_at(iter->btree, stack->node, stack->index);
        while (1) {
            iter->stack[iter->nstack++] = (struct btree_iter_stack_item) {
                .node = node, 
                .index = node->nitems,
            };
            if (node->leaf) {
                iter->stack[iter->nstack-1].index--;
                break;
            }
            node = btree_get_child_at(iter->btree, node, node->nitems);
        }
    }
    stack = &iter->stack[iter->nstack-1];
    btree_copy_item_into(iter->btree, stack->node, stack->index, iter->item);
    return true;
}


TXNHEAP_BTREE_EXTERN
bool txnheap_btree_iter_seek(struct btree_iter *iter, const void *key) {
    iter->atend = false;
    iter->atstart = false;
    iter->seeked = false;
    iter->nstack = 0;
    if (!iter->btree->root) {
        return false;
    }
    iter->seeked = true;
    struct btree_node *node = iter->btree->root;
    while (1) {
        bool found;
        size_t i = btree_node_bsearch(iter->btree, node, key, &found);
        iter->stack[iter->nstack++] = (struct btree_iter_stack_item) {
            .node = node,
            .index = (int)i,
        };
        if (found) {
            btree_copy_item_into(iter->btree, node, i, iter->item);
            return true;
        }
        if (node->leaf) {
            iter->stack[iter->nstack-1].index--;
            return txnheap_btree_iter_next(iter);
        }
        node = btree_get_child_at(iter->btree, node, i);
    }
}

TXNHEAP_BTREE_EXTERN
const void *txnheap_btree_iter_item(struct btree_iter *iter) {
    return iter->item;
}
