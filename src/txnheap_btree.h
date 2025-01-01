// This is a modified version of btree.c written by
// Joshua J Baker.
//
// Original source:
//    https://github.com/tidwall/btree.c/blob/master/btree.c
//
// Original copyright:
//    Copyright 2020 Joshua J Baker. All rights reserved.
//    Use of this source code is governed by an MIT-style
//    license that can be found in the LICENSE file.
//
//
// Modifications:
//
//    A minimal btree struct has been added called btree_data
//    that tracks the root, count, and height of the tree. This
//    is what is expected to be stored in the TXNHEAP memory region.
//
//    The btree code first expects to be opened (by passing a TxnHeap
//    txn and a pointer to btree_data in the TXNHEAP memory region),
//    and any subsequent operations will be stored inside the memory
//    region.
//
//    The copy-on-write functionality that Joshua wrote is repurposed
//    here to allow us to update the tree within the transaction we're
//    given in a fully atomic and isolated manner. Once you're done with
//    all updates you can call btree_done(), which will return you the
//    new btree_data of the final tree. Storing the as the root of the
//    TxnHeap and then committing the transaction will make all the changes
//    visible to other threads/processes.
//
//    Finally, children pointers have been replaced with offsets, and
//    the items pointer has been removed, which means the entire
//    tree structure is position invariant and works just the same
//    no matter what the absolute location is of the TxnHeap memory
//    region.
//
//
#ifndef TXNHEAP_BTREE_H
#define TXNHEAP_BTREE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "txnheap.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct btree;

// btree_new creates a new btree context manager that you can
// use to access/operate on a btree stored in a TxnHeap.
struct btree* txnheap_btree_new(
    size_t elsize, size_t max_items,
    int (*compare)(const void* a, const void* b, void* udata),
    void* udata
);

// btree_set_item_callbacks sets the item clone and free callbacks that will be
// called internally by the btree when items are inserted and removed.
//
// These callbacks are optional but may be needed by programs that require
// copy-on-write support by using the btree_clone function.
//
// The clone function should return true if the clone succeeded or false if the
// system is out of memory.
void txnheap_btree_set_item_callbacks(struct btree *btree,
    bool (*clone)(const void *item, void *into, void *udata), 
    void (*free)(const void *item, void *udata));

// btree_new will instantiate a new btree inside a TxnHeap, returning the
// root data which can be passed to a btree_ctx_open() to operate on the tree.
void* txnheap_btree_create(TXP_txn* txn);

// btree_ctx_open lets you open up a btree stored in a TxnHeap provided
// with a read or write transaction and a pointer to the data where
// the btree lives.
void txnheap_btree_open(struct btree* btree, TXP_txn* txn, void* data);

// btree_done can be called when you're done operating on the btree,
// this will return you a pointer to the new root data of the btree.
void* txnheap_btree_done(struct btree* btree);

// btree_free can be called to destroy the context (this will not clear
// or destroy the btree itself.)
void txnheap_btree_free(struct btree* btree);

// btree_destroy removes all items from the btree and frees the btree data.
// This does not free the btree context.
void txnheap_btree_destroy(struct btree *btree);

// btree_oom returns true if the last write operation failed because the system
// has no more memory available.
// 
// Functions that have the first param being a non-const btree receiver are 
// candidates for possible out-of-memory conditions, such as btree_set, 
// btree_delete, btree_load, etc.
bool txnheap_btree_oom(const struct btree *btree);

// btree_height returns the height of the btree from root to leaf or zero if
// the btree is empty.
size_t txnheap_btree_height(const struct btree *btree);

// btree_count returns the number of items in the btree.
size_t txnheap_btree_count(const struct btree *btree);

// btree_set inserts or replaces an item in the btree. If an item is replaced
// then it is returned otherwise NULL is returned. 
//
// If the system fails allocate the memory needed then NULL is returned 
// and btree_oom() returns true.
const void *txnheap_btree_set(struct btree *btree, const void *item);

// btree_delete removes an item from the B-tree and returns it.
//
// Returns NULL if item not found.
// This operation may trigger node copies if the btree was cloned using
// btree_clone.
// If the system fails allocate the memory needed then NULL is returned 
// and btree_oom() returns true.
const void *txnheap_btree_delete(struct btree *btree, const void *key);

// btree_load is the same as btree_set but is optimized for sequential bulk 
// loading. It can be up to 10x faster than btree_set when the items are
// in exact order, but up to 25% slower when not in exact order.
//
// If the system fails allocate the memory needed then NULL is returned 
// and btree_oom() returns true.
const void *txnheap_btree_load(struct btree *btree, const void *item);

// btree_pop_min removes the first item in the btree and returns it.
//
// Returns NULL if btree is empty.
// This operation may trigger node copies if the btree was cloned using
// btree_clone.
// If the system fails allocate the memory needed then NULL is returned 
// and btree_oom() returns true.
const void *txnheap_btree_pop_min(struct btree *btree);

// btree_pop_min removes the last item in the btree and returns it.
//
// Returns NULL if btree is empty.
// This operation may trigger node copies if the btree was cloned using
// btree_clone.
// If the system fails allocate the memory needed then NULL is returned 
// and btree_oom() returns true.
const void *txnheap_btree_pop_max(struct btree *btree);

// btree_pop_min returns the first item in the btree or NULL if btree is empty.
const void *txnheap_btree_min(const struct btree *btree);

// btree_pop_min returns the last item in the btree or NULL if btree is empty.
const void *txnheap_btree_max(const struct btree *btree);

// btree_get returns the item based on the provided key. 
//
// Returns NULL if item is not found.
const void *txnheap_btree_get(const struct btree *btree, const void *key);

// btree_ascend scans the tree within the range [pivot, last].
//
// In other words btree_ascend iterates over all items that are 
// greater-than-or-equal-to pivot in ascending order.
//
// Param pivot can be NULL, which means all items are iterated over.
// Param iter can return false to stop iteration early.
// Returns false if the iteration has been stopped early.
bool txnheap_btree_ascend(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata);

// btree_descend scans the tree within the range [pivot, first]. 

// In other words btree_descend() iterates over all items that are 
// less-than-or-equal-to pivot in descending order.
//
// Param pivot can be NULL, which means all items are iterated over.
// Param iter can return false to stop iteration early.
// Returns false if the iteration has been stopped early.
bool txnheap_btree_descend(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), void *udata);

// btree_set_hint is the same as btree_set except that an optional "hint" can 
// be provided which may make the operation quicker when done as a batch or 
// in a userspace context.
const void *txnheap_btree_set_hint(struct btree *btree, const void *item,
    uint64_t *hint);

// btree_get_hint is the same as btree_get except that an optional "hint" can 
// be provided which may make the operation quicker when done as a batch or 
// in a userspace context.
const void *txnheap_btree_get_hint(const struct btree *btree, const void *key,
    uint64_t *hint);

// btree_delete_hint is the same as btree_delete except that an optional "hint"
// can be provided which may make the operation quicker when done as a batch or 
// in a userspace context.
const void *txnheap_btree_delete_hint(struct btree *btree, const void *key,
    uint64_t *hint);

// btree_ascend_hint is the same as btree_ascend except that an optional
// "hint" can be provided which may make the operation quicker when done as a
// batch or in a userspace context.
bool txnheap_btree_ascend_hint(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), 
    void *udata, uint64_t *hint);

// btree_descend_hint is the same as btree_descend except that an optional
// "hint" can be provided which may make the operation quicker when done as a
// batch or in a userspace context.
bool txnheap_btree_descend_hint(const struct btree *btree, const void *pivot, 
    bool (*iter)(const void *item, void *udata), 
    void *udata, uint64_t *hint);

// btree_set_searcher allows for setting a custom search function.
void txnheap_btree_set_searcher(struct btree *btree, 
    int (*searcher)(const void *items, size_t nitems, const void *key, 
        bool *found, void *udata));

// Loop-based iterator
struct btree_iter *txnheap_btree_iter_new(const struct btree *btree);
void txnheap_btree_iter_free(struct btree_iter *iter);
bool txnheap_btree_iter_first(struct btree_iter *iter);
bool txnheap_btree_iter_last(struct btree_iter *iter);
bool txnheap_btree_iter_next(struct btree_iter *iter);
bool txnheap_btree_iter_prev(struct btree_iter *iter);
bool txnheap_btree_iter_seek(struct btree_iter *iter, const void *key);
const void *txnheap_btree_iter_item(struct btree_iter *iter);

#ifdef __cplusplus
}
#endif

#endif
