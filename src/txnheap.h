//
//
//
//              _______  ___   _   _   _ _____    _    ____
//             |_   _\ \/ / \ | | | | | | ____|  / \  |  _ \
//               | |  \  /|  \| | | |_| |  _|   / _ \ | |_) |
//               | |  /  \| |\  | |  _  | |___ / ___ \|  __/
//               |_| /_/\_\_| \_| |_| |_|_____/_/   \_\_|
//
//
//
//                    A TRANSACTIONAL HEAP ALLOCATOR
//                           Bartholomew Joyce
//
//
//   TxnHeap is a utility that helps manage any arbitrary data structure
//   that needs to be backed by a heap (e.g. trees or graphs), where you
//   want concurrent read/single write access using a transaction paradigm.
//
//   You provide a TxnHeap with a fixed buffer, and within this buffer you
//   will be able to alloc(), realloc() and free() heap nodes.
//
//   The critical functionality in a TxnHeap is that it allows for multiple
//   lock-free readers to read from the heap and one writer that can update
//   the heap. If the data structure you store in the heap is immutable
//   (i.e. no nodes mutated in-place, instead new nodes are created) then
//   readers will be able to read the entire data structure in a perfectly
//   valid state regardless of whether a writer is in the process of forming
//   a new state.
//
//   (This is achieved by deferring any frees on nodes who have open readers
//   to take effect after these readers are closed.)
//
//   In short, a Sheap is ~almost~ ACID-complaint:
//     - atomicity:   Yes, when writing, if you commit, all your writes will
//                    become visible to future readers, and if you abort,
//                    none of your writes will be visible.
//     - consistency: Depends on your data structure, Sheap does nothing to
//                    stop you from putting the data structure into an invalid
//                    state. But equally, it doesn't get in your way, either.
//     - isolation:   Yes, reads do not affect writes, and writes do not
//                    affect reads.
//     - durability:  No, Sheap is not persistent. You could in theory memory
//                    map it to a file, but there's no recovery mechanism
//                    for when your application crashes.
//
//   Advanced Mode: If you're willing to forego atomicity and isolation, you
//   are completely free to mutate nodes in-place. Sheap doesn't do anything
//   to stop you. So long as your mutations transition your data structure
//   from one valid state to another, this should work fine.
//
//

#ifndef TXNHEAP_H
#define TXNHEAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

//
// Environment API
//
//  You start by allocating an environment and providing a fixed buffer
//  that you want the Sheap to manage. Once you've done this you can call
//  txnheap_env_init() to have Sheap populate the buffer with its general
//  book-keeping data structures (you only need to do this once, if you
//  are opening up a Sheap that's already been created in another process
//  you only need to call txnheap_env_alloc()).
//
typedef struct TXP_env TXP_env;
TXP_env* txnheap_env_alloc(uint8_t* buffer, size_t buffer_size);
bool txnheap_env_init(TXP_env* txnheap);
void txnheap_env_free(TXP_env** txnheap);

//
// Transaction API
//
//  Transactions can be allocated once and reused many times. Whenever you
//  want to read or write, you can open a transaction either in RDONLY or
//  RDWR mode.
//
//  It is very important to close readers once you're done, since if you
//  don't close them they will prevent heap nodes from being properly cleaned
//  up.
//
//  For RDONLY transactions txnheap_txn_commit() and txnheap_txn_abort() are
//  identical and serve the purpose of closing the read transaction.
//
//  For RDWR transactions txnheap_txn_commit() will make your new root visible
//  to future transactions, and txnheap_txn_abort() will rollback any changes you
//  made and the root will not be updated.
//
//
#define TXP_RDONLY 0
#define TXP_RDWR 1
typedef struct TXP_txn TXP_txn;
TXP_txn* txnheap_txn_alloc();
void txnheap_txn_free(TXP_txn** txn);
bool txnheap_txn_begin(TXP_env* env, TXP_txn* txn, int mode);
void txnheap_txn_commit(TXP_txn* txn);
void txnheap_txn_abort(TXP_txn* txn);

//
// Core API
//
//  RDONLY & RDWR: For either types of transactions you can call txnheap_get_root()
//  to get the current root object pointer, from which you can access your data
//  structure in its entirety.
//
//  RDWR: For write transactions, you are further able to call txnheap_set_root() to
//  set the root object to something new (this will take effect after committing).
//
//  To update nodes you can call txnheap_alloc(), txnheap_realloc() and txnheap_free().
//  When you want to mutate some data node, you should first call txnheap_realloc()
//  on the data, passing the same size, and you'll get a fresh copy that can
//  be mutated without readers seeing it.
//
//  Successive calls to realloc() with the same size and data paremeters within the
//  same transaction will not re-clone the data each time. It will be cloned once
//  the first time, and then all subsequent calls will be no-ops.
//
//  Generally, to get the right ACID behaviour you should always realloc() nodes
//  before mutating.
//
//
void* txnheap_get_root(const TXP_txn* txn);
void txnheap_set_root(TXP_txn* txn, void* root);
TXP_env* txnheap_get_env(const TXP_txn* txn);
void* txnheap_alloc(TXP_txn* txn, size_t size);
void* txnheap_realloc(TXP_txn* txn, void* ptr, size_t size);
void txnheap_free(TXP_txn* txn, void* ptr);

//
// Utilities
//
//  To allow for sharing data structures across processes through shared
//  memory, it is necessary to use relative pointers or relative offsets
//  instead of absolute pointers. The following utility functions let you
//  convert between a 32-bit unsigned offset (from the start of the buffer)
//  and their absolute pointers.
//
//
void* txnheap_off_to_ptr(const TXP_txn* txn, uint32_t off);
uint32_t txnheap_ptr_to_off(const TXP_txn* txn, const void* ptr);

#ifdef __cplusplus
}
#endif

#endif
