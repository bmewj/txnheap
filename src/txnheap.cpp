#include "txnheap.h"

#include <assert.h>
#include <mutex>
#include <vector>
#include <deque>

using Word = uint32_t;
constexpr static size_t BIN_COUNT = 8;
constexpr static size_t MAX_READERS = 64;

struct NodeToFree {
    NodeToFree(Word gen, Word node_offset) : gen(gen), node_offset(node_offset) {}
    Word gen, node_offset;
};

/* TXP_base is stored and instantiated at the beginning of
   the shared memory buffer. The two mutexes for synchronising
   access needed by readers and writers, as well as all the
   bins of the heap allocator are stored here. */
struct TXP_base {
    std::mutex writer_mutex;
    std::mutex reader_mutex;
    Word bins[BIN_COUNT];
    struct Readers {
        Word start, end;
        Word gen[MAX_READERS];
        bool active[MAX_READERS];
    } readers;
    Word root = 0;
    Word gen = 0;
};

/* TXP_end is stored in each program individual. Multiple envs
   in the same process or in different processes can exist and
   operate on the same shared heap.

   The free_queue contains nodes that a writer has scheduled
   for deletion. This could theoretically also be stored in
   the heap itself, but for simplicity we're keeping this per-
   process. A writer thread is responsible for carrying out
   its own cleanup. */
struct TXP_env {
    Word* heap_begin;
    Word* heap_end;
    union {
        TXP_base* base;
        Word* heap_base;
    };
    std::deque<NodeToFree> free_queue;
};

struct TXP_txn {
    TXP_env* env;
    int mode;
    Word gen, root;
    std::vector<Word> new_node_offsets;
};

static void txnheap_free_immediate(TXP_env* env, Word* node);

/* Conversion between word offsets and word pointers */
static inline Word to_offset(const TXP_env* env, const Word* word) {
    if (word == nullptr) {
        return 0;
    }

    assert(word >= env->heap_base && word < env->heap_end);
    return Word(word - env->heap_base);
}
static inline Word* from_offset(const TXP_env* env, Word offset) {
    if (offset == 0) {
        return nullptr;
    }

    Word* word = env->heap_base + offset;
    assert(word >= env->heap_base && word < env->heap_end);
    return word;
}


/* Node manipulation */
static inline void set_node(Word* node, Word size, bool is_free, bool is_new) {
    node[0] = (size << 2) | (is_free ? 0x1 : 0) | (is_new ? 0x2 : 0);
    node[1 + size] = size;
}
static inline bool node_is_free(const Word* node) {
    return (node[0] & 0x1);
}
static inline bool node_is_new(const Word* node) {
    return (node[0] & 0x2);
}
static inline void mark_node_old(Word* node) {
    node[0] &= ~Word(0x2);
}
static inline void mark_node_free(Word* node) {
    node[0] |= 0x1;
}
static inline Word get_node_size(const Word* node) {
    return (node[0] >> 2);
}
static inline Word get_bin_index(Word size) {
    Word index = 0;
    while ((size >>= 1) && index < BIN_COUNT) {
        index++;
    }
    return (index - 1);
}
static inline Word get_bin_index(const Word* node) {
    return get_bin_index(get_node_size(node));
}


/* Functions for managing linked-list of free nodes */
static Word* llist_get_prev_node(TXP_env* env, Word* node) {
    assert(node_is_free(node));
    return from_offset(env, node[1]);
}
static Word* llist_get_next_node(TXP_env* env, Word* node) {
    assert(node_is_free(node));
    return from_offset(env, node[2]);
}
static void llist_set_prev_node(TXP_env* env, Word* node, const Word* prev) {
    if (prev == nullptr) {
        node[1] = 0;
    } else {
        node[1] = to_offset(env, prev);
    }
}
static void llist_set_next_node(TXP_env* env, Word* node, const Word* next) {
    if (next == nullptr) {
        node[2] = 0;
    } else {
        node[2] = to_offset(env, next);
    }
}
static void llist_add_node(TXP_env* env, Word* node) {
    assert(node && node_is_free(node) && get_node_size(node) >= 2);
    llist_set_next_node(env, node, nullptr);
    llist_set_prev_node(env, node, nullptr);

    Word* bin = &env->base->bins[get_bin_index(node)];

    // First entry for bin
    if (*bin == 0) {
        *bin = to_offset(env, node);
        return;
    }

    // Iterate through bin, break once we find a spot to insert
    Word* curr = from_offset(env, *bin);
    Word* prev = nullptr;
    while (curr != nullptr && get_node_size(curr) <= get_node_size(node)) {
        prev = curr;
        curr = llist_get_next_node(env, curr);
    }

    // Reached end
    if (curr == nullptr) {
        llist_set_next_node(env, prev, node);
        llist_set_prev_node(env, node, prev);
        return;
    }

    // Middle of list
    if (prev != nullptr) {
        llist_set_next_node(env, node, curr);
        llist_set_prev_node(env, node, prev);
        llist_set_next_node(env, prev, node);
        llist_set_prev_node(env, curr, node);
        return;
    }

    // Start of list
    Word* head = from_offset(env, *bin);
    llist_set_next_node(env, node, head);
    llist_set_prev_node(env, head, node);
    *bin = to_offset(env, node);
}
static void llist_remove_node(TXP_env* env, Word* node) {
    assert(node_is_free(node));

    Word* bin = &env->base->bins[get_bin_index(node)];
    assert(bin && *bin != 0);

    // First entry in bin?
    if (*bin == to_offset(env, node)) {
        *bin = to_offset(env, llist_get_next_node(env, node));
        if (*bin != 0) {
            llist_set_prev_node(env, from_offset(env, *bin), nullptr);
        }
        return;
    }

    // Somewhere else in bin...
    Word* prev = llist_get_prev_node(env, node);
    Word* next = llist_get_next_node(env, node);
    if (prev != nullptr) {
        assert(llist_get_next_node(env, prev) == node);
        llist_set_next_node(env, prev, next);
    }
    if (next != nullptr) {
        assert(llist_get_prev_node(env, next) == node);
        llist_set_prev_node(env, next, prev);
    }
}
static Word* llist_remove_best_node(TXP_env* env, Word word_size) {
    for (Word bin_idx = get_bin_index(word_size); bin_idx < BIN_COUNT; ++bin_idx) {
        if (env->base->bins[bin_idx] == 0) {
            continue;
        }

        Word* node = from_offset(env, env->base->bins[bin_idx]);
        for (; node != nullptr; node = llist_get_next_node(env, node)) {
            if (get_node_size(node) >= word_size) {
                llist_remove_node(env, node);
                return node;
            }
        }
    }
    return nullptr;
}


/* Utilities */
static bool add_reader(TXP_env* env, Word gen) {
    if (env->base->readers.end - env->base->readers.start >= MAX_READERS) {
        return false; // Too many readers!!!
    }

    Word idx = env->base->readers.end++;
    env->base->readers.gen[idx % MAX_READERS] = gen;
    env->base->readers.active[idx % MAX_READERS] = true;
    return true;
}
static void remove_reader(TXP_env* env, Word gen) {

    // Iterate through readers, removing an active reader with matching
    // generation.
    Word idx = env->base->readers.start;
    for (; idx < env->base->readers.end; ++idx) {
        if (env->base->readers.gen[idx % MAX_READERS] < gen) {
            continue;
        }
        assert(env->base->readers.gen[idx % MAX_READERS] == gen);
        if (!env->base->readers.active[idx % MAX_READERS]) {
            continue;
        }
        env->base->readers.active[idx % MAX_READERS] = false;
        break;
    }

    // Must have removed a reader!
    assert(idx != env->base->readers.end);

    // Cleanup readers
    while (env->base->readers.start <= idx) {
        if (!env->base->readers.active[env->base->readers.start % MAX_READERS]) {
            env->base->readers.start++;
        } else {
            break;
        }
    }
}
static Word get_active_gen(TXP_env* env) {
    if (env->base->readers.end > env->base->readers.start) {
        return env->base->readers.gen[env->base->readers.start % MAX_READERS];
    } else {
        return UINT32_MAX; // No generations are being referenced
    }
}
static void cleanup(TXP_env* env, Word active_gen) {
    // Cleanup will try freeing any entries that have been marked
    // for deletion that are not being referenced in or after the
    // current active_gen generation.

    // Go through all entries marked for deletions, deleting
    // those that are ready to delete.
    while (!env->free_queue.empty()) {

        auto& node_to_delete = env->free_queue.front();
        if (node_to_delete.gen > active_gen) {
            // Node is being referenced in the current active gen, can't
            // free it or any subsequent entries in the queue.
            break;
        }

        Word* node = from_offset(env, node_to_delete.node_offset);
        txnheap_free_immediate(env, node);
        env->free_queue.pop_front();
    }
}



/* Sheap API implementation */
TXP_env* txnheap_env_alloc(uint8_t* buffer, size_t buffer_size) {
    assert(buffer != nullptr);

    static constexpr Word BASE_SIZE = sizeof(TXP_base);
    static constexpr Word BASE_NUM_WORDS = (
        ((BASE_SIZE >> 2) + ((BASE_SIZE & 0x1) | ((BASE_SIZE & 0x2) >> 1))) | 1
    );

    Word num_words = Word(buffer_size / sizeof(Word));
    assert(num_words > BASE_NUM_WORDS + 32); // This buffer is WAY too small, man...
    num_words -= BASE_NUM_WORDS;

    TXP_env* env = new TXP_env;
    env->heap_base = reinterpret_cast<Word*>(buffer);
    env->heap_begin = env->heap_base + BASE_NUM_WORDS;
    env->heap_end = env->heap_begin + num_words;

    return env;
}

bool txnheap_env_init(TXP_env* env) {
    assert(env != nullptr);

    // Construct the base
    env->base = new(env->heap_base)TXP_base;
    memset(env->base->bins, 0, sizeof(env->base->bins));
    memset(&env->base->readers, 0, sizeof(env->base->readers));

    // Create an initial free node the size of the entire buffer
    Word num_words = Word(env->heap_end - env->heap_begin);
    set_node(env->heap_begin, num_words - 2, true, false);
    llist_add_node(env, env->heap_begin);

    return true;
}

void txnheap_env_free(TXP_env** txnheap_ptr) {
    TXP_env* env = nullptr;
    std::swap(env, *txnheap_ptr);
    delete env;
}

TXP_txn* txnheap_txn_alloc() {
    TXP_txn* txn = new TXP_txn;
    txn->mode = 0;
    txn->env = nullptr;
    txn->gen = 0;
    txn->root = 0;
    return txn;
}

void txnheap_txn_free(TXP_txn** txn_ptr) {
    TXP_txn* txn = nullptr;
    std::swap(txn, *txn_ptr);
    if (txn != nullptr) {
        assert(txn->gen == 0);
        delete txn;
    }
}

bool txnheap_txn_begin(TXP_env* env, TXP_txn* txn, int mode) {
    assert(env != nullptr && txn != nullptr && txn->gen == 0);
    assert(mode == TXP_RDONLY || mode == TXP_RDWR);
    txn->env = env;
    txn->mode = mode;
    if (mode == TXP_RDONLY) {
        assert(txn != nullptr && txn->gen == 0);
        std::unique_lock<std::mutex> lock(env->base->reader_mutex);
        if (!add_reader(env, env->base->gen)) {
            return false;
        }
        txn->gen = env->base->gen;
        txn->root = env->base->root;
    } else {
        env->base->writer_mutex.lock();

        Word active_gen;
        {
            std::unique_lock<std::mutex> lock(env->base->reader_mutex);
            txn->gen = env->base->gen + 1;
            txn->root = env->base->root;
            active_gen = get_active_gen(env);
        }

        cleanup(env, active_gen);
    }
    return true;
}

static void txnheap_txn_read_close(TXP_txn* txn) {
    std::unique_lock<std::mutex> lock(txn->env->base->reader_mutex);
    remove_reader(txn->env, txn->gen);
    txn->gen = 0;
    txn->root = 0;
}

void txnheap_txn_commit(TXP_txn* txn) {
    assert(txn != nullptr);
    if (txn->gen == 0) {
        return;
    } else if (txn->mode == TXP_RDONLY) {
        return txnheap_txn_read_close(txn);
    }

    Word active_gen;
    {
        std::unique_lock<std::mutex> lock(txn->env->base->reader_mutex);
        txn->env->base->root = txn->root;
        txn->env->base->gen = txn->gen;
        active_gen = get_active_gen(txn->env);
    }

    for (Word node_offset : txn->new_node_offsets) {
        Word* node = from_offset(txn->env, node_offset);
        mark_node_old(node);
    }
    txn->new_node_offsets.clear();

    cleanup(txn->env, active_gen);

    txn->gen = 0;
    txn->root = 0;
    txn->env->base->writer_mutex.unlock();
}

void txnheap_txn_abort(TXP_txn* txn) {
    if (txn == nullptr || txn->gen == 0) {
        return;
    } else if (txn->mode == TXP_RDONLY) {
        return txnheap_txn_read_close(txn);
    }

    // Free any nodes that were allocated during this write
    for (Word node_offset : txn->new_node_offsets) {
        Word* node = from_offset(txn->env, node_offset);
        txnheap_free_immediate(txn->env, node);
    }
    txn->new_node_offsets.clear();

    // Remove any nodes that were scheduled to be freed during this write
    for (auto it = txn->env->free_queue.begin(); it != txn->env->free_queue.end();) {
        if (it->gen < txn->gen) {
            ++it;
        } else {
            it = txn->env->free_queue.erase(it);
        }
    }

    txn->gen = 0;
    txn->root = 0;
    txn->env->base->writer_mutex.unlock();
}

void* txnheap_get_root(const TXP_txn* txn) {
    assert(txn != nullptr);
    return txnheap_off_to_ptr(txn, txn->root);
}

TXP_env* txnheap_get_env(const TXP_txn* txn) {
    assert(txn != nullptr);
    return const_cast<TXP_env*>(txn->env);
}

void txnheap_set_root(TXP_txn* txn, void* root) {
    assert(txn != nullptr && txn->gen != 0 && txn->mode == TXP_RDWR);
    txn->root = txnheap_ptr_to_off(txn, root);
}

static inline size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}
static inline Word to_word_size(size_t size) {
    assert(size < UINT32_MAX);
    size = (size >> 3) + ((size & 0x1) | ((size & 0x2) >> 1) | ((size & 0x4) >> 2));
    return Word(size << 1);
}

void* txnheap_alloc(TXP_txn* txn, size_t size) {
    assert(txn != nullptr && txn->gen != 0 && txn->mode == TXP_RDWR);

    // Align and print
    Word word_size = to_word_size(size);

    // Find a node that we can allocate into
    Word* found = llist_remove_best_node(txn->env, word_size);
    if (found == nullptr) {
        return nullptr; // Couldn't find any node!! OUT OF MEMORY
    }

    // Is this node large enough that we can split it?
    Word found_size = get_node_size(found);
    if ((found_size - word_size) >= 4) {

        Word split_size = found_size - word_size - 2;
        set_node(found, word_size, false, true);

        Word* split = found + word_size + 2;
        set_node(split, split_size, true, false);

        llist_add_node(txn->env, split);

    } else {
        set_node(found, found_size, false, true);
    }

    // Return the node!
    txn->new_node_offsets.push_back(to_offset(txn->env, found));
    // printf("txnheap_alloc(size: %d) -> %p\n", int(size), &found[1]);
    return &found[1];
}

void* txnheap_realloc(TXP_txn* txn, void* ptr, size_t size) {
    assert(txn != nullptr && txn->gen != 0 && txn->mode == TXP_RDWR);

    if (ptr == nullptr) {
        void* ptr2 = txnheap_alloc(txn, size);
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), ptr2);
        return ptr2;
    }
    if (size == 0) {
        txnheap_free(txn, ptr);
        return nullptr;
    }

    Word* node = static_cast<Word*>(ptr) - 1;
    assert(node >= txn->env->heap_begin && node < txn->env->heap_end);

    if (!node_is_new(node)) {
        // Node was created in an earlier generation, so we must
        // copy it out.
        void* ptr_new = txnheap_alloc(txn, size);
        memcpy(ptr_new, &node[1], min(get_node_size(node) * sizeof(Word), size));
        txn->env->free_queue.push_back(NodeToFree(txn->gen, to_offset(txn->env, node)));
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), ptr_new);
        return ptr_new;
    }

    Word new_size = to_word_size(size);
    Word old_size = get_node_size(node);

    // No size change (or decrease)?
    if (new_size == old_size) {
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p (no-op)\n", ptr, int(size), ptr);
        return ptr;
    }

    // Size decrease?
    if (new_size < old_size) {

        // Do we have a free node ahead of us?
        Word* next = node + old_size + 2;
        if (next + 4 <= txn->env->heap_end && node_is_free(next)) {
            // Adjust the node ahead of us
            Word next_old_size = get_node_size(next);
            Word next_new_size = next_old_size + (old_size - new_size);
            llist_remove_node(txn->env, next);

            next = node + new_size + 2;
            set_node(next, next_new_size, true, false);
            llist_add_node(txn->env, next);

            set_node(node, new_size, false, true);
            // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), &node[1]);
            return &node[1];
        }

        // Do we have space to create a new free node?
        if ((old_size - new_size) >= 4) {
            Word* next = node + new_size + 2;
            set_node(next, old_size - new_size - 2, true, false);
            llist_add_node(txn->env, next);

            set_node(node, new_size, false, true);
            // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), &node[1]);
            return &node[1];
        }

        // Not enough space to create a new node in the gap
        // that's been created by realloc-ing down in size, so
        // keep the node the same size...
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), &node[1]);
        return &node[1];
    }

    // Size increase
    assert(new_size > old_size);

    // Do we have a free node ahead of us?
    Word* next = node + old_size + 2;
    Word next_size;
    if (next + 4 >= txn->env->heap_end && !node_is_free(next)) {
        // No free node ahead :(
        goto copy;
    }

    next_size = get_node_size(next);
    if (next_size + 2 == (new_size - old_size)) {
        // Free node is exactly the size we want to increase by!
        llist_remove_node(txn->env, next);
        set_node(node, new_size, false, true);
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), &node[1]);
        return &node[1];
    }

    if (next_size >= (new_size - old_size) + 2) {
        // Free node can be shortened to accommodate our larger node
        llist_remove_node(txn->env, next);
        Word new_next_size = next_size + old_size - new_size;
        Word* next = node + new_size + 2;
        set_node(next, new_next_size, true, false);
        llist_add_node(txn->env, next);

        set_node(node, new_size, false, true);
        // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), &node[1]);
        return &node[1];
    }

copy:
    void* ptr_new = txnheap_alloc(txn, size);
    memcpy(ptr_new, &node[1], min(get_node_size(node) * sizeof(Word), size));
    txnheap_free_immediate(txn->env, node);
    // printf("txnheap_realloc(ptr: %p, size: %d) -> %p\n", ptr, int(size), ptr_new);
    return ptr_new;
}

void txnheap_free(TXP_txn* txn, void* ptr) {
    assert(txn != nullptr && txn->gen != 0 && txn->mode == TXP_RDWR);
    // printf("txnheap_free(ptr: %p)\n", ptr);

    if (ptr == nullptr) {
        return;
    }

    Word* node = static_cast<Word*>(ptr) - 1;
    assert(node >= txn->env->heap_begin && node < txn->env->heap_end);

    if (!node_is_new(node)) {
        txn->env->free_queue.push_back(NodeToFree(txn->gen, to_offset(txn->env, node)));
        return;
    }

    // If the node was created in the same generation that it's
    // being freed in, we can free it immediately.

    Word node_offset = to_offset(txn->env, node);
    for (auto it = txn->new_node_offsets.begin(); it != txn->new_node_offsets.end(); ++it) {
        if (*it == node_offset) {
            txn->new_node_offsets.erase(it);
            break;
        }
    }

    txnheap_free_immediate(txn->env, node);
}

void txnheap_free_immediate(TXP_env* env, Word* node) {
    assert(node && !node_is_free(node));

    // Clear memory?
    // memset(&node[1], 0, sizeof(Word) * get_node_size(node));

    // Find the node living adjacent before this one and try merging
    if (node > env->heap_begin) {
        Word* prev = node - node[-1] - 2;
        if (node_is_free(prev)) {
            llist_remove_node(env, prev);
            set_node(prev, get_node_size(prev) + get_node_size(node) + 2, true, false);
            node = prev;
        }
    }

    // Find the node living adjacent after this one and try merging
    if (node + get_node_size(node) + 2 < env->heap_end) {
        Word* next = node + get_node_size(node) + 2;
        if (node_is_free(next)) {
            llist_remove_node(env, next);
            set_node(node, get_node_size(node) + get_node_size(next) + 2, true, false);
        }
    }

    // Add the node
    set_node(node, get_node_size(node), true, false);
    llist_add_node(env, node);
}

void* txnheap_off_to_ptr(const TXP_txn* txn, uint32_t off) {
    if (off == 0) {
        return nullptr;
    }
    const uint8_t* begin = reinterpret_cast<const uint8_t*>(txn->env->heap_base);
    const uint8_t* end   = reinterpret_cast<const uint8_t*>(txn->env->heap_end);
    const uint8_t* ptr   = begin + off;
    assert(ptr <= end);
    return const_cast<uint8_t*>(ptr);
}

uint32_t txnheap_ptr_to_off(const TXP_txn* txn, const void* ptr) {
    if (ptr == nullptr) {
        return 0;
    }
    const uint8_t* begin  = reinterpret_cast<const uint8_t*>(txn->env->heap_base);
    const uint8_t* end    = reinterpret_cast<const uint8_t*>(txn->env->heap_end);
    const uint8_t* ptr_u8 = static_cast<const uint8_t*>(ptr);
    assert(begin < ptr_u8 && ptr_u8 <= end);
    return uint32_t(ptr_u8 - begin);
}
