#include <stdio.h>
#include <string.h>
#include <txnheap_btree.h>
#include <shared_map.h>
#include <vector>
#include <assert.h>

static void write(TXP_env* env, const char* message) {
    TXP_txn* txn = txnheap_txn_alloc();
    txnheap_txn_begin(env, txn, TXP_RDWR);

    size_t message_len = strlen(message);

    char* root_old = (char*)txnheap_get_root(txn);
    char* root_new = (char*)txnheap_realloc(txn, root_old, message_len + 1);
    memcpy(root_new, message, message_len + 1);

    txnheap_set_root(txn, root_new);
    txnheap_txn_commit(txn);
    txnheap_txn_free(&txn);
}

static void read(TXP_txn* txn) {
    const char* message = (const char*)txnheap_get_root(txn);
    if (message == nullptr) {
        printf("Data: NULL\n");
    } else {
        printf("Data: %s\n", message);
    }
}

static void read(TXP_env* env) {
    TXP_txn* txn = txnheap_txn_alloc();
    if (!txnheap_txn_begin(env, txn, TXP_RDONLY)) {
        printf("Failed to open reader!!\n");
        goto cleanup;
    }
    read(txn);
    txnheap_txn_abort(txn);
cleanup:
    txnheap_txn_free(&txn);
}

const char*const& key_of(const char*& val) {
    return val;
}
int main(int argc, const char** argv) {

    size_t BUF_SIZE = 1024 * 1024;
    uint8_t* buffer = new uint8_t[BUF_SIZE];

    TXP_env* env = txnheap_env_alloc(buffer, BUF_SIZE);
    txnheap_env_init(env);

    constexpr auto cmp = [](const char* const& a, const char* const& b) { return strcmp(a, b); };
    using Map = SharedMap<char, const char*, key_of, cmp>;
    Map map;
    map.set_sheap(env);
    map.create();

    auto insert = [&](const char* value) {
        auto txn = map.open_writer();

        printf("Inserting: %s\n", value);
        size_t value_len = strlen(value);
        char* value_copy = (char*)txnheap_alloc(txn.txn, value_len + 1);
        memcpy(value_copy, value, value_len + 1);

        txn.insert(value_copy);
        txn.commit();
    };

    auto print = [&]() {
        auto txn = map.open_reader();

        txn.print([](const char* item) {
            printf("item ---> %s\n", item);
        });
    };

    insert("Hello");
    print();
//    add_reader();
    insert("World");
    insert("cdjfkadjfkda");
    insert("Another");
    print();
//    add_reader();
    insert("Item");
    insert("bdjfkadjfkda");
    insert("1234");
    insert("1235");
    print();
//    add_reader();
    insert("123");
    insert("adjfkadjfkda");
    print();
//    add_reader();

//    TXP_txn* txn = txnheap_txn_alloc();
//
//    {
//        txnheap_txn_begin(sheap, txn, TXP_RDWR);
//        txnheap_set_root(txn, txnheap_btree_create(txn));
//        txnheap_txn_commit(txn);
//    }
//
//    btree* tree = txnheap_btree_new(sizeof(uint32_t), 16, [](const void* a, const void* b, void* udata) {
//        TXP_txn* txn = static_cast<TXP_txn*>(udata);
//        uint32_t a_off = *static_cast<const uint32_t*>(a);
//        uint32_t b_off = *static_cast<const uint32_t*>(b);
//        const char* a_str = static_cast<const char*>(txnheap_off_to_ptr(txn, a_off));
//        const char* b_str = static_cast<const char*>(txnheap_off_to_ptr(txn, b_off));
//        return strcmp(a_str, b_str);
//    }, txn);
//
//    auto insert = [&](const char* value) {
//        txnheap_txn_begin(sheap, txn, TXP_RDWR);
//
//        printf("Inserting: %s\n", value);
//        size_t value_len = strlen(value);
//        void* value_copy = txnheap_alloc(txn, value_len + 1);
//        memcpy(value_copy, value, value_len + 1);
//        uint32_t off = txnheap_ptr_to_off(txn, value_copy);
//        txnheap_btree_open(tree, txn, txnheap_get_root(txn));
//        txnheap_btree_set(tree, &off);
//        txnheap_set_root(txn, txnheap_btree_done(tree));
//
//        txnheap_txn_commit(txn);
//    };
//
//    std::vector<TXP_txn*> txns;
//    auto add_reader = [&]() {
//        printf("Open reader %d\n", int(txns.size() + 1));
//        TXP_txn* txn = txnheap_txn_alloc();
//        bool ok = txnheap_txn_begin(sheap, txn, TXP_RDONLY);
//        assert(ok);
//        txns.push_back(txn);
//    };
//
//    insert("Hello");
//    add_reader();
//    insert("World");
//    insert("cdjfkadjfkda");
//    insert("Another");
//    add_reader();
//    insert("Item");
//    insert("bdjfkadjfkda");
//    insert("1234");
//    insert("1235");
//    add_reader();
//    insert("123");
//    insert("adjfkadjfkTXP_RDWR);
//        txnheap_txn_abort(txn);
//    }

    FILE* f = fopen("/Users/bmj/Code/shade/data/heap.bin", "w+");
    if (f == nullptr) {
        return 1;
    }
    fwrite(buffer, 1, BUF_SIZE, f);
    fclose(f);

    return 0;
}
