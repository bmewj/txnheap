#pragma once
#include "txnheap_btree.h"
#include <utility>
#include <functional>

template <typename Value, typename Key, const Key&(*key_of)(const Value*&), int(*cmp)(const Key& a, const Key& b)>
struct SharedMap {

    struct Txn {

        Txn() : txn(nullptr), btree(nullptr) {}
        Txn(TXP_txn* txn, struct btree* btree) : txn(txn), btree(btree) {
            txnheap_btree_open(this->btree, this->txn, txnheap_get_root(this->txn));
        }
        Txn(const Txn&) = delete;
        Txn(Txn&& other) : txn(nullptr) {
            std::swap(this->txn, other.txn);
        }
        ~Txn() {
            txnheap_txn_abort(this->txn);
        }
        Txn& operator=(const Txn&) = delete;
        void commit() {
            txnheap_set_root(this->txn, txnheap_btree_done(this->btree));
            txnheap_txn_commit(this->txn);
            this->txn = nullptr;
            this->btree = nullptr;
        }

        void insert(const Value* value) {
            uint32_t off = txnheap_ptr_to_off(this->txn, value);
            txnheap_btree_set(this->btree, &off);
        }

        void print(const std::function<void(const Value*)>& fn) {
            auto iter = txnheap_btree_iter_new(this->btree);
            if (!txnheap_btree_iter_first(iter)) {
                txnheap_btree_iter_free(iter);
                return;
            }
            do {
                uint32_t off = *static_cast<const uint32_t*>(txnheap_btree_iter_item(iter));
                const Value* value = static_cast<const Value*>(txnheap_off_to_ptr(this->txn, off));
                fn(value);
            } while (txnheap_btree_iter_next(iter));
            txnheap_btree_iter_free(iter);
        }

    // protected:
        TXP_txn* txn;
        struct btree* btree;
    };

    SharedMap() {
        this->txn = txnheap_txn_alloc();
        this->btree = txnheap_btree_new(4, 8, &SharedMap::compare, this->txn);
    }
    ~SharedMap() {
        txnheap_txn_free(&this->txn);
        txnheap_btree_free(this->btree);
    }
    SharedMap(const SharedMap&) = delete;
    SharedMap(SharedMap&&) = delete;
    SharedMap& operator=(const SharedMap&) = delete;
    SharedMap& operator=(SharedMap&&) = delete;
    void set_sheap(TXP_env* env) {
        this->env = env;
    }
    void create() {
        txnheap_txn_begin(this->env, this->txn, TXP_RDWR);
        txnheap_set_root(this->txn, txnheap_btree_create(this->txn));
        txnheap_txn_commit(this->txn);
    }
    Txn open_reader() {
        txnheap_txn_begin(this->env, this->txn, TXP_RDONLY);
        return Txn(this->txn, this->btree);
    }
    Txn open_writer() {
        txnheap_txn_begin(this->env, this->txn, TXP_RDWR);
        return Txn(this->txn, this->btree);
    }

private:
    TXP_env* env = nullptr;
    TXP_txn* txn = nullptr;
    struct btree* btree = nullptr;

    static int compare(const void* a, const void* b, void* udata) {
        TXP_txn* txn = static_cast<TXP_txn*>(udata);
        uint32_t off_a = *reinterpret_cast<const uint32_t*>(a);
        uint32_t off_b = *reinterpret_cast<const uint32_t*>(b);
        const Value* val_a = static_cast<const Value*>(txnheap_off_to_ptr(txn, off_a));
        const Value* val_b = static_cast<const Value*>(txnheap_off_to_ptr(txn, off_b));
        return cmp(key_of(val_a), key_of(val_b));
    }
};
