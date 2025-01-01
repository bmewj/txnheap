/* This is a hex pattern written for ImHex to inspect the
   contents of a TxnHeap buffer with syntax highlighting. */
import std.mem;

u32 BIN_COUNT = 8;
u32 MAX_READERS = 64;

struct Mutex { u8 data[64]; };

struct Readers {
    u32 start, end;
    u32 gen[MAX_READERS];
    bool active[MAX_READERS];
};

struct TXNHEAP_base {
    Mutex writer_mutex;
    Mutex reader_mutex;
    u32 bins[BIN_COUNT];
    u32 readers_start, readers_end;
    u32 readers_gen[MAX_READERS];
    bool readers_active[MAX_READERS];
    u32 root;
    u32 gen;
};

bitfield NodeHeader {
    free : 1;
    new  : 1;
    size : 30;
};

struct Node {
    NodeHeader header [[highlight_hidden]];
    
    if (header.free) {
        u8 empty[header.size * 4] [[highlight_hidden]];
    } else {
        char node_content[header.size * 4];
    }
    u32 node_footer [[highlight_hidden]];
};

TXNHEAP_base base @ 0x00;
Node nodes[while(!std::mem::eof())] @ sizeof(TXNHEAP_base) + 4;
