// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.tsp.DbnTransactionManagement -Wno-everything -verify %s
// Skeleton class for DBN transactions.
struct DicosDbCollectionOfOpens {
    DicosDbCollectionOfOpens();
    virtual ~DicosDbCollectionOfOpens();

    enum Status {
        GoodStatus,
        RetryStatus,
        FailedStatus,
        UnknownStatus
    };

    Status status();
    bool isGood();
    bool isFailed();
    bool isRetry();

    void assertGoodStatus();
};

struct DicosDbTransaction : DicosDbCollectionOfOpens {
    DicosDbTransaction();
    virtual ~DicosDbTransaction();

    void start();
    void rollback();
    void commit();
};

inline bool  DicosDbCollectionOfOpens::isGood() {
  return this->status() == GoodStatus;
}

inline bool DicosDbCollectionOfOpens::isRetry() {
  return this->status() == RetryStatus;
}

inline bool DicosDbCollectionOfOpens::isFailed() {
  return this->status() == FailedStatus;
}


// Skeleton class for DBN object
struct Object {
    static Object* create(DicosDbTransaction& trans);
    static Object* openSafeRead(int, DicosDbTransaction& trans);
    static Object* openUpdate(int, DicosDbTransaction& trans);
    static Object* openDelete(int, DicosDbTransaction& trans);
    static Object* upgradeSafeRead(int, DicosDbTransaction& trans);
    static Object* upgradeUpdate(int, DicosDbTransaction& trans);
};

// This is perfectly valid, a newly constructed DicosDbTransaction is ready to use
void unstarted_commit() {
    DicosDbTransaction t;
    t.commit();
    t.assertGoodStatus();
}

void double_commit() {
    DicosDbTransaction t;
    t.commit();
    t.commit(); // expected-warning {{The transaction was double-committed}} // (2), double commit
    t.assertGoodStatus();
}

void commit_unchecked() {
    DicosDbTransaction t;
    t.start();
    t.commit();
} // expected-warning {{The state of the transaction was never checked after it was committed or rollbacked}} // (3), do not check state before going out of scope

void commit_unchecked_reuse() {
    DicosDbTransaction t;
    t.start();
    t.commit();

    t.start(); // expected-warning {{The state of the transaction was not checked after it was committed or rollbacked and before it was reused}} // (4), reusing transaction without checking commit state
    t.rollback();
}

void uncommited_unused() {
    DicosDbTransaction t;
}

void uncommited_used() {
    DicosDbTransaction t;
    Object* obj = Object::create(t);
}// expected-warning {{The transaction was never commited or rolled back after it was started}}


void unstarted_transaction_used() {
    DicosDbTransaction t;
    t.commit();
    t.assertGoodStatus();
    Object* obj = Object::create(t); // expected-warning {{The transaction was used without being started}} // not restarted but used
} // expected-warning {{The state of the transaction was never checked after it was committed or rollbacked}} // Result not checked

bool nontrivial_test() {
    DicosDbTransaction t;
    for (unsigned int i=0;i<100;i++) {
        Object::openDelete(i,t);
    }

    t.commit();
    if(!t.isGood()) return false;

    return true;
}
