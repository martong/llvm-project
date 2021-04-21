// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.DbnDelayAfterRetry -Wno-everything -verify %s
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

inline bool DicosDbCollectionOfOpens::isGood() {
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

void Dicos_delay(int) {}

void controll_case() {
    DicosDbTransaction trans;
    int var = 100;

    for(unsigned noOfRetries = 0; noOfRetries < 20; noOfRetries++) {
        trans.start();

        Object::openUpdate(5, trans);

        if (trans.isRetry()) {
            Dicos_delay(var);
            continue;
        }
        else if (!trans.isGood()) {
            return;
        }
    }

    trans.commit();
}

void mising_delay() {
    DicosDbTransaction trans;

    for(unsigned noOfRetries = 0; noOfRetries < 20; noOfRetries++) {
        trans.start();// expected-warning {{There is no delay between retries}} 

        Object::openUpdate(5, trans);

        if (trans.isRetry()) {
            continue;
        }
        else if (!trans.isGood()) {
            return;
        }
    }

    trans.commit();
}
