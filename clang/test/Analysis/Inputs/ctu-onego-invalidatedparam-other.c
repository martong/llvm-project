typedef struct evp_md_ctx_st EVP_MD_CTX;
struct evp_md_st {
  int (*md_ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
};
struct evp_md_ctx_st {
  int (*update)();
};
struct evp_md_st *EVP_MD_fetch() { return 0; }

