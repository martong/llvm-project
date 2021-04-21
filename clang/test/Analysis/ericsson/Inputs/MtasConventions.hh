// No include guard!! (-2)

extern int p;

int q; // expected-warning {{Definitions should be only in .cc files}} // (-1)

bool functionWithDefinitionInAHeader() { int i; return true; } // expected-warning {{Definitions should be only in .cc files}} // (0)

template <int N>
void templateFunctionWithDefinitionInAHeader() {}
