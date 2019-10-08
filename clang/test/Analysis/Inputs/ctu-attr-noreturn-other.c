int cond(void);
void fatal(void); // Should inherit noreturn when imported.

typedef struct {
  int a;
  int b;
} Data;

void ff(Data* data) {
  if (cond()) {
    fatal();
    return;
  }
  data->a = 0;
  data->b = 0;
}
