int random();
void other() {
  int y = random();
  if (y == 0)
    (void)(1 / y);
}
