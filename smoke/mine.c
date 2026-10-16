// Gate 6E, library (deps): a tiny shared object exercised through
// DT_NEEDED. One function, deterministic value, no globals.
int mine_value(void) { return 42; }
