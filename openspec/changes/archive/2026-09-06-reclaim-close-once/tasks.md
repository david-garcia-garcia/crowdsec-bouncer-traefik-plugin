## 1. Table dispose path

- [x] 1.1 Remove synchronous `closeFn` call from `fire`; cancel `life` only
- [x] 1.2 Update dispose comment to document watcher-only Close

## 2. Tests

- [x] 2.1 Assert exactly one Close in `TestTable_GraceClosesAfterSleep`
- [x] 2.2 Add test with panicking counter closer on grace dispose (concurrent fire vs watcher)
