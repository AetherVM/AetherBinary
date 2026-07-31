## v0.1.1
### Bug fixes:
 * fix wrong LC_ID_DYLIB name on macOS;
 * fix mismatch assembler target when cross assembling;
 
### Improvements:
 * reset aarch64 feature string as +all;
 * remove unused assembler llvm-mc logic to improve performance;
 * add new binary from memory object apis;
 * add the start of text section of relocatable object to function list;
 * add syscall category in InsnType;

## v0.1.0
Initial release.
