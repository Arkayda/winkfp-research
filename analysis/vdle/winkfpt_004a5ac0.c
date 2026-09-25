
undefined1 FUN_004a5ac0(int param_1)

{
  char cVar1;
  
  if (DAT_008818e4 == '\0') {
    FUN_004a2160("STOP_TESTERPRESENT","ERROR_DLL_INIT_ERROR");
    return 0;
  }
  if (param_1 != 0) {
    FUN_004a2160("STOP_TESTERPRESENT","ERROR_DLL_JOBAPIPARAM");
    return 0;
  }
  cVar1 = FUN_004a58e0();
  if (cVar1 == '\0') {
    FUN_004a2160("STOP_TESTERPRESENT","ERROR_DLL_TESTERPRESENTHANDLING");
    return 0;
  }
  FUN_004a2160("STOP_TESTERPRESENT",&DAT_00602af0);
  return 1;
}

