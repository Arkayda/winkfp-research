
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_004b8e10(int param_1)

{
  undefined4 *in_ECX;
  char local_c [12];
  
  builtin_strncpy(local_c,"SetSipro",8);
  builtin_strncpy(local_c + 8,"Key",4);
  if (param_1 == 3) {
    _DAT_00663390 = *in_ECX;
    _DAT_00663394 = in_ECX[1];
    return 0;
  }
  if (param_1 != 4) {
    if (param_1 != 5) {
      FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",local_c,0x235);
      return 0xfffffffd;
    }
    _DAT_006633a0 = *in_ECX;
    _DAT_006633a4 = in_ECX[1];
    return 0;
  }
  _DAT_00663398 = *in_ECX;
  _DAT_0066339c = in_ECX[1];
  return 0;
}

