
undefined4 FUN_004ba1b0(undefined4 *param_1,int param_2,undefined4 param_3)

{
  undefined4 local_8;
  undefined1 local_4;
  undefined1 local_3;
  undefined1 local_2;
  undefined1 local_1;
  
  local_4 = 0;
  local_3 = 0;
  local_2 = 0;
  local_1 = 0;
  local_8 = *param_1;
  if (param_2 == 3) {
    FUN_004ba080(&local_8,8,&DAT_00663390,param_3);
    return 0;
  }
  if (param_2 != 4) {
    if (param_2 != 5) {
      return 0xfffffffe;
    }
    FUN_004ba080(&local_8,8,&DAT_006633a0,param_3);
    return 0;
  }
  FUN_004ba080(&local_8,8,&DAT_00663398,param_3);
  return 0;
}

