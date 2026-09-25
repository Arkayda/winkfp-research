
int FUN_004bb720(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined1 local_104 [260];
  
  iVar1 = FUN_004bb780(param_1,0x10,local_104);
  if (iVar1 == -1) {
    return -1;
  }
  iVar1 = FUN_004bb910(local_104,param_3,param_2,param_4);
  return (iVar1 != -1) - 1;
}

