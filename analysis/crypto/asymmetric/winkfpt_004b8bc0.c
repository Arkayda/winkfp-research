
undefined4 FUN_004b8bc0(undefined4 param_1)

{
  uint *in_EAX;
  int iVar1;
  uint *puVar2;
  char local_c [12];
  
  builtin_strncpy(local_c,"SetS",4);
  builtin_strncpy(local_c + 4,"eKey",5);
  if (*in_EAX < 0x21) {
    switch(param_1) {
    case 1:
      puVar2 = &DAT_0088b91c;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 2:
      puVar2 = &DAT_0088bb24;
      break;
    case 3:
      puVar2 = &DAT_00662e4c;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 4:
      puVar2 = &DAT_00663054;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 5:
      puVar2 = &DAT_0066325c;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    default:
      FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",local_c,0x1fa);
      return 0xfffffffd;
    }
    for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar2 = *in_EAX;
      in_EAX = in_EAX + 1;
      puVar2 = puVar2 + 1;
    }
    return 0;
  }
  FUN_004b9d90(0xfffffff4,"KrApiLib.cpp",local_c,0x1e4);
  return 0xfffffff4;
}

