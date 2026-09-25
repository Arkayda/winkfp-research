
undefined4 FUN_004b8ac0(undefined4 param_1)

{
  uint *in_EAX;
  int iVar1;
  uint *puVar2;
  undefined4 local_8;
  undefined *local_4;
  
  local_8 = 0x4d746553;
  local_4 = &DAT_0079654b;
  if (*in_EAX < 0x21) {
    switch(param_1) {
    case 1:
      puVar2 = &DAT_0088b818;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 2:
      puVar2 = &DAT_0088ba20;
      break;
    case 3:
      puVar2 = &DAT_00662d48;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 4:
      puVar2 = &DAT_00662f50;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    case 5:
      puVar2 = &DAT_00663158;
      for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = *in_EAX;
        in_EAX = in_EAX + 1;
        puVar2 = puVar2 + 1;
      }
      return 0;
    default:
      FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",&local_8,0x1d2);
      return 0xfffffffd;
    }
    for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar2 = *in_EAX;
      in_EAX = in_EAX + 1;
      puVar2 = puVar2 + 1;
    }
    return 0;
  }
  FUN_004b9d90(0xfffffff4,"KrApiLib.cpp",&local_8,0x1bc);
  return 0xfffffff4;
}

