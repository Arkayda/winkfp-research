
void FUN_004ba080(int param_1,uint param_2,int param_3,byte *param_4)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  int iVar4;
  uint uVar5;
  byte bVar6;
  char *pcVar7;
  uint local_18;
  int local_14;
  undefined4 local_8;
  undefined4 local_4;
  
  pbVar3 = (byte *)(param_1 + -1 + param_2);
  iVar4 = 8;
  pbVar2 = param_4;
  do {
    bVar6 = *pbVar3;
    pbVar3 = pbVar3 + -1;
    *pbVar2 = pbVar2[param_3 - (int)param_4] ^ bVar6;
    pbVar2 = pbVar2 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  bVar6 = 0;
  iVar4 = 4;
  pbVar3 = param_4;
  do {
    bVar1 = bVar6 & 0x1f;
    bVar6 = bVar6 + 8;
    *pbVar3 = *pbVar3 ^ (byte)(param_2 >> bVar1);
    pbVar3 = pbVar3 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  local_18 = 0;
  if (param_2 != 0) {
    do {
      local_8 = *(undefined4 *)param_4;
      local_4 = *(undefined4 *)(param_4 + 4);
      local_14 = 4;
      do {
        uVar5 = 0xffffffff;
        iVar4 = 8;
        pcVar7 = (char *)(local_18 + param_1);
        do {
          bVar6 = *(byte *)((int)&local_8 + (uVar5 & 7));
          *(byte *)((int)&local_8 + uVar5 + 1) =
               ((*(byte *)((int)&local_8 + (uVar5 - 2 & 7)) & ~bVar6 |
                *(byte *)((int)&local_8 + (uVar5 - 1 & 7)) & bVar6) + *pcVar7) * '\x03' +
               *(char *)((int)&local_8 + uVar5 + 1) * '\x04';
          uVar5 = uVar5 + 1;
          pcVar7 = pcVar7 + 1;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        local_14 = local_14 + -1;
      } while (local_14 != 0);
      iVar4 = 8;
      pbVar3 = param_4;
      do {
        *pbVar3 = *pbVar3 + pbVar3[(int)&local_8 - (int)param_4];
        pbVar3 = pbVar3 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
      local_18 = local_18 + 8;
    } while (local_18 < param_2);
  }
  return;
}

