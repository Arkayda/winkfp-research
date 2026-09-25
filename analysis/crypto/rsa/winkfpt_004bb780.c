
undefined4 FUN_004bb780(int param_1,uint param_2,int *param_3)

{
  byte bVar1;
  ushort uVar2;
  uint3 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined1 *puVar7;
  bool bVar8;
  
  if (0x7f < (int)param_2) {
    return 0xffffffff;
  }
  iVar4 = (int)(param_2 + ((int)param_2 >> 0x1f & 3U)) >> 2;
  uVar5 = param_2 & 0x80000003;
  bVar8 = uVar5 == 0;
  if ((int)uVar5 < 0) {
    bVar8 = (uVar5 - 1 | 0xfffffffc) == 0xffffffff;
  }
  if (!bVar8) {
    iVar4 = iVar4 + 1;
  }
  iVar6 = 1;
  *param_3 = iVar4;
  if (1 < iVar4) {
    puVar7 = (undefined1 *)(param_1 + 2);
    do {
      param_3[iVar6] = 0;
      bVar1 = puVar7[1];
      param_3[iVar6] = (uint)bVar1 << 8;
      uVar2 = CONCAT11(bVar1,*puVar7);
      param_3[iVar6] = (uint)uVar2 << 8;
      uVar3 = CONCAT21(uVar2,puVar7[-1]);
      param_3[iVar6] = (uint)uVar3 << 8;
      param_3[iVar6] = CONCAT31(uVar3,puVar7[-2]);
      iVar6 = iVar6 + 1;
      puVar7 = puVar7 + 4;
    } while (iVar6 < iVar4);
  }
  param_3[iVar4] = 0;
  param_3[iVar4] = 0;
  if (iVar4 * 4 + -1 < (int)param_2) {
    param_3[iVar4] = (uint)*(byte *)(param_1 + -1 + iVar4 * 4);
  }
  if (iVar4 * 4 + -2 < (int)param_2) {
    iVar6 = param_3[iVar4];
    param_3[iVar4] = iVar6 << 8;
    param_3[iVar4] = (uint)*(byte *)(param_1 + -2 + iVar4 * 4) | iVar6 << 8;
  }
  else {
    param_3[iVar4] = 0;
  }
  if (iVar4 * 4 + -3 < (int)param_2) {
    iVar6 = param_3[iVar4];
    param_3[iVar4] = iVar6 << 8;
    param_3[iVar4] = (uint)*(byte *)(param_1 + -3 + iVar4 * 4) | iVar6 << 8;
  }
  else {
    param_3[iVar4] = 0;
  }
  if ((int)param_2 <= iVar4 * 4 + -4) {
    param_3[iVar4] = 0;
    return 0;
  }
  iVar6 = param_3[iVar4];
  param_3[iVar4] = iVar6 << 8;
  param_3[iVar4] = (uint)*(byte *)(param_1 + -4 + iVar4 * 4) | iVar6 << 8;
  return 0;
}

