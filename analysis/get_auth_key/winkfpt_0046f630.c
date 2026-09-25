
undefined4 FUN_0046f630(ushort param_1,byte *param_2,int *param_3)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  ushort uVar5;
  bool bVar6;
  
  uVar5 = 0;
  if (*(ushort *)(&DAT_00701668 + (uint)param_1 * 8) != 0) {
    do {
      pbVar2 = (byte *)((uint)uVar5 * 0x20 + *(int *)(&DAT_0070166c + (uint)param_1 * 8));
      pbVar4 = param_2;
      do {
        bVar1 = *pbVar4;
        bVar6 = bVar1 < *pbVar2;
        if (bVar1 != *pbVar2) {
LAB_0046f681:
          iVar3 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
          goto LAB_0046f686;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar4[1];
        bVar6 = bVar1 < pbVar2[1];
        if (bVar1 != pbVar2[1]) goto LAB_0046f681;
        pbVar4 = pbVar4 + 2;
        pbVar2 = pbVar2 + 2;
      } while (bVar1 != 0);
      iVar3 = 0;
LAB_0046f686:
      if (iVar3 == 0) {
        *param_3 = (uint)uVar5 * 0x20 + *(int *)(&DAT_0070166c + (uint)param_1 * 8);
        return 0;
      }
      uVar5 = uVar5 + 1;
    } while (uVar5 < *(ushort *)(&DAT_00701668 + (uint)param_1 * 8));
  }
  FUN_00460c90(0x107b,2,s_ATBALGO_C_0065f288,s_GetKeyIndex_0065f2c8,1);
  return 0xffffffff;
}

