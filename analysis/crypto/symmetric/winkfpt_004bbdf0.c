
void FUN_004bbdf0(void)

{
  uint uVar1;
  uint uVar2;
  undefined3 *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int local_64;
  int local_60;
  uint local_58;
  int aiStack_40 [16];
  
  uVar1 = DAT_008949e8;
  iVar7 = 0;
  puVar3 = (undefined3 *)&DAT_008949a1;
  do {
    aiStack_40[iVar7] = CONCAT31(*puVar3,*(undefined1 *)((int)puVar3 + -1));
    iVar7 = iVar7 + 1;
    puVar3 = puVar3 + 1;
  } while (iVar7 < 0x10);
  local_60 = 0;
  local_64 = 0;
  uVar4 = DAT_008949ec;
  uVar5 = DAT_008949e0;
  uVar8 = DAT_008949ec;
  uVar10 = DAT_008949f0;
  do {
    uVar6 = (uint)(char)(&DAT_00605148)[local_64];
    local_58 = 0;
    uVar2 = uVar8;
    do {
      uVar8 = uVar10;
      uVar9 = uVar2;
      uVar10 = uVar5;
      switch(local_64) {
      case 0:
        uVar4 = ~uVar10 & uVar9 | uVar8 & uVar10;
        break;
      case 1:
        uVar4 = ~uVar9 & uVar8 | uVar9 & uVar10;
        break;
      case 2:
        uVar4 = uVar9 ^ uVar8 ^ uVar10;
        break;
      case 3:
        uVar4 = (~uVar9 | uVar10) ^ uVar8;
      }
      uVar4 = uVar4 + aiStack_40[uVar6] + *(int *)(&DAT_00605160 + local_60 * 4) + DAT_008949e8;
      uVar4 = (uVar4 >> (0x20 - (&DAT_00605150)[local_64 * 4 + (local_58 & 3)] & 0x1f) |
              uVar4 << ((&DAT_00605150)[local_64 * 4 + (local_58 & 3)] & 0x1f)) + uVar10;
      uVar6 = uVar6 + (int)(char)(&DAT_0060514c)[local_64] & 0xf;
      local_60 = local_60 + 1;
      local_58 = local_58 + 1;
      uVar5 = uVar4;
      uVar2 = uVar8;
      DAT_008949e8 = uVar9;
    } while ((int)local_58 < 0x10);
    local_64 = local_64 + 1;
  } while (local_64 < 4);
  DAT_008949e0 = uVar4 + DAT_008949e0;
  DAT_008949f0 = uVar10 + DAT_008949f0;
  DAT_008949ec = uVar8 + DAT_008949ec;
  DAT_008949e8 = uVar9 + uVar1;
  DAT_008949f4 = 0;
  return;
}

