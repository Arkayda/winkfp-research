
void FUN_00492a90(undefined4 param_1,ushort param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  ushort *puVar4;
  uint uVar5;
  ushort uVar6;
  char *pcVar7;
  undefined4 *puVar8;
  undefined2 local_148 [2];
  char local_144 [26];
  undefined2 local_12a;
  undefined1 local_128 [260];
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined2 local_c;
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  uVar5 = (uint)param_2;
  *(undefined2 *)(&PTR_DAT_0065fa70)[uVar5] = 0;
  *(undefined2 *)(&PTR_DAT_0065fa7c)[uVar5] = 0;
  *(undefined2 *)(&PTR_DAT_0065fa88)[uVar5] = 0;
  *(undefined2 *)(&PTR_DAT_0065fa94)[uVar5] = 0;
  *(undefined2 *)(&PTR_DAT_0065faa0)[uVar5] = 0;
  local_24 = 0;
  local_20 = 0;
  local_1c = 0;
  local_18 = 0;
  local_14 = 0;
  local_10 = 0;
  local_c = 0;
  uVar6 = 0;
  sVar1 = FUN_00498400(0,param_1,local_128);
  if (sVar1 != 0) {
    iVar2 = (int)sVar1;
    if ((ushort)(sVar1 - 0x1eU) < 0xab) {
      iVar2 = iVar2 + 0x1130;
    }
    FUN_00460c90(iVar2,0,s_DEF_FILE_C_0065fa64,s_LeseDefinitionsdatei_0065faac,1);
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar2 = FUN_00475230(local_128,0);
  if (iVar2 == 0) {
    FUN_00460cc0(0x1150,0,s_DEF_FILE_C_0065fa64,s_LeseDefinitionsdatei_0065faac,2,local_128);
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  sVar1 = FUN_00474eb0(iVar2,"SWT_EINTRAG");
  while (sVar1 == 0) {
    FUN_00475330("KEYID",local_148);
    FUN_00475410("KEYWORD",&local_24,0x1a);
    local_12a = local_148[0];
    iVar3 = 0;
    do {
      pcVar7 = (char *)((int)&local_24 + iVar3);
      local_144[iVar3] = *pcVar7;
      iVar3 = iVar3 + 1;
    } while (*pcVar7 != '\0');
    uVar6 = uVar6 + 1;
    if (0x2db4 < uVar6) {
      FUN_0046efc0(iVar2);
      FUN_00460c90(0x115b,0,s_DEF_FILE_C_0065fa64,s_LeseDefinitionsdatei_0065faac,3);
      __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (uVar6 < 0x924) {
      puVar8 = (undefined4 *)((&PTR_DAT_0065fa70)[uVar5] + (uint)uVar6 * 0x1c + -0x1a);
    }
    else if (uVar6 < 0x1248) {
      puVar8 = (undefined4 *)((&PTR_DAT_0065fa7c)[uVar5] + (uint)uVar6 * 0x1c + -0xffee);
    }
    else if (uVar6 < 0x1b6c) {
      puVar8 = (undefined4 *)((&PTR_DAT_0065fa88)[uVar5] + (uint)uVar6 * 0x1c + -0x1ffde);
    }
    else if (uVar6 < 0x2490) {
      puVar8 = (undefined4 *)((&PTR_DAT_0065fa94)[uVar5] + (uint)uVar6 * 0x1c + -0x2ffce);
    }
    else {
      puVar8 = (undefined4 *)((&PTR_DAT_0065faa0)[uVar5] + (uint)uVar6 * 0x1c + -0x3ffbe);
    }
    pcVar7 = local_144;
    for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar8 = *(undefined4 *)pcVar7;
      pcVar7 = pcVar7 + 4;
      puVar8 = puVar8 + 1;
    }
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_18 = 0;
    local_14 = 0;
    local_10 = 0;
    local_c = 0;
    sVar1 = FUN_00474eb0(iVar2,"SWT_EINTRAG");
  }
  FUN_0046efc0(iVar2);
  if (uVar6 < 0x924) {
    puVar4 = (ushort *)(&PTR_DAT_0065fa70)[uVar5];
  }
  else {
    if (uVar6 < 0x1248) {
      *(undefined2 *)(&PTR_DAT_0065fa70)[uVar5] = 0x924;
      *(ushort *)(&PTR_DAT_0065fa7c)[uVar5] = uVar6 - 0x923;
      __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (uVar6 < 0x1b6c) {
      *(undefined2 *)(&PTR_DAT_0065fa70)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa7c)[uVar5] = 0x924;
      *(ushort *)(&PTR_DAT_0065fa88)[uVar5] = uVar6 + 0xedb9;
      __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (uVar6 < 0x2490) {
      *(undefined2 *)(&PTR_DAT_0065fa70)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa7c)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa88)[uVar5] = 0x924;
      puVar4 = (ushort *)(&PTR_DAT_0065fa94)[uVar5];
      uVar6 = uVar6 + 0xe495;
    }
    else {
      *(undefined2 *)(&PTR_DAT_0065fa70)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa7c)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa88)[uVar5] = 0x924;
      *(undefined2 *)(&PTR_DAT_0065fa94)[uVar5] = 0x924;
      puVar4 = (ushort *)(&PTR_DAT_0065faa0)[uVar5];
      uVar6 = uVar6 + 0xdb71;
    }
  }
  *puVar4 = uVar6;
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

