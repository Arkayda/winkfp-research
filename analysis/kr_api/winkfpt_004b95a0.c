
void FUN_004b95a0(undefined4 param_1,undefined4 param_2,undefined4 param_3,char *param_4,
                 undefined4 param_5,int param_6,int param_7,int *param_8,undefined4 *param_9)

{
  undefined1 uVar1;
  undefined1 uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined1 *puVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 *puVar9;
  char cVar10;
  bool bVar11;
  char local_124 [20];
  undefined4 local_110 [67];
  
  builtin_strncpy(local_124,"KrApiAuthenticate",0x12);
  if ((param_6 < 0) || (5 < param_6)) {
    uVar4 = FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",local_124,0xdd);
    *param_9 = uVar4;
    return;
  }
  iVar6 = 0xb;
  cVar10 = true;
  pcVar7 = "Symetrisch";
  pcVar8 = param_4;
  do {
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    cVar10 = *pcVar7 == *pcVar8;
    pcVar7 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
  } while ((bool)cVar10);
  iVar6 = 7;
  bVar11 = true;
  pcVar7 = "Simple";
  pcVar8 = param_4;
  do {
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    bVar11 = *pcVar7 == *pcVar8;
    pcVar7 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
  } while (bVar11);
  if (bVar11) {
    cVar10 = '\x02';
  }
  iVar6 = 0xc;
  bVar11 = true;
  pcVar7 = "Asymetrisch";
  do {
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    bVar11 = *pcVar7 == *param_4;
    pcVar7 = pcVar7 + 1;
    param_4 = param_4 + 1;
  } while (bVar11);
  if (bVar11) {
    cVar10 = '\x03';
  }
  else if (cVar10 == '\0') {
    uVar4 = FUN_004b9d90(0xfffffffa,"KrApiLib.cpp",local_124,0xe9);
    *param_9 = uVar4;
    return;
  }
  puVar9 = local_110;
  for (iVar6 = 0x42; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  iVar6 = FUN_004b8fe0(local_110,0x108);
  iVar3 = FUN_004b8a00(iVar6);
  if (iVar3 != 0) {
    uVar4 = FUN_004b9d90(0xfffffffb,"KrApiLib.cpp",local_124,0xf5);
    *param_9 = uVar4;
    return;
  }
  if (*param_8 < iVar6) {
    *param_8 = 0;
    uVar4 = FUN_004b9d90(0xfffffffc,"KrApiLib.cpp",local_124,0xfd);
    *param_9 = uVar4;
    return;
  }
  *param_8 = iVar6;
  if (cVar10 == '\x01') {
    iVar6 = FUN_004b8cc0(param_6);
    if (iVar6 != 0) {
LAB_004b9797:
      *param_9 = 0x82a;
      return;
    }
    iVar6 = FUN_004b9f50(param_5,param_2,param_3,param_6,param_7);
  }
  else {
    if (cVar10 != '\x02') {
      if (cVar10 == '\x03') {
        *param_8 = iVar6 / 2;
        FUN_004b8a70();
        FUN_004b8a70();
        iVar6 = FUN_004b8ac0(param_6);
        if (iVar6 != 0) {
          *param_9 = 0x82a;
          return;
        }
        iVar6 = FUN_004b8bc0(param_6);
        if (iVar6 != 0) goto LAB_004b980f;
        iVar6 = FUN_004b9e30(param_5,param_2,param_3,param_6,param_7);
        if (iVar6 != 0) goto LAB_004b9797;
        if (0 < *param_8) {
          puVar5 = (undefined1 *)(param_7 + 1);
          do {
            uVar1 = puVar5[-1];
            uVar2 = *puVar5;
            puVar5[-1] = puVar5[2];
            puVar5[2] = uVar1;
            *puVar5 = puVar5[1];
            puVar5[1] = uVar2;
            puVar5 = puVar5 + 4;
          } while ((int)(puVar5 + (-1 - param_7)) < *param_8);
        }
      }
      goto LAB_004b97d6;
    }
    iVar6 = FUN_004b8e10(param_6);
    if (iVar6 != 0) goto LAB_004b980f;
    iVar6 = FUN_004ba1b0(param_5,param_6,param_7);
  }
  if (iVar6 != 0) {
LAB_004b980f:
    *param_9 = 0x82a;
    return;
  }
LAB_004b97d6:
  *param_9 = 0;
  return;
}

