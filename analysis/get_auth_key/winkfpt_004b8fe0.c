
uint FUN_004b8fe0(undefined4 *param_1,uint param_2)

{
  char *pcVar1;
  int *piVar2;
  char cVar3;
  uint uVar4;
  undefined4 *puVar5;
  int in_ECX;
  int iVar6;
  uint uVar7;
  char *in_EDX;
  char *pcVar8;
  undefined4 *puVar9;
  char *local_574;
  char local_570 [24];
  undefined4 *local_558;
  char local_538;
  undefined4 local_537;
  char local_418 [1028];
  void *local_14;
  undefined1 *puStack_10;
  int local_c;
  
  local_c = 0xffffffff;
  puStack_10 = &LAB_005e70f1;
  local_14 = ExceptionList;
  builtin_strncpy(local_570,"GetAuthK",8);
  local_538 = '\0';
  local_570[10] = 0;
  puVar5 = &local_537;
  for (iVar6 = 0x47; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  local_570[8] = 'e';
  local_570[9] = 'y';
  *(undefined1 *)((int)puVar5 + 2) = 0;
  ExceptionList = &local_14;
  FUN_004ba480();
  local_c = 0;
  iVar6 = -(int)in_EDX;
  do {
    cVar3 = *in_EDX;
    in_EDX[(int)(local_418 + iVar6)] = cVar3;
    in_EDX = in_EDX + 1;
  } while (cVar3 != '\0');
  if ((in_ECX < 0) || (5 < in_ECX)) {
    FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",local_570);
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffffd;
  }
  _sprintf(&local_538,"%s%c%s",&DAT_00605034,in_ECX + 0x40);
  __strlwr(&local_538);
  FUN_004bb680();
  local_c._0_1_ = 1;
  iVar6 = FUN_004ba6d0();
  if (iVar6 != 0) {
    if (iVar6 == -8) {
      FUN_004b9d90(0xfffffff2,"KrApiLib.cpp",local_570);
      local_c = (uint)local_c._1_3_ << 8;
      FUN_004ba930();
      local_c = 0xffffffff;
      FUN_004ba4b0();
      ExceptionList = local_14;
      return 0xfffffff2;
    }
    FUN_004b9d90(0xfffffff9,"KrApiLib.cpp",local_570);
    local_c = (uint)local_c._1_3_ << 8;
    FUN_004ba930();
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffff9;
  }
  if (local_418[0] != '\0') {
    pcVar8 = local_418;
    do {
      iVar6 = _toupper((int)*pcVar8);
      *pcVar8 = (char)iVar6;
      if ((char)iVar6 == ' ') {
        *pcVar8 = '\0';
      }
      pcVar1 = pcVar8 + 1;
      pcVar8 = pcVar8 + 1;
    } while (*pcVar1 != '\0');
  }
  local_558 = (undefined4 *)&stack0xfffffa74;
  FUN_004bacd0(&stack0xfffffa74,local_418);
  FUN_004ba650();
  iVar6 = FUN_004ba6d0();
  if (iVar6 != 0) {
    FUN_004b9d90(0xfffffff8,"KrApiLib.cpp",local_570);
    local_c = (uint)local_c._1_3_ << 8;
    FUN_004ba930();
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffff8;
  }
  FUN_004baef0(&local_574);
  local_c._0_1_ = 2;
  iVar6 = FUN_004ba6d0();
  if (iVar6 != 0) {
    FUN_004b9d90(0xfffffff7,"KrApiLib.cpp",local_570);
    local_c._0_1_ = 1;
    piVar2 = (int *)(local_574 + -4);
    LOCK();
    iVar6 = *piVar2;
    *piVar2 = *piVar2 + -1;
    UNLOCK();
    if (iVar6 == 1 || iVar6 + -1 < 0) {
      (**(code **)(**(int **)(local_574 + -0x10) + 4))();
    }
    local_c = (uint)local_c._1_3_ << 8;
    FUN_004ba930();
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffff7;
  }
  if (*(int *)(local_574 + -0xc) < 0) {
                    /* WARNING: Subroutine does not return */
    FUN_004b8f50();
  }
  cVar3 = *local_574;
  uVar4 = FUN_004ba720();
  if (param_2 < uVar4) {
    FUN_004b9d90(0xfffffffc,"KrApiLib.cpp",local_570);
    local_c._0_1_ = 1;
    piVar2 = (int *)(local_574 + -4);
    LOCK();
    iVar6 = *piVar2;
    *piVar2 = *piVar2 + -1;
    UNLOCK();
    if (iVar6 == 1 || iVar6 + -1 < 0) {
      (**(code **)(**(int **)(local_574 + -0x10) + 4))();
    }
    local_c = (uint)local_c._1_3_ << 8;
    FUN_004ba930();
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffffc;
  }
  puVar5 = (undefined4 *)FUN_004ba4a0();
  puVar9 = param_1;
  for (uVar7 = uVar4 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
    *puVar9 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar9 = puVar9 + 1;
  }
  for (uVar7 = uVar4 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
    *(undefined1 *)puVar9 = *(undefined1 *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  if (cVar3 == 'K') {
    local_558 = (undefined4 *)FUN_004ba430();
    if (local_558 == (undefined4 *)0x0) {
      FUN_004b9d90(0xfffffff6,"KrApiLib.cpp",local_570);
      FUN_00405280();
      local_c = (uint)local_c._1_3_ << 8;
      FUN_004ba930();
      local_c = 0xffffffff;
      FUN_004ba4b0();
      ExceptionList = local_14;
      return 0xfffffff6;
    }
    puVar5 = param_1;
    puVar9 = local_558;
    for (uVar7 = uVar4 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar9 = *puVar5;
      puVar5 = puVar5 + 1;
      puVar9 = puVar9 + 1;
    }
    for (uVar7 = uVar4 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined1 *)puVar9 = *(undefined1 *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
    FUN_004ba410(local_558);
    puVar5 = local_558;
    for (uVar7 = uVar4 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *param_1 = *puVar5;
      puVar5 = puVar5 + 1;
      param_1 = param_1 + 1;
    }
    for (uVar7 = uVar4 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined1 *)param_1 = *(undefined1 *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      param_1 = (undefined4 *)((int)param_1 + 1);
    }
    FUN_004ba450(local_558);
  }
  else if (cVar3 != 'U') {
    FUN_004b9d90(0xfffffff5,"KrApiLib.cpp",local_570);
    FUN_00405280();
    local_c = (uint)local_c._1_3_ << 8;
    FUN_004ba930();
    local_c = 0xffffffff;
    FUN_004ba4b0();
    ExceptionList = local_14;
    return 0xfffffff5;
  }
  FUN_00405280();
  local_c = (uint)local_c._1_3_ << 8;
  FUN_004ba930();
  local_c = 0xffffffff;
  FUN_004ba4b0();
  ExceptionList = local_14;
  return uVar4;
}

