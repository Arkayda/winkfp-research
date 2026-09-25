
void FUN_0041ae40(int *param_1,int *param_2)

{
  int *piVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 in_EDX;
  int unaff_EDI;
  int local_458;
  int local_454;
  int local_450;
  int *local_44c;
  int *local_448;
  char local_441;
  short local_440 [2];
  char local_43c [1064];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_005f54a1;
  local_10 = ExceptionList;
  uVar2 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *param_1 = 0;
  local_44c = param_2;
  *param_2 = 0;
  local_14 = uVar2;
  FUN_0045cab0();
  uVar3 = FUN_00405130(in_EDX);
  local_8 = 0;
  uVar3 = FUN_00404be0(&local_450,uVar3,&DAT_0062f104,uVar2);
  local_8._0_1_ = 1;
  puVar4 = (undefined4 *)FUN_00404be0(&local_458,uVar3,"FLASH_ZEITEN_LESEN");
  local_8._0_1_ = 2;
  local_441 = FUN_0041bc80(0x1c2f,0x1a5,*puVar4);
  local_8._0_1_ = 1;
  piVar1 = (int *)(local_458 + -4);
  LOCK();
  iVar5 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar5 + -1 < 1) {
    (**(code **)(**(int **)(local_458 + -0x10) + 4))((undefined4 *)(local_458 + -0x10));
  }
  local_8 = (uint)local_8._1_3_ << 8;
  piVar1 = (int *)(local_450 + -4);
  LOCK();
  iVar5 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar5 + -1 < 1) {
    (**(code **)(**(int **)(local_450 + -0x10) + 4))((undefined4 *)(local_450 + -0x10));
  }
  local_8 = 0xffffffff;
  piVar1 = (int *)(local_454 + -4);
  LOCK();
  iVar5 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar5 + -1 < 1) {
    (**(code **)(**(int **)(local_454 + -0x10) + 4))((undefined4 *)(local_454 + -0x10));
  }
  if (local_441 == '\0') {
    iVar5 = FUN_0045cae0(local_440,"FLASH_SIGNATURTESTZEIT",1);
    if (iVar5 != 0) {
      *param_1 = (int)local_440[0];
    }
    iVar5 = FUN_0045cae0(local_440,"FLASH_AUTHENTISIERZEIT",1);
    if (iVar5 != 0) {
      *local_44c = (int)local_440[0];
    }
    iVar5 = FUN_0045cae0(local_440,"FLASH_RESETZEIT",1);
    if (iVar5 != 0) {
      *local_448 = (int)local_440[0];
    }
    if (*(char *)(unaff_EDI + 0x888) != '\0') {
      _sprintf(local_43c,"%.*s: %d",0x400,&DAT_00630800,*param_1);
      FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
    }
    if (*(char *)(unaff_EDI + 0x888) != '\0') {
      _sprintf(local_43c,"%.*s: %d",0x400,&DAT_00630820,*local_44c);
      FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
    }
    if (*(char *)(unaff_EDI + 0x888) != '\0') {
      _sprintf(local_43c,"%.*s: %d",0x400,&DAT_0063083c,*local_448);
      FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
    }
  }
  ExceptionList = local_10;
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffffc);
  return;
}

