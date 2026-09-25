
void FUN_004665d0(int param_1,undefined4 *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char local_30 [40];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  if (DAT_008818e4 == '\0') {
    pcVar6 = "ERROR_DLL_INIT_ERROR";
    goto LAB_004666b4;
  }
  if (DAT_008818e0 != 2) {
    pcVar6 = "ERROR_DLL_WRONGSTATE";
    goto LAB_004666b4;
  }
  if (param_1 != 1) {
LAB_0046660f:
    pcVar6 = "ERROR_DLL_JOBAPIPARAM";
    goto LAB_004666b4;
  }
  iVar2 = FUN_005c8227(*param_2);
  if (iVar2 == -1) {
    if (DAT_008817d4 == -1) {
      pcVar6 = "ERROR_DLL_ILEGALL_WAS";
      goto LAB_004666b4;
    }
    if (DAT_0088162c < DAT_008817c0) {
      iVar2 = 0;
    }
    else {
      iVar2 = DAT_0088162c - DAT_008817c0;
    }
    iVar3 = (&DAT_00881630)[DAT_008817d4] - DAT_008817cc * iVar2;
    iVar2 = (&DAT_00881498)[DAT_008817d4] + DAT_008817cc * iVar2;
LAB_00466712:
    _sprintf(local_30,"OKAY;0x%08X;0x%08X",iVar2,iVar3);
    cVar1 = FUN_004a5960();
    if (cVar1 == '\0') {
      pcVar6 = "ERROR_DLL_TESTERPRESENTHANDLING";
      goto LAB_004666b4;
    }
  }
  else {
    if (iVar2 != 99) {
      if ((iVar2 < -1) || (DAT_008817d0 <= iVar2)) goto LAB_0046660f;
      iVar3 = (&DAT_00881630)[iVar2];
      iVar2 = (&DAT_00881498)[iVar2];
      goto LAB_00466712;
    }
    iVar4 = 0;
    iVar5 = 0;
    iVar2 = 0;
    iVar3 = 0;
    if (1 < DAT_008817d0) {
      do {
        iVar4 = iVar4 + (&DAT_00881630)[iVar3];
        iVar5 = iVar5 + (&DAT_00881634)[iVar3];
        iVar3 = iVar3 + 2;
      } while (iVar3 < DAT_008817d0 + -1);
    }
    if (iVar3 < DAT_008817d0) {
      iVar2 = (&DAT_00881630)[iVar3];
    }
    _sprintf(local_30,"OKAY;0x%08X;0x%08X",DAT_00881498,iVar5 + iVar4 + iVar2);
  }
  pcVar6 = local_30;
LAB_004666b4:
  FUN_004a2160("REQUEST_SEGMENTINFO",pcVar6);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

