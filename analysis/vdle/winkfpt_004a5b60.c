
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_004a5b60(int param_1,undefined4 *param_2)

{
  int *piVar1;
  byte bVar2;
  char cVar3;
  byte *pbVar4;
  int iVar5;
  byte *pbVar6;
  byte *pbVar7;
  int iVar8;
  bool bVar9;
  char *pcVar10;
  char local_1c [20];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  if (param_1 != 3) {
    FUN_004a2160("INIT_VDLE","ERROR_DLL_JOBAPIPARAM;0");
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar8 = 0;
  _memset(&DAT_008817d8,0,0x104);
  _strncpy(&DAT_008817d8,(char *)*param_2,0x103);
  pcVar10 = (char *)param_2[1];
  DAT_008817cc = _atol(pcVar10);
  if ((DAT_008817cc == 0) || (0xffe9 < DAT_008817cc)) {
LAB_004a5d9a:
    pcVar10 = "ERROR_DLL_JOBAPIPARAM;0";
  }
  else {
    pbVar6 = (byte *)param_2[2];
    pbVar7 = &DAT_00604464;
    pbVar4 = pbVar6;
    do {
      bVar2 = *pbVar4;
      bVar9 = bVar2 < *pbVar7;
      if (bVar2 != *pbVar7) {
LAB_004a5c11:
        iVar5 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
        goto LAB_004a5c16;
      }
      if (bVar2 == 0) break;
      bVar2 = pbVar4[1];
      bVar9 = bVar2 < pbVar7[1];
      if (bVar2 != pbVar7[1]) goto LAB_004a5c11;
      pbVar4 = pbVar4 + 2;
      pbVar7 = pbVar7 + 2;
    } while (bVar2 != 0);
    iVar5 = 0;
LAB_004a5c16:
    if (iVar5 == 0) {
      DAT_008817c8 = FUN_004a5dc0();
      if (DAT_008817c8 != '\0') {
        FUN_004a5b40();
        cVar3 = FUN_004a5e70();
        if (cVar3 == '\0') {
          pcVar10 = "ERROR_DLL_OPPSRESET;0";
          goto LAB_004a5d9f;
        }
        cVar3 = FUN_004a5e90(&DAT_00604440);
        if (cVar3 == '\0') {
          pcVar10 = "ERROR_DLL_OPPS_SET_TP;0";
          goto LAB_004a5d9f;
        }
        cVar3 = FUN_004a5ee0(&DAT_00604420,pcVar10);
        if (cVar3 == '\0') {
          pcVar10 = "ERROR_DLL_OPPS_SET_HEADER;0";
          goto LAB_004a5d9f;
        }
        cVar3 = FUN_004a5f90("76000001","FF0000FF");
        if (cVar3 == '\0') {
          pcVar10 = "ERROR_DLL_OPPS_SET_IOANSWER;0";
          goto LAB_004a5d9f;
        }
        cVar3 = FUN_004a6040(&DAT_006043c8);
        if (cVar3 == '\0') {
          pcVar10 = "ERROR_DLL_OPPS_SET_SERVICEID;0";
          goto LAB_004a5d9f;
        }
        FUN_004a5eb0(0);
      }
    }
    else {
      pbVar4 = &DAT_00604460;
      do {
        bVar2 = *pbVar6;
        bVar9 = bVar2 < *pbVar4;
        if (bVar2 != *pbVar4) {
LAB_004a5c41:
          iVar5 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
          goto LAB_004a5c46;
        }
        if (bVar2 == 0) break;
        bVar2 = pbVar6[1];
        bVar9 = bVar2 < pbVar4[1];
        if (bVar2 != pbVar4[1]) goto LAB_004a5c41;
        pbVar6 = pbVar6 + 2;
        pbVar4 = pbVar4 + 2;
      } while (bVar2 != 0);
      iVar5 = 0;
LAB_004a5c46:
      if (iVar5 != 0) goto LAB_004a5d9a;
      DAT_008817c8 = '\0';
    }
    cVar3 = FUN_00490570();
    if (cVar3 != '\0') {
      iVar5 = 0;
      DAT_00881628 = 0;
      _DAT_008818dc = 0;
      if (0 < DAT_008817d0) {
        do {
          piVar1 = &DAT_00881630 + iVar5;
          iVar5 = iVar5 + 1;
          iVar8 = iVar8 + (*piVar1 + -1 + DAT_008817cc) / DAT_008817cc;
          DAT_00881628 = iVar8;
        } while (iVar5 < DAT_008817d0);
      }
      DAT_008817d4 = 0xffffffff;
      DAT_008818e0 = 2;
      _sprintf(local_1c,"OKAY;%d",DAT_008817d0);
      DAT_008818e4 = 1;
      FUN_004a2160("INIT_VDLE",local_1c);
      __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    pcVar10 = "ERROR_DLL_LOADTABLE;0";
  }
LAB_004a5d9f:
  FUN_004a2160("INIT_VDLE",pcVar10);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

