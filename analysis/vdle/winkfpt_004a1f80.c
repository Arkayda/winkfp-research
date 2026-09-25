
void FUN_004a1f80(byte *param_1,byte *param_2,char *param_3)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  byte *pbVar5;
  int iVar6;
  bool bVar7;
  
  pbVar5 = &DAT_00600d74;
  do {
    bVar1 = *param_1;
    bVar7 = bVar1 < *pbVar5;
    if (bVar1 != *pbVar5) {
LAB_004a1fb0:
      iVar3 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
      goto LAB_004a1fb5;
    }
    if (bVar1 == 0) break;
    bVar1 = param_1[1];
    bVar7 = bVar1 < pbVar5[1];
    if (bVar1 != pbVar5[1]) goto LAB_004a1fb0;
    param_1 = param_1 + 2;
    pbVar5 = pbVar5 + 2;
  } while (bVar1 != 0);
  iVar3 = 0;
LAB_004a1fb5:
  if (iVar3 == 0) {
    iVar3 = (int)&DAT_0087fe50 - (int)param_3;
    do {
      cVar2 = *param_3;
      param_3[iVar3] = cVar2;
      param_3 = param_3 + 1;
    } while (cVar2 != '\0');
    iVar3 = 0;
    pcVar4 = _strtok(&DAT_0087fe50,";");
    while (pcVar4 != (char *)0x0) {
      (&DAT_0087fe10)[iVar3] = pcVar4;
      iVar3 = iVar3 + 1;
      pcVar4 = _strtok((char *)0x0,";");
    }
    pcVar4 = "INIT_VDLE";
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      bVar7 = bVar1 < (byte)*pcVar4;
      if (bVar1 != *pcVar4) {
LAB_004a2036:
        iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_004a203b;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar5[1];
      bVar7 = bVar1 < (byte)pcVar4[1];
      if (bVar1 != pcVar4[1]) goto LAB_004a2036;
      pbVar5 = pbVar5 + 2;
      pcVar4 = pcVar4 + 2;
    } while (bVar1 != 0);
    iVar6 = 0;
LAB_004a203b:
    if (iVar6 == 0) {
      FUN_004a5b60(iVar3,&DAT_0087fe10);
      return;
    }
    pcVar4 = "START_TESTERPRESENT";
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      bVar7 = bVar1 < (byte)*pcVar4;
      if (bVar1 != *pcVar4) {
LAB_004a2078:
        iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_004a207d;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar5[1];
      bVar7 = bVar1 < (byte)pcVar4[1];
      if (bVar1 != pcVar4[1]) goto LAB_004a2078;
      pbVar5 = pbVar5 + 2;
      pcVar4 = pcVar4 + 2;
    } while (bVar1 != 0);
    iVar6 = 0;
LAB_004a207d:
    if (iVar6 == 0) {
      FUN_004a5a40(iVar3,&DAT_0087fe10);
      return;
    }
    pcVar4 = "STOP_TESTERPRESENT";
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      bVar7 = bVar1 < (byte)*pcVar4;
      if (bVar1 != *pcVar4) {
LAB_004a20c0:
        iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_004a20c5;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar5[1];
      bVar7 = bVar1 < (byte)pcVar4[1];
      if (bVar1 != pcVar4[1]) goto LAB_004a20c0;
      pbVar5 = pbVar5 + 2;
      pcVar4 = pcVar4 + 2;
    } while (bVar1 != 0);
    iVar6 = 0;
LAB_004a20c5:
    if (iVar6 == 0) {
      FUN_004a5ac0(iVar3,&DAT_0087fe10);
      return;
    }
    pcVar4 = "REQUEST_SEGMENTINFO";
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      bVar7 = bVar1 < (byte)*pcVar4;
      if (bVar1 != *pcVar4) {
LAB_004a2102:
        iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_004a2107;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar5[1];
      bVar7 = bVar1 < (byte)pcVar4[1];
      if (bVar1 != pcVar4[1]) goto LAB_004a2102;
      pbVar5 = pbVar5 + 2;
      pcVar4 = pcVar4 + 2;
    } while (bVar1 != 0);
    iVar6 = 0;
LAB_004a2107:
    if (iVar6 == 0) {
      FUN_004665d0(iVar3,&DAT_0087fe10);
      return;
    }
    pcVar4 = "SEND_SEGMENT";
    do {
      bVar1 = *param_2;
      bVar7 = bVar1 < (byte)*pcVar4;
      if (bVar1 != *pcVar4) {
LAB_004a2142:
        iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_004a2147;
      }
      if (bVar1 == 0) break;
      bVar1 = param_2[1];
      bVar7 = bVar1 < (byte)pcVar4[1];
      if (bVar1 != pcVar4[1]) goto LAB_004a2142;
      param_2 = param_2 + 2;
      pcVar4 = pcVar4 + 2;
    } while (bVar1 != 0);
    iVar6 = 0;
LAB_004a2147:
    if (iVar6 == 0) {
      FUN_00467010(iVar3,&DAT_0087fe10);
    }
  }
  return;
}

