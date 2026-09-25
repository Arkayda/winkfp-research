
void FUN_00490250(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  bool bVar6;
  byte local_28 [32];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  if (DAT_00735398 != (code *)0x0) {
    (*DAT_00735398)(param_1,param_2,param_3,param_4,param_5);
    cVar2 = FUN_00490120(local_28,"JOB_STATUS",1,&DAT_0062e5ae);
    if (cVar2 != '\0') {
      pbVar5 = &DAT_00602af0;
      pbVar4 = local_28;
      do {
        bVar1 = *pbVar4;
        bVar6 = bVar1 < *pbVar5;
        if (bVar1 != *pbVar5) {
LAB_004902c6:
          iVar3 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
          goto LAB_004902cb;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar4[1];
        bVar6 = bVar1 < pbVar5[1];
        if (bVar1 != pbVar5[1]) goto LAB_004902c6;
        pbVar4 = pbVar4 + 2;
        pbVar5 = pbVar5 + 2;
      } while (bVar1 != 0);
      iVar3 = 0;
LAB_004902cb:
      if (iVar3 == 0) {
        __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
    }
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

