
void FUN_00493090(ushort param_1,char *param_2,ushort param_3)

{
  char *pcVar1;
  ushort uVar2;
  ushort *puVar3;
  uint uVar4;
  char local_1c [20];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  uVar4 = (uint)param_3;
  puVar3 = (ushort *)(&PTR_DAT_0065fa70)[uVar4];
  uVar2 = 0;
  if (*puVar3 != 0) {
    do {
      if (uVar2 == 0x7f8) {
        uVar2 = 0x7f8;
      }
      if (param_1 == puVar3[(uVar2 + 1) * 0xe]) goto LAB_0049320d;
      uVar2 = uVar2 + 1;
    } while (uVar2 < *puVar3);
  }
  puVar3 = (ushort *)(&PTR_DAT_0065fa7c)[uVar4];
  uVar2 = 0;
  if (*puVar3 != 0) {
    do {
      if (param_1 == puVar3[(uVar2 + 1) * 0xe]) goto LAB_0049320d;
      uVar2 = uVar2 + 1;
    } while (uVar2 < *puVar3);
  }
  puVar3 = (ushort *)(&PTR_DAT_0065fa88)[uVar4];
  uVar2 = 0;
  if (*puVar3 != 0) {
    do {
      if (param_1 == puVar3[(uVar2 + 1) * 0xe]) goto LAB_0049320d;
      uVar2 = uVar2 + 1;
    } while (uVar2 < *puVar3);
  }
  puVar3 = (ushort *)(&PTR_DAT_0065fa94)[uVar4];
  uVar2 = 0;
  if (*puVar3 != 0) {
    do {
      if (param_1 == puVar3[(uVar2 + 1) * 0xe]) goto LAB_0049320d;
      uVar2 = uVar2 + 1;
    } while (uVar2 < *puVar3);
  }
  puVar3 = (ushort *)(&PTR_DAT_0065faa0)[uVar4];
  uVar2 = 0;
  if (*puVar3 != 0) {
    do {
      if (param_1 == puVar3[(uVar2 + 1) * 0xe]) {
LAB_0049320d:
        _strncpy(param_2,(char *)(puVar3 + (uint)uVar2 * 0xe + 1),0x1a);
        __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < *puVar3);
  }
  *param_2 = '\0';
  pcVar1 = __itoa((uint)param_1,local_1c,10);
  FUN_00460cc0(0x116e,0,s_DEF_FILE_C_0065fa64,s_GetKeyWord_0065fac4,1,pcVar1);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

