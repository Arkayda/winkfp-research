
void FUN_0046f6d0(ushort param_1,ushort param_2,int *param_3)

{
  ushort uVar1;
  char local_1c [20];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  uVar1 = 0;
  if (*(ushort *)(&DAT_00701668 + (uint)param_1 * 8) != 0) {
    do {
      if (param_2 ==
          *(ushort *)((uint)uVar1 * 0x20 + 0x1a + *(int *)(&DAT_0070166c + (uint)param_1 * 8))) {
        *param_3 = (uint)uVar1 * 0x20 + *(int *)(&DAT_0070166c + (uint)param_1 * 8);
        __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      uVar1 = uVar1 + 1;
    } while (uVar1 < *(ushort *)(&DAT_00701668 + (uint)param_1 * 8));
  }
  __itoa((uint)param_2,local_1c,10);
  FUN_00460c90(0x107b,2,s_ATBALGO_C_0065f288,s_atbGetKeyWord_0065f2d4,1);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

