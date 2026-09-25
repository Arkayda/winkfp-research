
undefined4 FUN_004b8a70(void)

{
  int in_EAX;
  int in_ECX;
  byte *pbVar1;
  
  if (0 < in_EAX) {
    pbVar1 = (byte *)(in_ECX + 2);
    do {
      *(uint *)(pbVar1 + -2) =
           (((*(uint *)(pbVar1 + -2) & 0xff) << 8 | (uint)pbVar1[-1]) << 8 | (uint)*pbVar1) << 8 |
           (uint)pbVar1[1];
      pbVar1 = pbVar1 + 4;
      in_EAX = in_EAX + -1;
    } while (in_EAX != 0);
  }
  return 0;
}

