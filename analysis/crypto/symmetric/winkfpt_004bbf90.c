
void FUN_004bbf90(int param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_2 != 0) {
    do {
      (&DAT_008949a0)[DAT_008949f4] = *(undefined1 *)(uVar1 + param_1);
      DAT_008949f4 = DAT_008949f4 + 1;
      if (DAT_008949f4 == 0x40) {
        FUN_004bbdf0();
      }
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_2);
  }
  DAT_008949e4 = DAT_008949e4 + param_2;
  return;
}

