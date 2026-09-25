
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_004bbff0(undefined1 *param_1)

{
  (&DAT_008949a0)[DAT_008949f4] = 0x80;
  DAT_008949f4 = DAT_008949f4 + 1;
  if (DAT_008949f4 == 0x40) {
    FUN_004bbdf0();
  }
  while (DAT_008949f4 != 0x38) {
    (&DAT_008949a0)[DAT_008949f4] = 0;
    DAT_008949f4 = DAT_008949f4 + 1;
    if (DAT_008949f4 == 0x40) {
      FUN_004bbdf0();
    }
  }
  DAT_008949d8 = (char)DAT_008949e4 << 3;
  DAT_008949d9 = (undefined1)(DAT_008949e4 >> 5);
  DAT_008949dc = (byte)(DAT_008949e4 >> 0x1d);
  _DAT_008949dd = 0;
  DAT_008949da = (undefined1)(DAT_008949e4 >> 0xd);
  DAT_008949db = (undefined1)(DAT_008949e4 >> 0x15);
  DAT_008949df = 0;
  FUN_004bbdf0();
  *param_1 = (undefined1)DAT_008949e8;
  param_1[1] = (char)((uint)DAT_008949e8 >> 8);
  param_1[2] = DAT_008949e8._2_1_;
  param_1[3] = DAT_008949e8._3_1_;
  param_1[4] = (undefined1)DAT_008949e0;
  param_1[5] = (char)((uint)DAT_008949e0 >> 8);
  param_1[6] = DAT_008949e0._2_1_;
  param_1[7] = DAT_008949e0._3_1_;
  param_1[8] = (undefined1)DAT_008949f0;
  param_1[9] = (char)((uint)DAT_008949f0 >> 8);
  param_1[10] = DAT_008949f0._2_1_;
  param_1[0xb] = DAT_008949f0._3_1_;
  param_1[0xc] = (undefined1)DAT_008949ec;
  param_1[0xd] = (char)((uint)DAT_008949ec >> 8);
  param_1[0xe] = DAT_008949ec._2_1_;
  param_1[0xf] = DAT_008949ec._3_1_;
  return;
}

