
void FUN_004bb8c0(int param_1,undefined4 *param_2,int param_3,undefined4 param_4)

{
  FUN_004bbdb0();
  if (0 < param_1) {
    param_3 = param_3 - (int)param_2;
    do {
      FUN_004bbf90(*param_2,*(undefined4 *)(param_3 + (int)param_2));
      param_2 = param_2 + 1;
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  FUN_004bbff0(param_4);
  return;
}

