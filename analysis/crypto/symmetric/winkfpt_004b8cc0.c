
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_004b8cc0(undefined4 param_1)

{
  undefined4 *in_EAX;
  char local_c [12];
  
  builtin_strncpy(local_c,"SetSymmKey",0xb);
  switch(param_1) {
  case 1:
    _DAT_00894a10 = *in_EAX;
    _DAT_00894a14 = in_EAX[1];
    _DAT_00894a18 = in_EAX[2];
    _DAT_00894a1c = in_EAX[3];
    return 0;
  case 2:
    _DAT_00894a00 = *in_EAX;
    _DAT_00894a04 = in_EAX[1];
    _DAT_00894a08 = in_EAX[2];
    _DAT_00894a0c = in_EAX[3];
    return 0;
  case 3:
    _DAT_00663360 = *in_EAX;
    _DAT_00663364 = in_EAX[1];
    _DAT_00663368 = in_EAX[2];
    _DAT_0066336c = in_EAX[3];
    return 0;
  case 4:
    _DAT_00663370 = *in_EAX;
    _DAT_00663374 = in_EAX[1];
    _DAT_00663378 = in_EAX[2];
    _DAT_0066337c = in_EAX[3];
    return 0;
  case 5:
    _DAT_00663380 = *in_EAX;
    _DAT_00663384 = in_EAX[1];
    _DAT_00663388 = in_EAX[2];
    _DAT_0066338c = in_EAX[3];
    return 0;
  default:
    FUN_004b9d90(0xfffffffd,"KrApiLib.cpp",local_c,0x219);
    return 0xfffffffd;
  }
}

