
undefined1 FUN_004a5850(void)

{
  char cVar1;
  
  if (DAT_0088146c != '\0') {
    return 1;
  }
  if (DAT_008817c8 == '\0') {
    FUN_004a57e0();
    FUN_004a57e0();
    cVar1 = FUN_004901b0(&DAT_008817d8,"NORMALER_DATENVERKEHR","NEIN;NEIN;JA",&DAT_0062e5ae);
    if (cVar1 == '\0') {
      return 0;
    }
  }
  else {
    FUN_004a5eb0(1);
  }
  cVar1 = FUN_004901b0(&DAT_008817d8,"NORMALER_DATENVERKEHR","JA;NEIN;NEIN",&DAT_0062e5ae);
  if (cVar1 == '\0') {
    return 0;
  }
  DAT_0088146c = 1;
  return 1;
}

