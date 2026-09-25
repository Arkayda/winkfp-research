
undefined1 FUN_004a5960(void)

{
  char cVar1;
  undefined1 uVar2;
  
  if ((DAT_0088146c == '\0') || (DAT_008817c8 != '\0')) {
    return 1;
  }
  cVar1 = FUN_004a5820();
  if (cVar1 == '\0') {
    cVar1 = FUN_004a5820();
    if (cVar1 == '\0') {
      return 1;
    }
    FUN_004a57e0();
    FUN_004a57e0();
    uVar2 = FUN_004901b0(&DAT_008817d8,"DIAGNOSE_AUFRECHT","NEIN;JA",&DAT_0062e5ae);
    return uVar2;
  }
  FUN_004a57e0();
  FUN_004a57e0();
  cVar1 = FUN_004901b0(&DAT_008817d8,"NORMALER_DATENVERKEHR","NEIN;NEIN;JA",&DAT_0062e5ae);
  if ((cVar1 != '\0') &&
     (cVar1 = FUN_004901b0(&DAT_008817d8,"NORMALER_DATENVERKEHR","JA;NEIN;NEIN",&DAT_0062e5ae),
     cVar1 != '\0')) {
    return 1;
  }
  return 0;
}

