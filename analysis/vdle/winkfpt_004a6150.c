
void FUN_004a6150(undefined4 param_1,undefined4 param_2)

{
  char *pcVar1;
  
  pcVar1 = "FLASH_SCHREIBEN";
  if (0xfe < DAT_008817cc) {
    pcVar1 = "FLASH_SCHREIBEN_XXL";
  }
  FUN_00490250(&DAT_008817d8,pcVar1,param_1,param_2,&DAT_0062e5ae);
  return;
}

