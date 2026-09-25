
void FUN_0046f350(ushort param_1)

{
  char cVar1;
  short sVar2;
  short sVar3;
  FILE *_File;
  char *pcVar4;
  long lVar5;
  char *in_ECX;
  char *pcVar6;
  int iVar7;
  ushort uVar8;
  undefined4 *puVar9;
  void *local_74;
  char local_69;
  char local_68 [26];
  undefined2 local_4e;
  undefined4 local_4c;
  char local_48 [16];
  char local_38 [48];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  uVar8 = 0;
  local_69 = '\0';
  sVar3 = 0;
  sVar2 = 0;
  _memset(local_48,0,0x40);
  local_74 = (void *)0x0;
  FUN_004a7220("Lese Schluesselworttabelle %s\n");
  _File = _fopen(in_ECX,"r");
  if (_File == (FILE *)0x0) {
    FUN_00460cc0(0x106c,2,s_ATBALGO_C_0065f288,s_LeseDefinitionsdatei_0065f2b0,1);
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  pcVar4 = _fgets(local_48,0x40,_File);
  do {
    if ((pcVar4 == (char *)0x0) || (sVar2 != 0)) {
      _fclose(_File);
      iVar7 = (uint)param_1 * 8;
      if (sVar2 == 0) {
        *(ushort *)(&DAT_00701668 + iVar7) = uVar8;
        *(void **)(&DAT_0070166c + iVar7) = local_74;
        __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      *(undefined4 *)(&DAT_0070166c + iVar7) = 0;
      *(undefined2 *)(&DAT_00701668 + iVar7) = 0;
      __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    sVar3 = sVar3 + 1;
    FUN_004a7240(&DAT_006019c0,sVar3);
    if (local_48[0] != '/') {
      pcVar4 = local_48;
      do {
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      if (1 < (uint)((int)pcVar4 - (int)(local_48 + 1))) {
        if (local_48[0] == 'B') {
          if (((local_48[2] == 'A') || (local_48[2] == 'F')) || (local_48[2] == 'P')) {
            local_69 = local_48[2];
            goto LAB_0046f503;
          }
          local_69 = '\0';
        }
        else {
LAB_0046f503:
          if (local_48[0] != local_69) goto LAB_0046f496;
          if (local_48[1] == '_') {
            local_4c = 0;
          }
          else {
            if (local_48[1] != 'x') goto LAB_0046f466;
            local_4c = 1;
          }
          pcVar4 = _strtok(local_48 + 2," ");
          if (pcVar4 != (char *)0x0) {
            pcVar6 = pcVar4;
            do {
              cVar1 = *pcVar6;
              pcVar6 = pcVar6 + 1;
            } while (cVar1 != '\0');
            if ((uint)((int)pcVar6 - (int)(pcVar4 + 1)) < 0xb) {
              lVar5 = _atol(pcVar4);
              local_4e = (undefined2)lVar5;
              pcVar4 = _strtok(local_38," \n");
              if (pcVar4 != (char *)0x0) {
                pcVar6 = pcVar4;
                do {
                  cVar1 = *pcVar6;
                  pcVar6 = pcVar6 + 1;
                } while (cVar1 != '\0');
                if ((uint)((int)pcVar6 - (int)(pcVar4 + 1)) < 0x1a) {
                  iVar7 = -(int)pcVar4;
                  do {
                    cVar1 = *pcVar4;
                    pcVar4[(int)(local_68 + iVar7)] = cVar1;
                    pcVar4 = pcVar4 + 1;
                  } while (cVar1 != '\0');
                  uVar8 = uVar8 + 1;
                  local_74 = _realloc(local_74,(uint)uVar8 * 0x20);
                  if (local_74 == (void *)0x0) {
                    FUN_00460c90(0x1077,2,s_ATBALGO_C_0065f288,s_LeseDefinitionsdatei_0065f2b0,2);
                    sVar2 = -0xf;
                  }
                  else {
                    pcVar4 = local_68;
                    puVar9 = (undefined4 *)(((uint)uVar8 * 0x20 - 0x20) + (int)local_74);
                    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
                      *puVar9 = *(undefined4 *)pcVar4;
                      pcVar4 = pcVar4 + 4;
                      puVar9 = puVar9 + 1;
                    }
                  }
                  goto LAB_0046f496;
                }
              }
            }
          }
        }
LAB_0046f466:
        FUN_00460c90(0x107a,2,s_ATBALGO_C_0065f288,s_LeseDefinitionsdatei_0065f2b0,3);
        sVar2 = -0x12;
        FUN_004a7220("Fehler beim Einlesen der Datei %s\n",in_ECX);
      }
    }
LAB_0046f496:
    _memset(local_48,0,0x40);
    pcVar4 = _fgets(local_48,0x40,_File);
  } while( true );
}

