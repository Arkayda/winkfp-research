
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_004668b0(int param_1,int param_2)

{
  int iVar1;
  short sVar2;
  undefined1 uVar3;
  char cVar4;
  short sVar5;
  int iVar6;
  char *_Filename;
  FILE *_File;
  size_t sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  size_t _ElementSize;
  uint uVar11;
  char *_Mode;
  uint local_8;
  
  iVar6 = DAT_008817cc * param_2;
  iVar1 = (&DAT_00881498)[param_1];
  iVar9 = 0;
  iVar10 = 0;
  uVar11 = (&DAT_00881630)[param_1] - iVar6;
  iVar8 = 0;
  if (1 < param_1) {
    do {
      iVar9 = iVar9 + (&DAT_00881630)[iVar8];
      iVar10 = iVar10 + (&DAT_00881634)[iVar8];
      iVar8 = iVar8 + 2;
    } while (iVar8 < param_1 + -1);
  }
  if (iVar8 < param_1) {
    iVar8 = (&DAT_00881630)[iVar8] + 4;
  }
  else {
    iVar8 = 4;
  }
  _Mode = "rb";
  DAT_008817d4 = 0xffffffff;
  DAT_0088162c = param_2;
  _Filename = (char *)FUN_00490350();
  _File = _fopen(_Filename,_Mode);
  if (_File == (FILE *)0x0) {
    FUN_00466740(0);
    return;
  }
  iVar8 = _fseek(_File,iVar8 + iVar6 + iVar9 + iVar10,0);
  if (iVar8 == 0) {
    _DAT_006d0584 = 0;
    _DAT_006d058c = 0;
    _DAT_006d0580 = 0x101;
    _DAT_006d0588 = 0xff00;
    _DAT_006d0590 = (iVar1 + iVar6) * 0x100;
    DAT_006d0594 = (undefined1)((uint)(iVar1 + iVar6) >> 0x18);
    local_8 = 0;
    sVar2 = -1;
    if (uVar11 != 0) {
      do {
        _ElementSize = DAT_008817cc;
        if (uVar11 < DAT_008817cc + local_8) {
          _ElementSize = uVar11 - local_8;
        }
        sVar7 = _fread(&DAT_006d0595,_ElementSize,1,_File);
        if (sVar7 == 0) goto LAB_0046698b;
        uVar3 = (undefined1)(_ElementSize >> 8);
        _DAT_006d058c =
             CONCAT13((char)_ElementSize,CONCAT12(uVar3,CONCAT11((char)_ElementSize,DAT_006d058c)));
        _DAT_006d0590 = CONCAT31(_DAT_006d0591,uVar3);
        (&DAT_006d0595)[_ElementSize] = 3;
        cVar4 = FUN_004a5960();
        if (cVar4 == '\0') {
          _fclose(_File);
          FUN_00466740(0,0);
          return;
        }
        cVar4 = FUN_004a6150(&DAT_006d0580,_ElementSize + 0x16);
        if (cVar4 == '\0') {
          _fclose(_File);
          DAT_008817d4 = param_1;
          FUN_00466740(0,1);
          return;
        }
        cVar4 = FUN_00490150(&param_2,"FLASH_SCHREIBEN_STATUS",1);
        if ((cVar4 == '\0') || ((short)param_2 != 1)) {
          _fclose(_File);
          FUN_00466740(0,0);
          return;
        }
        _DAT_008818dc = _DAT_008818dc + 1;
        sVar5 = FUN_005cb370();
        if (sVar5 != sVar2) {
          FUN_00466800();
        }
        iVar1 = CONCAT13(DAT_006d0594,_DAT_006d0591) + _ElementSize;
        _DAT_006d0591 = (undefined3)iVar1;
        DAT_006d0594 = (undefined1)((uint)iVar1 >> 0x18);
        DAT_0088162c = DAT_0088162c + 1;
        local_8 = local_8 + _ElementSize;
        sVar2 = sVar5;
      } while (local_8 < uVar11);
    }
    _fclose(_File);
    if (param_1 == DAT_008817d0 + -1) {
      FUN_00466800();
    }
    FUN_00466740(1,1);
    return;
  }
LAB_0046698b:
  _fclose(_File);
  FUN_00466740(0,0);
  return;
}

