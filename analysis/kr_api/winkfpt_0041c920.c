
/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */

void FUN_0041c920(int param_1)

{
  int *piVar1;
  byte bVar2;
  char cVar3;
  undefined4 *puVar4;
  void *pvVar5;
  char *pcVar6;
  int iVar7;
  undefined4 uVar8;
  byte *pbVar9;
  int in_ECX;
  byte *pbVar10;
  char *unaff_EDI;
  bool bVar11;
  undefined1 local_1c8c [4];
  int local_1c88;
  int local_1c84;
  int local_1c80;
  int local_1c7c;
  int local_1c78;
  int local_1c74;
  int local_1c70;
  size_t local_1c6c;
  int local_1c68;
  int local_1c64;
  int local_1c60;
  char local_1c59;
  int local_1c58;
  char local_1c51;
  char local_1c50 [1064];
  undefined1 local_1828 [1024];
  char local_1428 [1024];
  byte local_1028 [1024];
  char local_c28 [5];
  undefined1 local_c23 [1019];
  undefined1 local_828 [4];
  undefined1 local_824;
  undefined1 local_81b;
  undefined1 local_81a;
  undefined1 local_813 [1002];
  byte abStack_429 [1025];
  char local_28 [12];
  undefined1 local_1c [8];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_005f5fe1;
  local_10 = ExceptionList;
  local_14 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  builtin_strncpy(unaff_EDI,"Authentication",0xf);
  local_1c6c = 0x400;
  local_1c88 = 2000;
  local_1c80 = 0;
  local_1c78 = in_ECX;
  _memset(local_828,0,0x400);
  _memset(local_1028,0,0x400);
  FUN_0045cab0();
  puVar4 = (undefined4 *)FUN_00405130(in_ECX);
  local_8 = 0;
  FUN_00404d10(", SERIENNUMMER_LESEN",0x14);
  local_1c51 = FUN_0041bc80(0x7e4,0x64f,*puVar4);
  local_8._0_1_ = 0xff;
  local_8._1_3_ = 0xffffff;
  piVar1 = (int *)(local_1c68 + -4);
  LOCK();
  iVar7 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar7 + -1 < 1) {
    (**(code **)(**(int **)(local_1c68 + -0x10) + 4))((undefined4 *)(local_1c68 + -0x10));
  }
  if (local_1c51 == '\0') {
    FUN_0045cb20(local_c28,"SERIENNUMMER",1,&DAT_0062e5ae);
    pvVar5 = FID_conflict__memcpy(local_c28,local_c23,4);
    *(undefined1 *)((int)pvVar5 + 5) = 0;
    FUN_00405130("SgSerienNr         : ");
    pcVar6 = local_c28;
    local_8 = 1;
    do {
      cVar3 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar3 != '\0');
    FUN_00404d10(local_c28,(int)pcVar6 - (int)(local_c28 + 1));
    if (unaff_EDI[0x888] != '\0') {
      FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
    }
    local_8 = 0xffffffff;
    piVar1 = (int *)(local_1c68 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 == 1 || iVar7 + -1 < 0) {
      (**(code **)(**(int **)(local_1c68 + -0x10) + 4))((undefined4 *)(local_1c68 + -0x10));
    }
    FUN_00461800(local_1c,local_28);
    DAT_00893f49 = 1;
    iVar7 = FUN_00461e40(1);
    if ((0 < iVar7) || (iVar7 = FUN_00461e40(2), 0 < iVar7)) {
      FUN_00461c80(1,10000);
      FUN_00461c80(2,0x1e46);
    }
    FUN_00405130("HDD_AUTHENTISIERUNGS_LEVEL");
    local_8 = 2;
    FUN_00404d10(&DAT_00630ed4,1);
    pcVar6 = local_28;
    do {
      cVar3 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar3 != '\0');
    FUN_00404d10(local_28,(int)pcVar6 - (int)(local_28 + 1));
    FUN_0045cab0();
    uVar8 = FUN_00405130(in_ECX);
    local_8._0_1_ = 3;
    uVar8 = FUN_00404be0(&local_1c70,uVar8,&DAT_00630ecc);
    local_8._0_1_ = 4;
    uVar8 = FUN_00404850(&local_1c74,uVar8,&local_1c60);
    local_8._0_1_ = 5;
    puVar4 = (undefined4 *)FUN_00404be0(&local_1c68,uVar8,&DAT_00630ed0);
    local_8._0_1_ = 6;
    local_1c51 = FUN_0041bc80(0x7e4,0x661,*puVar4);
    local_8._0_1_ = 5;
    piVar1 = (int *)(local_1c68 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 == 1 || iVar7 + -1 < 0) {
      (**(code **)(**(int **)(local_1c68 + -0x10) + 4))((undefined4 *)(local_1c68 + -0x10));
    }
    local_8._0_1_ = 4;
    piVar1 = (int *)(local_1c74 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 == 1 || iVar7 + -1 < 0) {
      (**(code **)(**(int **)(local_1c74 + -0x10) + 4))((undefined4 *)(local_1c74 + -0x10));
    }
    local_8._0_1_ = 3;
    piVar1 = (int *)(local_1c70 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 == 1 || iVar7 + -1 < 0) {
      (**(code **)(**(int **)(local_1c70 + -0x10) + 4))((undefined4 *)(local_1c70 + -0x10));
    }
    local_8._0_1_ = 2;
    piVar1 = (int *)(local_1c64 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 + -1 < 1) {
      (**(code **)(**(int **)(local_1c64 + -0x10) + 4))((undefined4 *)(local_1c64 + -0x10));
    }
    if (local_1c51 == '\0') {
      FUN_00405130(in_ECX);
      local_8._0_1_ = 7;
      FUN_00404d10(&DAT_0062f104,2);
      FUN_00404d10("NG_AUTHENTISIERUNG_START",0x18);
      iVar7 = FUN_0045cad0(local_1828,local_1c8c,"ZUFALLSZAHL",1);
      if (iVar7 == 0) {
        FUN_00404d10(" (...): ",8);
        pbVar9 = abStack_429 + 1;
        do {
          bVar2 = *pbVar9;
          pbVar9 = pbVar9 + 1;
        } while (bVar2 != 0);
        FUN_00404d10(abStack_429 + 1,(int)pbVar9 - (int)(abStack_429 + 2));
        iVar7 = 0x7d2;
      }
      else {
        FUN_0045cb20(local_1428,"AUTHENTISIERUNG",1,&DAT_0062e5ae);
        FUN_00405130("Authentisierungsart : ");
        pcVar6 = local_1428;
        local_8 = CONCAT31(local_8._1_3_,8);
        do {
          cVar3 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar3 != '\0');
        FUN_00404d10(local_1428,(int)pcVar6 - (int)(local_1428 + 1));
        if (unaff_EDI[0x888] != '\0') {
          FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
        }
        local_8._0_1_ = 7;
        piVar1 = (int *)(local_1c64 + -4);
        LOCK();
        iVar7 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if (iVar7 == 1 || iVar7 + -1 < 0) {
          (**(code **)(**(int **)(local_1c64 + -0x10) + 4))((undefined4 *)(local_1c64 + -0x10));
        }
        FUN_00405130("Key  : ");
        local_8 = CONCAT31(local_8._1_3_,9);
        FUN_00404e10(unaff_EDI + 0x5f6);
        if (unaff_EDI[0x888] != '\0') {
          FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
        }
        local_8._0_1_ = 7;
        piVar1 = (int *)(local_1c64 + -4);
        LOCK();
        iVar7 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if (iVar7 == 1 || iVar7 + -1 < 0) {
          (**(code **)(**(int **)(local_1c64 + -0x10) + 4))((undefined4 *)(local_1c64 + -0x10));
        }
        local_1c84 = 0;
        FUN_004617c0(unaff_EDI + 0x5f6,local_1c,local_c28,local_1428,local_1828,3,local_1028,
                     &local_1c6c,&local_1c84);
        if (local_1c84 == 0) {
          if (unaff_EDI[0x888] != '\0') {
            _sprintf(local_1c50,"%.*s: %d",0x400,"Schluessellaenge   ",local_1c6c);
            FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
          }
          local_81b = (undefined1)local_1c6c;
          local_828[0] = 1;
          local_824 = (undefined1)param_1;
          local_81a = 0;
          local_813[local_1c6c] = 3;
          FID_conflict__memcpy(local_813,local_1028,local_1c6c);
          DAT_00893f49 = 1;
          iVar7 = FUN_00461e40(1);
          if (iVar7 < 1) {
            FUN_00461e40(2);
            FUN_00461c80(1,10000);
            FUN_00461c80(2,0x1e46);
          }
          else {
            FUN_00461c80(1,10000);
            FUN_00461c80(2,0x1e46);
          }
          FUN_00461c80(3,(param_1 + 1) * 1000);
          iVar7 = FUN_00461e40(3);
          local_1c51 = '\0';
          local_1c59 = '\0';
          do {
            cVar3 = local_1c51;
            if (0 < iVar7) {
              if (local_1c59 == '\0') {
                FUN_0041acc0();
                uVar8 = FUN_00404be0(&local_1c74,&local_1c58," (...): ");
                local_8._0_1_ = 0x11;
                puVar4 = (undefined4 *)FUN_00404be0(&local_1c70,uVar8,abStack_429 + 1);
                local_8._0_1_ = 0x12;
                FUN_0041bc80(0x821,0x723,*puVar4);
                FUN_00405280();
                FUN_00405280();
LAB_0041d6a9:
                FUN_00405280();
                FUN_00405280();
                goto LAB_0041d6c1;
              }
              break;
            }
            FUN_0045cac0(local_1c78,"NG_AUTHENTISIERUNG_START",local_828,local_1c6c + 0x16,
                         &DAT_0062e5ae);
            iVar7 = FUN_0045cb20(abStack_429 + 1,"JOB_STATUS",1,&DAT_0062e5ae);
            if (iVar7 == 0) {
              if (unaff_EDI[0x888] != '\0') {
                FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
              }
              puVar4 = (undefined4 *)FUN_00404be0(&local_1c7c,&local_1c58," (...)");
              local_8._0_1_ = 0xd;
              cVar3 = FUN_0041bc80(0x821,0x70f,*puVar4);
              local_8._0_1_ = 7;
              piVar1 = (int *)(local_1c7c + -4);
              LOCK();
              iVar7 = *piVar1;
              *piVar1 = *piVar1 + -1;
              UNLOCK();
              if (iVar7 == 1 || iVar7 + -1 < 0) {
                (**(code **)(**(int **)(local_1c7c + -0x10) + 4))
                          ((undefined4 *)(local_1c7c + -0x10));
              }
              if (cVar3 != '\0') goto LAB_0041d6a9;
            }
            else {
              pbVar10 = &DAT_00630194;
              pbVar9 = abStack_429 + 1;
              do {
                bVar2 = *pbVar9;
                bVar11 = bVar2 < *pbVar10;
                if (bVar2 != *pbVar10) {
LAB_0041d123:
                  iVar7 = (1 - (uint)bVar11) - (uint)(bVar11 != 0);
                  goto LAB_0041d128;
                }
                if (bVar2 == 0) break;
                bVar2 = pbVar9[1];
                bVar11 = bVar2 < pbVar10[1];
                if (bVar2 != pbVar10[1]) goto LAB_0041d123;
                pbVar9 = pbVar9 + 2;
                pbVar10 = pbVar10 + 2;
              } while (bVar2 != 0);
              iVar7 = 0;
LAB_0041d128:
              if (iVar7 == 0) {
                if (unaff_EDI[0x888] != '\0') {
                  FUN_00460cc0(9000,DAT_00669168,"Debug-Info");
                }
                local_1c59 = '\x01';
              }
              else {
                pcVar6 = "ERROR_ERROR_AUTHENTICATION";
                pbVar9 = abStack_429 + 1;
                do {
                  bVar2 = *pbVar9;
                  bVar11 = bVar2 < (byte)*pcVar6;
                  if (bVar2 != *pcVar6) {
LAB_0041d190:
                    iVar7 = (1 - (uint)bVar11) - (uint)(bVar11 != 0);
                    goto LAB_0041d195;
                  }
                  if (bVar2 == 0) break;
                  bVar2 = pbVar9[1];
                  bVar11 = bVar2 < (byte)pcVar6[1];
                  if (bVar2 != pcVar6[1]) goto LAB_0041d190;
                  pbVar9 = pbVar9 + 2;
                  pcVar6 = pcVar6 + 2;
                } while (bVar2 != 0);
                iVar7 = 0;
LAB_0041d195:
                if (iVar7 != 0) {
                  pcVar6 = "ERROR_AUTHENTICATION";
                  pbVar9 = abStack_429 + 1;
                  do {
                    bVar2 = *pbVar9;
                    bVar11 = bVar2 < (byte)*pcVar6;
                    if (bVar2 != *pcVar6) {
LAB_0041d1c4:
                      iVar7 = (1 - (uint)bVar11) - (uint)(bVar11 != 0);
                      goto LAB_0041d1c9;
                    }
                    if (bVar2 == 0) break;
                    bVar2 = pbVar9[1];
                    bVar11 = bVar2 < (byte)pcVar6[1];
                    if (bVar2 != pcVar6[1]) goto LAB_0041d1c4;
                    pbVar9 = pbVar9 + 2;
                    pcVar6 = pcVar6 + 2;
                  } while (bVar2 != 0);
                  iVar7 = 0;
LAB_0041d1c9:
                  if (iVar7 != 0) {
                    pcVar6 = "ROUTINE_NOT_COMPLETE";
                    pbVar9 = abStack_429 + 1;
                    do {
                      bVar2 = *pbVar9;
                      bVar11 = bVar2 < (byte)*pcVar6;
                      if (bVar2 != *pcVar6) {
LAB_0041d215:
                        iVar7 = (1 - (uint)bVar11) - (uint)(bVar11 != 0);
                        goto LAB_0041d21a;
                      }
                      if (bVar2 == 0) break;
                      bVar2 = pbVar9[1];
                      bVar11 = bVar2 < (byte)pcVar6[1];
                      if (bVar2 != pcVar6[1]) goto LAB_0041d215;
                      pbVar9 = pbVar9 + 2;
                      pcVar6 = pcVar6 + 2;
                    } while (bVar2 != 0);
                    iVar7 = 0;
LAB_0041d21a:
                    if (iVar7 == 0) {
                      if (cVar3 == '\0') {
                        FUN_0041acc0();
                        local_1c51 = '\x01';
                      }
                    }
                    else {
                      pcVar6 = "NO_RESPONSE";
                      pbVar9 = abStack_429 + 1;
                      do {
                        bVar2 = *pbVar9;
                        bVar11 = bVar2 < (byte)*pcVar6;
                        if (bVar2 != *pcVar6) {
LAB_0041d270:
                          iVar7 = (1 - (uint)bVar11) - (uint)(bVar11 != 0);
                          goto LAB_0041d275;
                        }
                        if (bVar2 == 0) break;
                        bVar2 = pbVar9[1];
                        bVar11 = bVar2 < (byte)pcVar6[1];
                        if (bVar2 != pcVar6[1]) goto LAB_0041d270;
                        pbVar9 = pbVar9 + 2;
                        pcVar6 = pcVar6 + 2;
                      } while (bVar2 != 0);
                      iVar7 = 0;
LAB_0041d275:
                      if (iVar7 == 0) {
                        if (cVar3 != '\0') goto LAB_0041d373;
                        FUN_0041acc0();
                        puVar4 = (undefined4 *)FUN_00404be0(&local_1c64,&local_1c58," (...)");
                        local_8 = CONCAT31(local_8._1_3_,10);
                        cVar3 = FUN_0041bc80(0x821,0x6e2,*puVar4);
                      }
                      else {
                        uVar8 = FUN_00405130("Auf Job bei Authentisierung Antwort erhalten: ");
                        local_8._0_1_ = 0xb;
                        FUN_00404be0(&local_1c70,uVar8,abStack_429 + 1);
                        FUN_0041acc0();
                        FUN_00405280();
                        local_8._0_1_ = 7;
                        FUN_00405280();
                        puVar4 = (undefined4 *)FUN_00404be0(&local_1c68,&local_1c58," (...)");
                        local_8 = CONCAT31(local_8._1_3_,0xc);
                        cVar3 = FUN_0041bc80(0x821,0x6f4,*puVar4);
                      }
                      local_8._0_1_ = 7;
                      FUN_00405280();
                      if (cVar3 != '\0') goto LAB_0041d6a9;
                    }
LAB_0041d373:
                    local_1c80 = local_1c80 + 1;
                    if (local_1c80 == 3) {
                      DAT_00893f49 = 1;
                      iVar7 = FUN_00461e40(1);
                      if (iVar7 < 1) {
                        FUN_00461e40(2);
                        FUN_00461c80(1,10000);
                        FUN_00461c80(2,0x1e46);
                      }
                      else {
                        FUN_00461c80(1,10000);
                        FUN_00461c80(2,0x1e46);
                      }
                      local_1c80 = 0;
                    }
                    if (local_1c88 != 0) {
                      FUN_0041ad90();
                    }
                    local_1c88 = 1000;
                    goto LAB_0041d497;
                  }
                }
                FUN_0041acc0();
                local_1c59 = '\x01';
              }
            }
LAB_0041d497:
            iVar7 = FUN_00461e40(3);
          } while (local_1c59 == '\0');
          iVar7 = 0;
          if (0 < (int)local_1c6c) {
            pbVar9 = abStack_429 + 1;
            do {
              _sprintf((char *)pbVar9,"%02x",(uint)local_1028[iVar7]);
              iVar7 = iVar7 + 1;
              pbVar9 = pbVar9 + 2;
            } while (iVar7 < (int)local_1c6c);
          }
          abStack_429[local_1c6c * 2] = 0;
          uVar8 = FUN_00404be0(&local_1c64,&local_1c58," (SG-Schluessel ");
          local_8._0_1_ = 0xe;
          uVar8 = FUN_00404be0(&local_1c78,uVar8,abStack_429 + 1);
          local_8._0_1_ = 0xf;
          puVar4 = (undefined4 *)FUN_00404be0(&local_1c7c,uVar8,&DAT_00630ed0);
          local_8._0_1_ = 0x10;
          cVar3 = FUN_0041bc80(0x821,0x71d,*puVar4);
          local_1c51 = cVar3 == '\0';
          local_8._0_1_ = 0xf;
          piVar1 = (int *)(local_1c7c + -4);
          LOCK();
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 + -1 < 1) {
            (**(code **)(**(int **)(local_1c7c + -0x10) + 4))((undefined4 *)(local_1c7c + -0x10));
          }
          local_8._0_1_ = 0xe;
          piVar1 = (int *)(local_1c78 + -4);
          LOCK();
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 + -1 < 1) {
            (**(code **)(**(int **)(local_1c78 + -0x10) + 4))((undefined4 *)(local_1c78 + -0x10));
          }
          local_8._0_1_ = 7;
          piVar1 = (int *)(local_1c64 + -4);
          LOCK();
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 + -1 < 1) {
            (**(code **)(**(int **)(local_1c64 + -0x10) + 4))((undefined4 *)(local_1c64 + -0x10));
          }
          local_8 = CONCAT31(local_8._1_3_,2);
          piVar1 = (int *)(local_1c58 + -4);
          LOCK();
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 + -1 < 1) {
            (**(code **)(**(int **)(local_1c58 + -0x10) + 4))((undefined4 *)(local_1c58 + -0x10));
          }
          local_8._0_1_ = 0xff;
          local_8._1_3_ = 0xffffff;
          piVar1 = (int *)(local_1c60 + -4);
          LOCK();
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 + -1 < 1) {
            (**(code **)(**(int **)(local_1c60 + -0x10) + 4))((undefined4 *)(local_1c60 + -0x10));
          }
          goto LAB_0041d6c1;
        }
        pbVar9 = abStack_429 + 1;
        FUN_00404e10(" (...): ");
        FUN_00404e10(pbVar9);
        iVar7 = local_1c84;
      }
      FUN_00460cc0(iVar7,2,"HDDownload");
      local_8 = CONCAT31(local_8._1_3_,2);
      piVar1 = (int *)(local_1c58 + -4);
      LOCK();
      iVar7 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar7 == 1 || iVar7 + -1 < 0) {
        (**(code **)(**(int **)(local_1c58 + -0x10) + 4))((undefined4 *)(local_1c58 + -0x10));
      }
    }
    local_8._0_1_ = 0xff;
    local_8._1_3_ = 0xffffff;
    piVar1 = (int *)(local_1c60 + -4);
    LOCK();
    iVar7 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar7 == 1 || iVar7 + -1 < 0) {
      (**(code **)(**(int **)(local_1c60 + -0x10) + 4))((undefined4 *)(local_1c60 + -0x10));
    }
  }
LAB_0041d6c1:
  ExceptionList = local_10;
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffffc);
  return;
}

