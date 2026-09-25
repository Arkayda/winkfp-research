
undefined4 FUN_004bd0e0(undefined4 param_1,uint *param_2,undefined4 *param_3,int *param_4)

{
  undefined4 *puVar1;
  int *piVar2;
  bool bVar3;
  uint uVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  ushort uVar9;
  ushort uVar10;
  uint uVar11;
  undefined *puVar12;
  byte bVar13;
  int iVar14;
  undefined4 *puVar15;
  undefined4 *puVar16;
  uint local_c;
  uint *local_8;
  int local_4;
  
  piVar2 = param_4;
  if (*param_4 == 0) {
    return 0xffffffff;
  }
  if (*param_2 != 0) {
    FUN_004bd090(param_1,&DAT_0088c374,param_4);
    if (DAT_0088c374 != 0) {
      uVar11 = param_4[*param_4];
      if ((int)uVar11 < 0) {
        param_4 = (int *)0x0;
      }
      else {
        param_4 = (int *)0x20;
        do {
          uVar11 = uVar11 >> 1;
          param_4 = (int *)((int)param_4 + -1);
        } while (uVar11 != 0);
      }
      FUN_004bc760(piVar2,param_4,&DAT_0088c060);
      uVar11 = 2;
      bVar3 = false;
      puVar12 = &DAT_0088c478;
      iVar14 = 0xe;
      do {
        if (bVar3) {
          puVar15 = &DAT_0088c374;
          puVar16 = (undefined4 *)(puVar12 + -0x104);
        }
        else {
          puVar15 = (undefined4 *)(&DAT_0088c270 + (uVar11 >> 1) * 0x104);
          puVar16 = puVar15;
        }
        FUN_004bc240(puVar15,puVar16,puVar12);
        FUN_004bc960(puVar12,&DAT_0088c060);
        uVar11 = uVar11 + 1;
        bVar3 = (bool)(bVar3 ^ 1);
        puVar12 = puVar12 + 0x104;
        iVar14 = iVar14 + -1;
      } while (iVar14 != 0);
      uVar11 = *param_2;
      uVar6 = param_2[uVar11];
      local_8 = param_2 + uVar11;
      uVar10 = 0x1c;
      do {
        uVar9 = uVar10;
        uVar10 = uVar9 - 4;
        uVar4 = uVar6 >> ((byte)uVar9 & 0x1f) & 0xf;
      } while ((short)uVar4 == 0);
      piVar5 = (int *)(&DAT_0088c270 + uVar4 * 0x104);
      piVar2 = piVar5 + *piVar5;
      do {
        piVar5[uVar4 * -0x41 + -0x14a] = *piVar5;
        piVar5 = piVar5 + 1;
      } while (piVar5 <= piVar2);
      if (-1 < (short)uVar10) {
        iVar14 = (int)(short)uVar10;
        local_c = (uint)(uVar9 >> 2);
        do {
          iVar8 = DAT_0088bd48;
          puVar15 = &DAT_0088bd48 + DAT_0088bd48;
          iVar7 = 0;
          do {
            *(undefined4 *)((int)&DAT_0088d4c0 + iVar7) =
                 *(undefined4 *)((int)&DAT_0088bd48 + iVar7);
            puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar7);
            iVar7 = iVar7 + 4;
          } while (puVar16 <= puVar15);
          puVar16 = puVar15 + DAT_0088d4c0;
          *puVar16 = *puVar15;
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            puVar1 = puVar15 + -1;
            puVar15 = puVar15 + -1;
            puVar16 = puVar16 + -1;
            *puVar16 = *puVar1;
          }
          FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
          FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
          iVar8 = DAT_0088bd48;
          puVar15 = &DAT_0088bd48 + DAT_0088bd48;
          iVar7 = 0;
          do {
            *(undefined4 *)((int)&DAT_0088d4c0 + iVar7) =
                 *(undefined4 *)((int)&DAT_0088bd48 + iVar7);
            puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar7);
            iVar7 = iVar7 + 4;
          } while (puVar16 <= puVar15);
          puVar16 = puVar15 + DAT_0088d4c0;
          *puVar16 = *puVar15;
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            puVar1 = puVar15 + -1;
            puVar15 = puVar15 + -1;
            puVar16 = puVar16 + -1;
            *puVar16 = *puVar1;
          }
          FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
          FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
          iVar8 = DAT_0088bd48;
          puVar15 = &DAT_0088bd48 + DAT_0088bd48;
          iVar7 = 0;
          do {
            *(undefined4 *)((int)&DAT_0088d4c0 + iVar7) =
                 *(undefined4 *)((int)&DAT_0088bd48 + iVar7);
            puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar7);
            iVar7 = iVar7 + 4;
          } while (puVar16 <= puVar15);
          puVar16 = puVar15 + DAT_0088d4c0;
          *puVar16 = *puVar15;
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            puVar1 = puVar15 + -1;
            puVar15 = puVar15 + -1;
            puVar16 = puVar16 + -1;
            *puVar16 = *puVar1;
          }
          FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
          FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
          iVar8 = DAT_0088bd48;
          puVar15 = &DAT_0088bd48 + DAT_0088bd48;
          iVar7 = 0;
          do {
            *(undefined4 *)((int)&DAT_0088d4c0 + iVar7) =
                 *(undefined4 *)((int)&DAT_0088bd48 + iVar7);
            puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar7);
            iVar7 = iVar7 + 4;
          } while (puVar16 <= puVar15);
          puVar16 = puVar15 + DAT_0088d4c0;
          *puVar16 = *puVar15;
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            puVar1 = puVar15 + -1;
            puVar15 = puVar15 + -1;
            puVar16 = puVar16 + -1;
            *puVar16 = *puVar1;
          }
          FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
          FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
          iVar8 = DAT_0088bd48;
          uVar4 = uVar6 >> ((byte)iVar14 & 0x1f) & 0xf;
          if (uVar4 != 0) {
            puVar16 = &DAT_0088bd48 + DAT_0088bd48;
            puVar15 = puVar16 + *(int *)(&DAT_0088c270 + uVar4 * 0x104);
            *puVar15 = (&DAT_0088bd48)[DAT_0088bd48];
            for (; iVar8 != 0; iVar8 = iVar8 + -1) {
              puVar1 = puVar16 + -1;
              puVar16 = puVar16 + -1;
              puVar15 = puVar15 + -1;
              *puVar15 = *puVar1;
            }
            FUN_004bc240(puVar15,&DAT_0088c270 + uVar4 * 0x104,puVar16);
            FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
          }
          iVar14 = iVar14 + -4;
          local_c = local_c - 1;
        } while (local_c != 0);
      }
      if (1 < uVar11) {
        local_4 = uVar11 - 1;
        do {
          uVar11 = local_8[-1];
          local_8 = local_8 + -1;
          bVar13 = 0x1c;
          local_c = 8;
          do {
            iVar14 = DAT_0088bd48;
            puVar15 = &DAT_0088bd48 + DAT_0088bd48;
            iVar8 = 0;
            do {
              *(undefined4 *)((int)&DAT_0088d4c0 + iVar8) =
                   *(undefined4 *)((int)&DAT_0088bd48 + iVar8);
              puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar8);
              iVar8 = iVar8 + 4;
            } while (puVar16 <= puVar15);
            puVar16 = puVar15 + DAT_0088d4c0;
            *puVar16 = *puVar15;
            for (; iVar14 != 0; iVar14 = iVar14 + -1) {
              puVar1 = puVar15 + -1;
              puVar15 = puVar15 + -1;
              puVar16 = puVar16 + -1;
              *puVar16 = *puVar1;
            }
            FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
            FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
            iVar14 = DAT_0088bd48;
            puVar15 = &DAT_0088bd48 + DAT_0088bd48;
            iVar8 = 0;
            do {
              *(undefined4 *)((int)&DAT_0088d4c0 + iVar8) =
                   *(undefined4 *)((int)&DAT_0088bd48 + iVar8);
              puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar8);
              iVar8 = iVar8 + 4;
            } while (puVar16 <= puVar15);
            puVar16 = puVar15 + DAT_0088d4c0;
            *puVar16 = *puVar15;
            for (; iVar14 != 0; iVar14 = iVar14 + -1) {
              puVar1 = puVar15 + -1;
              puVar15 = puVar15 + -1;
              puVar16 = puVar16 + -1;
              *puVar16 = *puVar1;
            }
            FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
            FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
            iVar14 = DAT_0088bd48;
            puVar15 = &DAT_0088bd48 + DAT_0088bd48;
            iVar8 = 0;
            do {
              *(undefined4 *)((int)&DAT_0088d4c0 + iVar8) =
                   *(undefined4 *)((int)&DAT_0088bd48 + iVar8);
              puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar8);
              iVar8 = iVar8 + 4;
            } while (puVar16 <= puVar15);
            puVar16 = puVar15 + DAT_0088d4c0;
            *puVar16 = *puVar15;
            for (; iVar14 != 0; iVar14 = iVar14 + -1) {
              puVar1 = puVar15 + -1;
              puVar15 = puVar15 + -1;
              puVar16 = puVar16 + -1;
              *puVar16 = *puVar1;
            }
            FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
            FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
            iVar14 = DAT_0088bd48;
            puVar15 = &DAT_0088bd48 + DAT_0088bd48;
            iVar8 = 0;
            do {
              *(undefined4 *)((int)&DAT_0088d4c0 + iVar8) =
                   *(undefined4 *)((int)&DAT_0088bd48 + iVar8);
              puVar16 = (undefined4 *)((int)&DAT_0088bd4c + iVar8);
              iVar8 = iVar8 + 4;
            } while (puVar16 <= puVar15);
            puVar16 = puVar15 + DAT_0088d4c0;
            *puVar16 = *puVar15;
            for (; iVar14 != 0; iVar14 = iVar14 + -1) {
              puVar1 = puVar15 + -1;
              puVar15 = puVar15 + -1;
              puVar16 = puVar16 + -1;
              *puVar16 = *puVar1;
            }
            FUN_004bc240(puVar16,&DAT_0088d4c0,puVar15);
            FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
            iVar14 = DAT_0088bd48;
            uVar6 = uVar11 >> (bVar13 & 0x1f) & 0xf;
            if (uVar6 != 0) {
              puVar16 = &DAT_0088bd48 + DAT_0088bd48;
              puVar15 = puVar16 + *(int *)(&DAT_0088c270 + uVar6 * 0x104);
              *puVar15 = (&DAT_0088bd48)[DAT_0088bd48];
              for (; iVar14 != 0; iVar14 = iVar14 + -1) {
                puVar1 = puVar16 + -1;
                puVar16 = puVar16 + -1;
                puVar15 = puVar15 + -1;
                *puVar15 = *puVar1;
              }
              FUN_004bc240(puVar15,&DAT_0088c270 + uVar6 * 0x104,puVar16);
              FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
            }
            bVar13 = bVar13 - 4;
            local_c = local_c + -1;
          } while (local_c != 0);
          local_4 = local_4 + -1;
        } while (local_4 != 0);
      }
      if (param_4 != (int *)0x0) {
        FUN_004bc760(&DAT_0088bd48,param_4,&DAT_0088bd48);
        FUN_004bc960(&DAT_0088bd48,&DAT_0088c060);
      }
      FUN_004bc760(&DAT_0088bd48,-(int)param_4,param_3);
      return 0;
    }
    *param_3 = 0;
    return 0;
  }
  *param_3 = 1;
  param_3[1] = 1;
  return 0;
}

