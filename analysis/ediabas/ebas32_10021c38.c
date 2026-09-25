
undefined4 FUN_10021c38(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  undefined4 uVar3;
  undefined2 uVar4;
  undefined4 *puVar5;
  
  bVar1 = FUN_1000f792(1,2);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    FUN_1000fdc4(1,s_ifhSetProgramVoltage____10087cf0);
    FUN_1000fe1b(1,(short)DAT_100d1788);
    FUN_1000fd9a(1);
  }
  puVar5 = &DAT_100d1788;
  uVar4 = 2;
  iVar2 = FUN_1002267c();
  uVar3 = FUN_1002a800((short)iVar2,uVar4,puVar5);
  DAT_100d013c = (short)uVar3;
  if (DAT_100d013c != 0) {
    uVar3 = FUN_100226a0(0,0,0x5e,DAT_100d013c);
  }
  DAT_100d0140 = 0;
  return CONCAT22((short)((uint)uVar3 >> 0x10),0xffff);
}

