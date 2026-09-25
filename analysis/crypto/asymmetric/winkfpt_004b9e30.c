
undefined4
FUN_004b9e30(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  undefined4 uVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined1 local_10 [16];
  
  local_1c = param_2;
  local_18 = param_3;
  local_14 = param_1;
  local_28 = 4;
  local_24 = 4;
  local_20 = 8;
  FUN_004bb8c0(3,&local_1c,&local_28,local_10);
  switch(param_4) {
  case 1:
    uVar1 = FUN_004bb720(local_10,&DAT_0088b818,&DAT_0088b91c,param_5);
    return uVar1;
  case 2:
    uVar1 = FUN_004bb720(local_10,&DAT_0088ba20,&DAT_0088bb24,param_5);
    return uVar1;
  case 3:
    uVar1 = FUN_004bb720(local_10,&DAT_00662d48,&DAT_00662e4c,param_5);
    return uVar1;
  case 4:
    uVar1 = FUN_004bb720(local_10,&DAT_00662f50,&DAT_00663054,param_5);
    return uVar1;
  case 5:
    uVar1 = FUN_004bb720(local_10,&DAT_00663158,&DAT_0066325c,param_5);
    return uVar1;
  default:
    return 0xffffffff;
  }
}

