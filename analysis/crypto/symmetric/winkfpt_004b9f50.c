
undefined4
FUN_004b9f50(undefined1 *param_1,undefined4 *param_2,undefined1 *param_3,undefined4 param_4,
            undefined4 param_5)

{
  undefined4 local_10;
  undefined1 local_c;
  undefined1 local_b;
  undefined1 local_a;
  undefined1 local_9;
  undefined1 local_8;
  undefined1 local_7;
  undefined1 local_6;
  undefined1 local_5;
  undefined1 local_4;
  undefined1 local_3;
  undefined1 local_2;
  undefined1 local_1;
  
  local_10 = *param_2;
  local_c = *param_3;
  local_b = param_3[1];
  local_a = param_3[2];
  local_9 = param_3[3];
  local_8 = *param_1;
  local_7 = param_1[1];
  local_6 = param_1[2];
  local_5 = param_1[3];
  local_4 = param_1[4];
  local_3 = param_1[5];
  local_2 = param_1[6];
  local_1 = param_1[7];
  switch(param_4) {
  case 1:
    FUN_004bb930(&local_10,&DAT_00894a10,param_5);
    return 0;
  case 2:
    FUN_004bb930(&local_10,&DAT_00894a00,param_5);
    return 0;
  case 3:
    FUN_004bb930(&local_10,&DAT_00663360,param_5);
    return 0;
  case 4:
    FUN_004bb930(&local_10,&DAT_00663370,param_5);
    return 0;
  case 5:
    FUN_004bb930(&local_10,&DAT_00663380,param_5);
    return 0;
  default:
    return 0xffffffff;
  }
}

