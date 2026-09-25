
void FUN_00461800(char *param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  char cVar3;
  int iVar4;
  undefined4 local_30;
  char local_2c [36];
  uint local_8;
  
  local_8 = DAT_00667a24 ^ (uint)&stack0xfffffffc;
  __time32(&local_30);
  FUN_005cafa9(local_30);
  local_30 = FUN_005cafbb();
  _sprintf(local_2c,"%4.4lx",local_30);
  iVar4 = 0;
  while (local_2c[0] != '\0') {
    local_2c[0] = local_2c[iVar4 + 1];
    iVar4 = iVar4 + 1;
  }
  cVar1 = local_2c[iVar4 + -3];
  *param_1 = local_2c[iVar4 + -4];
  cVar2 = local_2c[iVar4 + -2];
  param_1[1] = cVar1;
  cVar1 = local_2c[iVar4 + -1];
  cVar3 = local_2c[iVar4];
  param_1[2] = cVar2;
  param_1[3] = cVar1;
  param_1[4] = cVar3;
  _sprintf(param_2,"0x%2.2x%2.2x%2.2x%2.2x",(int)*param_1,(int)param_1[1],(int)param_1[2],(int)cVar1
          );
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}

