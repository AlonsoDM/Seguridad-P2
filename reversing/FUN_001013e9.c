void FUN_001013e9(long param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint local_1c;
  
  if (((int)param_2 >> 0x14 & 0xfU) != 1) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar1 = (int)param_2 >> 0x10 & 0xf;
  uVar2 = (int)param_2 >> 0xc & 0xf;
  if ((uVar2 != 0) && (uVar2 != 1)) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_1c = param_2 & 0xfff;
  if (uVar2 == 1) {
    local_1c = **(uint **)(param_1 + ((long)((int)local_1c >> 8) + 2) * 8);
  }
  **(int **)(param_1 + ((long)(int)uVar1 + 2) * 8) =
       local_1c + **(int **)(param_1 + ((long)(int)uVar1 + 2) * 8);
  return;
}

void FUN_00101322(long param_1,uint param_2)

{
  uint uVar1;
  uint local_1c;
  
  if (((int)param_2 >> 0x14 & 0xfU) != 1) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar1 = (int)param_2 >> 0xc & 0xf;
  if ((uVar1 != 0) && (uVar1 != 1)) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_1c = param_2 & 0xfff;
  if (uVar1 == 1) {
    local_1c = **(uint **)(param_1 + ((long)((int)local_1c >> 8) + 2) * 8);
  }
  **(uint **)(param_1 + ((long)(int)((int)param_2 >> 0x10 & 0xf) + 2) * 8) = local_1c;
  return;
}


void FUN_001014c6(long param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint local_1c;
  
  if (((int)param_2 >> 0x14 & 0xfU) != 1) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar1 = (int)param_2 >> 0x10 & 0xf;
  uVar2 = (int)param_2 >> 0xc & 0xf;
  if ((uVar2 != 0) && (uVar2 != 1)) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_1c = param_2 & 0xfff;
  if (uVar2 == 1) {
    local_1c = **(uint **)(param_1 + ((long)((int)local_1c >> 8) + 2) * 8);
  }
  **(int **)(param_1 + ((long)(int)uVar1 + 2) * 8) =
       **(int **)(param_1 + ((long)(int)uVar1 + 2) * 8) - local_1c;
  return;
}

void FUN_001015bd(long param_1,uint param_2)

{
  uint uVar1;
  uint local_1c;
  
  if (((int)param_2 >> 0x14 & 0xfU) != 1) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar1 = (int)param_2 >> 0xc & 0xf;
  if ((uVar1 != 0) && (uVar1 != 1)) {
    perror("Invalid value.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_1c = param_2 & 0xfff;
  if (uVar1 == 1) {
    local_1c = **(uint **)(param_1 + ((long)((int)local_1c >> 8) + 2) * 8);
  }
  if (local_1c == **(uint **)(param_1 + ((long)(int)((int)param_2 >> 0x10 & 0xf) + 2) * 8)) {
    FUN_001012a9(param_1,1);
  }
  else {
    FUN_001012a9(param_1,0);
  }
  return;
}

void FUN_001015a1(int *param_1)

{
                    /* WARNING: Subroutine does not return */
  exit(*param_1);
}