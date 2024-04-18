#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64 sys_setpriority(void){
  int pri;

  argint(0, &pri);
  return proc_set_priority(pri);
}

uint64 sys_getpriority(void){
  return proc_get_priority();
}

uint64 sys_readobject(void){
  int idx;

  argint(0, &idx);
  return read_object(idx);
}

uint64 sys_writeobject(void){
  int idx;
  uint64 value;

  argint(0, &idx);
  argaddr(1, &value);
  return write_object(idx, value);
}

uint64 sys_readacl(void){
  return read_acl();
}

uint64 sys_writeacl(void){
  uint64 value;

  argaddr(0, &value);
  return write_acl(value);
}

uint64 sys_yield(void){
  yield();
  return 0;
}