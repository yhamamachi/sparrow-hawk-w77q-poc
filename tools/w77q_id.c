/* read-only smoke test of the raw interface: JEDEC ID (0x9F) and SFDP header */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include "../kmod/w77q_raw.h"
static int x(int fd,uint8_t op,int an,uint32_t a,uint32_t dm,void*b,uint32_t l){
  struct w77q_xfer t={.opcode=op,.addr_nbytes=an,.dir=W77Q_DIR_IN,.dummy_cycles=dm,.addr=a,.len=l,.buf=(uint64_t)(uintptr_t)b};
  return ioctl(fd,W77Q_IOC_XFER,&t);}
int main(void){uint8_t b[16]={0};int fd=open("/dev/w77q0",O_RDWR);if(fd<0){perror("open");return 1;}
 int r=x(fd,0x9f,0,0,0,b,3);printf("9F ret=%d id=%02x %02x %02x\n",r,b[0],b[1],b[2]);
 memset(b,0,16);r=x(fd,0x5a,3,0,8,b,16);printf("5A SFDP ret=%d: ",r);for(int i=0;i<16;i++)printf("%02x ",b[i]);puts("");return 0;}
