#include "qlib_sample_flash_handle_stubs.h"
void* W77Q_OpenFlash(const char*);
void  W77Q_CloseFlash(void*);
void* QLIB_SAMPLE_GetFlashHandle(void)            { return W77Q_OpenFlash(NULL); }
void  QLIB_SAMPLE_ReleaseFlashHandle(void* h)     { W77Q_CloseFlash(h); }
