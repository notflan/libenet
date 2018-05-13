#ifndef _SMEM_H
#define _SMEM_H

#define SM_ZERO_MEMORY

#define sm_context _en_sm_context

typedef struct __en_sm_context *sm_context;

sm_context _en_sm_init();
void _en_sm_free(sm_context s);
void* _en_smalloc(sm_context s, size_t size);
int _en_sm_clear(sm_context s);

#endif /* _SMEM_H */
