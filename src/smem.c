#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <internal/smem.h>

struct __en_sm_context {
	void* ptr;
	size_t size;
};

sm_context _en_sm_init()
{
	sm_context s = (sm_context)malloc(sizeof(struct __en_sm_context));
	memset(s, 0, sizeof(struct __en_sm_context));
	return s;
}

void _en_sm_free(sm_context s)
{
	if(s->ptr!=NULL)
	{
#ifdef SM_ZERO_MEMORY
		memset(s->ptr,0,s->size);
#endif
		free(s->ptr);
		s->ptr=NULL;
	}
	s->size=0;
	free(s);
}

void* _en_smalloc(sm_context s, size_t size)
{
	if(s->ptr==NULL)
	{
		s->size=size;
		s->ptr=malloc(size);
#ifdef SM_ZERO_MEMORY
		memset(s->ptr,0,size);
#endif
		return s->ptr;
	}
	else {
		if(s->size==size) {
#ifdef SM_ZERO_MEMORY
			memset(s->ptr,0,s->size);
#endif
			return s->ptr;
		}
		else {
			free(s->ptr);
			s->size=0;
			s->ptr = NULL;
			return _en_smalloc(s, size);
		}
	}
}

int _en_sm_clear(sm_context s)
{
	if(s->ptr!=NULL)
	{
		memset(s->ptr, 0, s->size);
		return 1;
	}
	return 0;
}
