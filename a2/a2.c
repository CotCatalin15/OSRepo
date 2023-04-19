#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "a2_helper.h"
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>

typedef struct {
    sem_t th2_beg;
    sem_t th4_end;
}Process3Context;

typedef struct 
{
    int id;
    sem_t* semaphore;

    pthread_mutex_t* lock;
    int* numActiveThreads;
    int* t12Active;

    pthread_cond_t* cVar;
    pthread_cond_t* t12EndCVar;
}Process5Context;

typedef struct
{
    sem_t* P4T1_End;
    sem_t* P3T3_End;
}P3_4_GlobalContext;

#define P4T1_END_SEMAPHORE_NAME "P4T1Semname"
#define P3T3_END_SEMAPHORE_NAME "P3T3Semname"

typedef void(*PFN_ChildProcessRoutine)(void*);

pid_t CreateProcess(int customeID, PFN_ChildProcessRoutine Routine, void* Context) 
{
    pid_t id = fork();
    if(id == 0)
    {
        //Child
        info(BEGIN, customeID, 0);
        Routine(Context);
        info(END, customeID, 0);
        exit(0);
    }

    return id;
}

void Process2Routine(void* Context);
    void Process3Routine(void* Context);
        void Process4Routine(void* Context);
            void Process8Routine(void* Context);
        void Process5Routine(void* Context);
            void Process9Routine(void* Context);

void Process6Routine(void* Context);

void Process7Routine(void* Context);


int main()
{
    init();

    info(BEGIN, 1, 0);
    
    sem_t* p3t3_end = sem_open(P3T3_END_SEMAPHORE_NAME, O_CREAT, 0644, 0);
    sem_t* p4t1_end = sem_open(P4T1_END_SEMAPHORE_NAME, O_CREAT, 0644, 0);;

    pid_t pid2 = CreateProcess(2, Process2Routine, NULL);
    pid_t pid6 = CreateProcess(6, Process6Routine, NULL);
    pid_t pid7 = CreateProcess(7, Process7Routine, NULL);

    waitpid(pid2, NULL, 0);
    waitpid(pid6, NULL, 0);
    waitpid(pid7, NULL, 0);

    sem_close(p3t3_end);
    sem_close(p4t1_end);
    
    info(END, 1, 0);
    return 0;
}

void Process2Routine(void* Context)
{
    pid_t pid3 = CreateProcess(3, Process3Routine, NULL);
    waitpid(pid3, NULL, 0);
}

void* Process3GenricThread(void* context)
{
    int id = *((int*)context);
    info(BEGIN, 3, id);
    
    info(END, 3, id);

    return NULL;
}

void* Process3Thread3(void* Context)
{
    P3_4_GlobalContext* globalContext = (P3_4_GlobalContext*)Context;    

    printf("BEGIN P3T3_WAIT\n");
    sem_wait(globalContext->P4T1_End);
    printf("END P3T3_WAIT\n");

    info(BEGIN, 3, 3);
    info(END, 3, 3);

    printf("P3T3 POST\n");
    sem_post(globalContext->P3T3_End);

    return NULL;
}

void* Process3Thread2(void* thcontext)
{
    Process3Context* context = (Process3Context*)thcontext;
    sem_wait(&context->th2_beg);

    info(BEGIN, 3, 2);
    info(END, 3, 2);

    sem_post(&context->th4_end);

    return NULL;
}

void* Process3Thread4(void* thcontext)
{
    Process3Context* context = (Process3Context*)thcontext;
    info(BEGIN, 3, 4);
    sem_post(&context->th2_beg);

    sem_wait(&context->th4_end);
    info(END, 3, 4);

    return NULL;
}

void Process3Routine(void* Context)
{
    pid_t pid4 = CreateProcess(4, Process4Routine, NULL);
    pid_t pid5 = CreateProcess(5, Process5Routine, NULL);

    Process3Context context = {0};
    sem_init(&context.th2_beg, 0, 0);
    sem_init(&context.th2_beg, 0, 0);

    pthread_t threads[5];
    int ids[] = {1, 2, 3, 4, 5};

    P3_4_GlobalContext globalContext = {0};
    globalContext.P3T3_End = sem_open(P3T3_END_SEMAPHORE_NAME, 0);
    globalContext.P4T1_End = sem_open(P4T1_END_SEMAPHORE_NAME, 0);

    for(int i = 1; i <= 5; ++i)
    {
        if(i == 2)
        {
            pthread_create(&threads[i - 1], NULL, Process3Thread2, &context);
        }
        else if(i == 3)
        {
            pthread_create(&threads[i - 1], NULL, Process3Thread3, &globalContext);
        }
        else if(i == 4)
        {
            pthread_create(&threads[i - 1], NULL, Process3Thread4, &context);
        }
        else
        {
            pthread_create(&threads[i - 1], NULL, Process3GenricThread, &ids[i - 1]);
        }
    }

    for(int i = 0; i < 5; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    sem_destroy(&context.th2_beg);
    sem_destroy(&context.th4_end);

    sem_close(globalContext.P3T3_End);
    sem_close(globalContext.P4T1_End);

    waitpid(pid4, NULL, 0);
    waitpid(pid5, NULL, 0);
}

void* Process4Thread(void* Context)
{
    int id = *((int*)Context);
    info(BEGIN, 4, id);
    info(END, 4, id);
    return NULL;
}

void* Process4Thread4(void* Context)
{
    int id = 4;
    P3_4_GlobalContext* globalContext = (P3_4_GlobalContext*)Context;    
    
    printf("BEGIN P4T4_WAIT\n");
    sem_wait(globalContext->P3T3_End);
    printf("END P4T4_WAIT\n");

    info(BEGIN, 4, id);
    info(END, 4, id);

    return NULL;
}

void* Process4Thread1(void* Context)
{
    int id = 1;
    P3_4_GlobalContext* globalContext = (P3_4_GlobalContext*)Context;    

    info(BEGIN, 4, id);
    info(END, 4, id);

    if(id == 1)
    {
        printf("POST P4T1\n");
        sem_post(globalContext->P4T1_End);
    }

    return NULL;
}


void Process4Routine(void* Context)
{
    pid_t pid8 = CreateProcess(8, Process8Routine, NULL);

    int ids[] = {1, 2, 3, 4, 5};
    pthread_t threads[5];

    P3_4_GlobalContext globalContext = {0};
    globalContext.P3T3_End = sem_open(P3T3_END_SEMAPHORE_NAME, 0);
    globalContext.P4T1_End = sem_open(P4T1_END_SEMAPHORE_NAME, 0);

    for(int i = 0; i < 5; ++i)
    {
        if(i == 3)
        {
            pthread_create(&threads[i], NULL, Process4Thread4, &globalContext);
        }
        else if(i == 0)
        {
            pthread_create(&threads[i], NULL, Process4Thread1, &globalContext);
        }
        else
        {
            pthread_create(&threads[i], NULL, Process4Thread, &ids[i]);
        }
    }

    for(int i = 0; i < 5; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    sem_close(globalContext.P3T3_End);
    sem_close(globalContext.P4T1_End);

    waitpid(pid8, NULL, 0);
}

void* Process5ThreadRoutine(void* thcontext)
{
    Process5Context* context = (Process5Context*)thcontext;
    sem_wait(context->semaphore);

    info(BEGIN, 5, context->id);

    /*
    {
        pthread_mutex_lock(context->lock);
        ++(*context->numActiveThreads);

        if(context->id == 12)
        {
            *context->t12Active = 1;
        }
        else if (*context->numActiveThreads == 6 && *context->t12Active == 1)
        {
            pthread_cond_broadcast(context->cVar);
        }
        pthread_mutex_unlock(context->lock);
    }
   
    if(context->id == 12)
    {
        pthread_mutex_lock(context->lock);
        if(*context->numActiveThreads != 6)
        {
            pthread_cond_wait(context->cVar, context->lock);
        }
        *context->t12Active = 0;
        info(END, 5, context->id);
        --(*context->numActiveThreads);
        pthread_mutex_unlock(context->lock);

        pthread_cond_broadcast(context->t12EndCVar);
    }
    else
    {
        pthread_mutex_lock(context->lock);
        if(*context->t12Active == 1)
        {
            pthread_cond_wait(context->t12EndCVar, context->lock);
        }
        --(*context->numActiveThreads);
        pthread_mutex_unlock(context->lock);
        info(END, 5, context->id);
    }
    */

    info(END, 5, context->id);
    sem_post(context->semaphore);

    return NULL;
}

void Process5Routine(void* Context)
{
    pid_t pid9 = CreateProcess(9, Process9Routine, NULL);

    Process5Context contexts[47];
    pthread_t threads[47];

    sem_t mainSem;
    sem_init(&mainSem, 0, 6);
    
    pthread_mutex_t lock;
    pthread_mutex_init(&lock, NULL);

    pthread_cond_t cVar;
    pthread_cond_init(&cVar, NULL);

    pthread_cond_t t12EndCVar;
    pthread_cond_init(&t12EndCVar, NULL);

    int numActiveThreads = 0;
    int t12Active = 1;
    
    contexts[11].semaphore = &mainSem;
    contexts[11].id = 12;
    contexts[11].lock = &lock;
    contexts[11].cVar = &cVar;
    contexts[11].t12EndCVar = &t12EndCVar;
    contexts[11].numActiveThreads = &numActiveThreads;
    contexts[11].t12Active = &t12Active;

    pthread_create(&threads[11], NULL, Process5ThreadRoutine, &contexts[11]);

    for(int i = 0; i < 47; ++i)
    {
        if(i == 11)
            continue;

        contexts[i].semaphore = &mainSem;
        contexts[i].id = i + 1;
        contexts[i].lock = &lock;
        contexts[i].cVar = &cVar;
        contexts[i].t12EndCVar = &t12EndCVar;
        contexts[i].numActiveThreads = &numActiveThreads;
        contexts[i].t12Active = &t12Active;

        pthread_create(&threads[i], NULL, Process5ThreadRoutine, &contexts[i]);
    }

    for(int i = 0; i < 47; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&cVar);
    pthread_cond_destroy(&t12EndCVar);
    sem_destroy(&mainSem);

    waitpid(pid9, NULL, 0);
}

void Process6Routine(void* Context)
{
}

void Process7Routine(void* Context)
{
}

void Process8Routine(void* Context)
{
}

void Process9Routine(void* Context)
{

}