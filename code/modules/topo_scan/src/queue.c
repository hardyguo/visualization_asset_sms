/*-------------------------------------------------------------------------
	proxy_queue.c
-------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

extern void _DEBUG_FILE(char *fmt, ...);

/* 1.初始化链队 */
void queue_init(struct msg_queue *hq)
{
    hq->front = hq->rear = NULL;        /* 把队首和队尾指针置空 */
    return;
}

/* 2.向链队中插入一个元素x */
void en_queue(struct msg_queue *hq, void *x)
{
    /* 得到一个由newP指针所指向的新结点 */
    struct msg_node *newP;
    newP = malloc(sizeof(struct msg_node));
    if(newP == NULL)
    {
        _DEBUG_FILE("[%s] malloc error!\n", __func__);
        return;
    }
	memset(newP, 0, sizeof(struct msg_node));
    /* 把x的值赋给新结点的值域，把新结点的指针域置空 */
    newP->data = x;
    newP->next = NULL;
    /* 若链队为空，则新结点即是队首结点又是队尾结点 */
    if(hq->rear == NULL)
    {
        hq->front = hq->rear = newP;
    }
    else      /* 若链队非空，则依次修改队尾结点的指针域和队尾指针，使之指向新的队尾结点 */
    {
        hq->rear = hq->rear->next = newP;        /* 注重赋值顺序哦 */
    }
    return;
}

/* 3.从队列中删除一个元素 */
void *out_queue(struct msg_queue *hq)
{
    struct msg_node *p;
    void *temp;
    /* 若链队为空则停止运行 */
    if(hq->front == NULL)
    {
        //_DEBUG_FILE("[%s] queue is null!\n", __func__);
        return NULL;
    }
    temp = hq->front->data;        /* 暂存队尾元素以便返回 */
    p = hq->front;                /* 暂存队尾指针以便回收队尾结点 */
    hq->front = p->next;        /* 使队首指针指向下一个结点 */
    /* 若删除后链队为空，则需同时使队尾指针为空 */
    if(hq->front == NULL)
    {
        hq->rear = NULL;
    }
    free(p);        /* 回收原队首结点 */
    return temp;    /* 返回被删除的队首元素值 */
}

/* 4.读取队首元素 */
void *peek_queue(struct msg_queue *hq)
{
    /* 若链队为空则停止运行 */
    if(hq->front == NULL)
    {
        _DEBUG_FILE("[%s] queue is null!\n", __func__);
        return NULL;
    }
    return hq->front->data;        /* 返回队首元素 */
}

/* 5.检查链队是否为空，若为空则返回1, 否则返回0 */
int empty_queue(struct msg_queue *hq)
{
    /* 判定队首或队尾任一个指针是否为空即可 */
    if(hq->front == NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* 6.清除链队中的所有元素 */
void clear_queue(struct msg_queue *hq)
{
    struct msg_node *p = hq->front;        /* 队首指针赋给p */
    /* 依次删除队列中的每一个结点，最后使队首指针为空 */
    while(p != NULL)
    {
        hq->front = hq->front->next;
        free(p);
        p = hq->front;
    }    /* 循环结束后队首指针已经为空 */
    hq->rear = NULL;        /* 置队尾指针为空 */
    return;
}

