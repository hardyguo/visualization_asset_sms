/*-------------------------------------------------------------------------
	proxy_queue.c
-------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

extern void _DEBUG_FILE(char *fmt, ...);

/* 1.��ʼ������ */
void queue_init(struct msg_queue *hq)
{
    hq->front = hq->rear = NULL;        /* �Ѷ��׺Ͷ�βָ���ÿ� */
    return;
}

/* 2.�������в���һ��Ԫ��x */
void en_queue(struct msg_queue *hq, void *x)
{
    /* �õ�һ����newPָ����ָ����½�� */
    struct msg_node *newP;
    newP = malloc(sizeof(struct msg_node));
    if(newP == NULL)
    {
        _DEBUG_FILE("[%s] malloc error!\n", __func__);
        return;
    }
	memset(newP, 0, sizeof(struct msg_node));
    /* ��x��ֵ�����½���ֵ�򣬰��½���ָ�����ÿ� */
    newP->data = x;
    newP->next = NULL;
    /* ������Ϊ�գ����½�㼴�Ƕ��׽�����Ƕ�β��� */
    if(hq->rear == NULL)
    {
        hq->front = hq->rear = newP;
    }
    else      /* �����ӷǿգ��������޸Ķ�β����ָ����Ͷ�βָ�룬ʹָ֮���µĶ�β��� */
    {
        hq->rear = hq->rear->next = newP;        /* ע�ظ�ֵ˳��Ŷ */
    }
    return;
}

/* 3.�Ӷ�����ɾ��һ��Ԫ�� */
void *out_queue(struct msg_queue *hq)
{
    struct msg_node *p;
    void *temp;
    /* ������Ϊ����ֹͣ���� */
    if(hq->front == NULL)
    {
        //_DEBUG_FILE("[%s] queue is null!\n", __func__);
        return NULL;
    }
    temp = hq->front->data;        /* �ݴ��βԪ���Ա㷵�� */
    p = hq->front;                /* �ݴ��βָ���Ա���ն�β��� */
    hq->front = p->next;        /* ʹ����ָ��ָ����һ����� */
    /* ��ɾ��������Ϊ�գ�����ͬʱʹ��βָ��Ϊ�� */
    if(hq->front == NULL)
    {
        hq->rear = NULL;
    }
    free(p);        /* ����ԭ���׽�� */
    return temp;    /* ���ر�ɾ���Ķ���Ԫ��ֵ */
}

/* 4.��ȡ����Ԫ�� */
void *peek_queue(struct msg_queue *hq)
{
    /* ������Ϊ����ֹͣ���� */
    if(hq->front == NULL)
    {
        _DEBUG_FILE("[%s] queue is null!\n", __func__);
        return NULL;
    }
    return hq->front->data;        /* ���ض���Ԫ�� */
}

/* 5.��������Ƿ�Ϊ�գ���Ϊ���򷵻�1, ���򷵻�0 */
int empty_queue(struct msg_queue *hq)
{
    /* �ж����׻��β��һ��ָ���Ƿ�Ϊ�ռ��� */
    if(hq->front == NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* 6.��������е�����Ԫ�� */
void clear_queue(struct msg_queue *hq)
{
    struct msg_node *p = hq->front;        /* ����ָ�븳��p */
    /* ����ɾ�������е�ÿһ����㣬���ʹ����ָ��Ϊ�� */
    while(p != NULL)
    {
        hq->front = hq->front->next;
        free(p);
        p = hq->front;
    }    /* ѭ�����������ָ���Ѿ�Ϊ�� */
    hq->rear = NULL;        /* �ö�βָ��Ϊ�� */
    return;
}

