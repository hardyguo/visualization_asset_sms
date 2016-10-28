#ifndef _PROXY_QUEUE_H
#define _PROXY_QUEUE_H

typedef struct msg_node{
    void *data;						/* ֵ�� */
    struct msg_node *next;			/* ����ָ�� */
}msg_node_t;

typedef struct msg_queue{
    struct msg_node *front;			/* ����ָ�� */
    struct msg_node *rear;			/* ��βָ�� */
}msg_queue_t;

void queue_init(struct msg_queue *);
void en_queue(struct msg_queue *, void *);
void *out_queue(struct msg_queue *);

#endif /*_PROXY_QUEUE_H*/
