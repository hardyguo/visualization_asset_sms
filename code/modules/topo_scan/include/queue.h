#ifndef _PROXY_QUEUE_H
#define _PROXY_QUEUE_H

typedef struct msg_node{
    void *data;						/* 值域 */
    struct msg_node *next;			/* 链接指针 */
}msg_node_t;

typedef struct msg_queue{
    struct msg_node *front;			/* 队首指针 */
    struct msg_node *rear;			/* 队尾指针 */
}msg_queue_t;

void queue_init(struct msg_queue *);
void en_queue(struct msg_queue *, void *);
void *out_queue(struct msg_queue *);

#endif /*_PROXY_QUEUE_H*/
