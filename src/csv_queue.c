#include "csv_queue.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void csv_enqueue(char *csv_string, size_t csv_length) {
    struct csv_node *new = malloc(sizeof(struct csv_node));
    new->string = csv_string;
    new->length = csv_length;
    new->next = NULL;

    if (csv_queue_front == NULL && csv_queue_back == NULL) {
        // queue is empty
        csv_queue_front = csv_queue_back = new;
        return;
    }
    csv_queue_back->next = new;
    csv_queue_back = new;
}

struct csv_node *csv_queue_pop() {
    if (csv_queue_front == NULL) {
        // queue is empty
        return NULL;
    }

    struct csv_node *node = csv_queue_front;
    csv_queue_front = node->next;
    return node;
}
