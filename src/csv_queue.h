#pragma once
#include <stddef.h>

struct csv_node {
    char *string;
    size_t length;
    struct csv_node *next;
};
struct csv_node *csv_queue_front;
struct csv_node *csv_queue_back;

/**
 * \brief Add a pointer to a CSV string to the queue
 *
 * \param csv  Pointer to a CSV string
 */
void csv_enqueue(char *csv_string, size_t csv_length);

/**
 * \brief Returns the first CSV node and removes it from the queue
 *
 * \return    Pointer to the CSV string
 */
struct csv_node *csv_queue_pop();