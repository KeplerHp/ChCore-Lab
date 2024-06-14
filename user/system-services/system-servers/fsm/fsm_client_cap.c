/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS),
 * Shanghai Jiao Tong University (SJTU) Licensed under the Mulan PSL v2. You can
 * use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 * Mulan PSL v2 for more details.
 */

#include <malloc.h>
#include <string.h>
#include "fsm_client_cap.h"
#include <errno.h>

struct list_head fsm_client_cap_table;

/* Return mount_id */
int fsm_set_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        struct fsm_client_cap_node *traget_node = NULL;
        bool found = false;

        pthread_mutex_lock(&fsm_client_cap_table_lock);

        for_each_in_list (traget_node,
                          struct fsm_client_cap_node,
                          node,
                          &fsm_client_cap_table) {
                if (traget_node->client_badge == client_badge) {
                        found = true;
                        break;
                }
        }

        if (found) {
                if (traget_node->cap_num >= 16) {
                        pthread_mutex_unlock(&fsm_client_cap_table_lock);
                        return -1;
                }

                traget_node->cap_table[traget_node->cap_num] = cap;
                traget_node->cap_num++;
                pthread_mutex_unlock(&fsm_client_cap_table_lock);
                return traget_node->cap_num - 1;
        }

        pthread_mutex_unlock(&fsm_client_cap_table_lock);

        traget_node = (struct fsm_client_cap_node *)malloc(
                sizeof(struct fsm_client_cap_node));
        if (traget_node == NULL) {
                return -1;
        }
        traget_node->client_badge = client_badge;
        traget_node->cap_table[0] = cap;
        traget_node->cap_num = 1;

        pthread_mutex_lock(&fsm_client_cap_table_lock);
        list_add(&traget_node->node, &fsm_client_cap_table);
        pthread_mutex_unlock(&fsm_client_cap_table_lock);

        /* Lab 5 TODO End */
        return 0;
}

/* Return mount_id if record exists, otherwise -1 */
int fsm_get_client_cap(badge_t client_badge, cap_t cap)
{
        /* Lab 5 TODO Begin */
        pthread_mutex_lock(&fsm_client_cap_table_lock);

        struct fsm_client_cap_node *traget_node = NULL;
        for_each_in_list (traget_node,
                          struct fsm_client_cap_node,
                          node,
                          &fsm_client_cap_table) {
                if (traget_node->client_badge == client_badge) {
                        for (int i = 0; i < traget_node->cap_num; i++) {
                                if (traget_node->cap_table[i] == cap) {
                                        pthread_mutex_unlock(
                                                &fsm_client_cap_table_lock);
                                        return i;
                                }
                        }
                }
        }

        pthread_mutex_unlock(&fsm_client_cap_table_lock);
        /* Lab 5 TODO End */
        return -1;
}
