/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * IPPairDPort queue handler functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "ippairdport-queue.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"

IPPairDPortQueue *IPPairDPortQueueInit (IPPairDPortQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(IPPairDPortQueue));
        HQLOCK_INIT(q);
    }
    return q;
}

IPPairDPortQueue *IPPairDPortQueueNew(void)
{
    IPPairDPortQueue *q = (IPPairDPortQueue *)SCMalloc(sizeof(IPPairDPortQueue));
    if (q == NULL) {
        SCLogError("Fatal error encountered in IPPairDPortQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = IPPairDPortQueueInit(q);
    return q;
}

/**
 *  \brief Destroy a ippairdport queue
 *
 *  \param q the ippairdport queue to destroy
 */
void IPPairDPortQueueDestroy (IPPairDPortQueue *q)
{
    HQLOCK_DESTROY(q);
}

/**
 *  \brief add a ippairdport to a queue
 *
 *  \param q queue
 *  \param h ippairdport
 */
void IPPairDPortEnqueue (IPPairDPortQueue *q, IPPairDPort *h)
{
#ifdef DEBUG
    BUG_ON(q == NULL || h == NULL);
#endif

    HQLOCK_LOCK(q);

    /* more ippairdports in queue */
    if (q->top != NULL) {
        h->lnext = q->top;
        q->top->lprev = h;
        q->top = h;
    /* only ippairdport */
    } else {
        q->top = h;
        q->bot = h;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    HQLOCK_UNLOCK(q);
}

/**
 *  \brief remove a ippairdport from the queue
 *
 *  \param q queue
 *
 *  \retval h ippairdport or NULL if empty list.
 */
IPPairDPort *IPPairDPortDequeue (IPPairDPortQueue *q)
{
    HQLOCK_LOCK(q);

    IPPairDPort *h = q->bot;
    if (h == NULL) {
        HQLOCK_UNLOCK(q);
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->lprev != NULL) {
        q->bot = q->bot->lprev;
        q->bot->lnext = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;

    h->lnext = NULL;
    h->lprev = NULL;

    HQLOCK_UNLOCK(q);
    return h;
}

uint32_t IPPairDPortQueueLen(IPPairDPortQueue *q)
{
    uint32_t len;
    HQLOCK_LOCK(q);
    len = q->len;
    HQLOCK_UNLOCK(q);
    return len;
}
