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
 * Information about ippairdports.
 */

#include "suricata-common.h"
#include "conf.h"

#include "util-debug.h"
#include "ippairdport.h"
#include "ippairdport-storage.h"

#include "util-random.h"
#include "util-misc.h"
#include "util-byte.h"
#include "util-validate.h"

#include "ippairdport-queue.h"

#include "detect-tag.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"

#include "util-hash-lookup3.h"

static IPPairDPort *IPPairDPortGetUsedIPPairDPort(void);

/** ippairdport hash table */
IPPairDPortHashRow *ippairdport_hash;
/** queue with spare ippairdports */
static IPPairDPortQueue ippairdport_spare_q;
IPPairDPortConfig ippairdport_config;
SC_ATOMIC_DECLARE(uint64_t, ippairdport_memuse);
SC_ATOMIC_DECLARE(uint32_t, ippairdport_counter);
SC_ATOMIC_DECLARE(uint32_t, ippairdport_prune_idx);

/** size of the ippairdport object. Maybe updated in IPPairDPortInitConfig to include
 *  the storage APIs additions. */
static uint16_t g_ippairdport_size = sizeof(IPPairDPort);

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int IPPairDPortSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(ippairdport_memuse) < size) {
        SC_ATOMIC_SET(ippairdport_config.memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \retval memcap value
 */
uint64_t IPPairDPortGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(ippairdport_config.memcap);
    return memcapcopy;
}

/**
 *  \brief Return memuse value
 *
 *  \retval memuse value
 */
uint64_t IPPairDPortGetMemuse(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(ippairdport_memuse);
    return memusecopy;
}

uint32_t IPPairDPortSpareQueueGetSize(void)
{
    return IPPairDPortQueueLen(&ippairdport_spare_q);
}

void IPPairDPortMoveToSpare(IPPairDPort *h)
{
    IPPairDPortEnqueue(&ippairdport_spare_q, h);
    (void)SC_ATOMIC_SUB(ippairdport_counter, 1);
}

IPPairDPort *IPPairDPortAlloc(void)
{
    if (!(IPPAIRDPORT_CHECK_MEMCAP(g_ippairdport_size))) {
        return NULL;
    }

    (void)SC_ATOMIC_ADD(ippairdport_memuse, g_ippairdport_size);

    IPPairDPort *h = SCMalloc(g_ippairdport_size);
    if (unlikely(h == NULL))
        goto error;

    memset(h, 0x00, g_ippairdport_size);

    SCMutexInit(&h->m, NULL);
    SC_ATOMIC_INIT(h->use_cnt);
    return h;

error:
    return NULL;
}

void IPPairDPortFree(IPPairDPort *h)
{
    if (h != NULL) {
        IPPairDPortClearMemory(h);
        SCMutexDestroy(&h->m);
        SCFree(h);
        (void)SC_ATOMIC_SUB(ippairdport_memuse, g_ippairdport_size);
    }
}

static IPPairDPort *IPPairDPortNew(Address *a, Address *b, uint16_t *c)
{
    IPPairDPort *p = IPPairDPortAlloc();
    if (p == NULL)
        goto error;

    /* copy addresses */
    COPY_ADDRESS(a, &p->a[0]);
    COPY_ADDRESS(b, &p->a[1]);

    /* copy destination port*/
    COPY_PORT(c, &p->dp);

    return p;

error:
    return NULL;
}

void IPPairDPortClearMemory(IPPairDPort *h)
{
    if (IPPairDPortStorageSize() > 0)
        IPPairDPortFreeStorage(h);
}

#define IPPAIRDPORT_DEFAULT_HASHSIZE 4096
#define IPPAIRDPORT_DEFAULT_MEMCAP   16777216
#define IPPAIRDPORT_DEFAULT_PREALLOC 1000

/** \brief initialize the configuration
 *  \warning Not thread safe */
void IPPairDPortInitConfig(bool quiet)
{
    SCLogDebug("initializing ippairdport engine...");
    if (IPPairDPortStorageSize() > 0) {
        DEBUG_VALIDATE_BUG_ON(sizeof(IPPairDPort) + IPPairDPortStorageSize() > UINT16_MAX);
        g_ippairdport_size = (uint16_t)(sizeof(IPPairDPort) + IPPairDPortStorageSize());
    }

    memset(&ippairdport_config, 0, sizeof(ippairdport_config));
    // SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(ippairdport_counter);
    SC_ATOMIC_INIT(ippairdport_memuse);
    SC_ATOMIC_INIT(ippairdport_prune_idx);
    SC_ATOMIC_INIT(ippairdport_config.memcap);
    IPPairDPortQueueInit(&ippairdport_spare_q);

    /* set defaults */
    ippairdport_config.hash_rand = (uint32_t)RandomGet();
    ippairdport_config.hash_size = IPPAIRDPORT_DEFAULT_HASHSIZE;
    ippairdport_config.prealloc = IPPAIRDPORT_DEFAULT_PREALLOC;
    SC_ATOMIC_SET(ippairdport_config.memcap, IPPAIRDPORT_DEFAULT_MEMCAP);

    /* Check if we have memcap and hash_size defined at config */
    const char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    uint64_t ippairdport_memcap;
    if ((ConfGet("ippairdport.memcap", &conf_val)) == 1) {
        if (ParseSizeStringU64(conf_val, &ippairdport_memcap) < 0) {
            SCLogError("Error parsing ippairdport.memcap "
                       "from conf file - %s.  Killing engine",
                    conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(ippairdport_config.memcap, ippairdport_memcap);
        }
    }
    if ((ConfGet("ippairdport.hash-size", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val), conf_val) > 0) {
            ippairdport_config.hash_size = configval;
        }
    }

    if ((ConfGet("ippairdport.prealloc", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val), conf_val) > 0) {
            ippairdport_config.prealloc = configval;
        } else {
            WarnInvalidConfEntry("ippairdport.prealloc", "%" PRIu32, ippairdport_config.prealloc);
        }
    }
    SCLogDebug("IPPairDPort config from suricata.yaml: memcap: %" PRIu64 ", hash-size: "
               "%" PRIu32 ", prealloc: %" PRIu32,
            SC_ATOMIC_GET(ippairdport_config.memcap), ippairdport_config.hash_size,
            ippairdport_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = ippairdport_config.hash_size * sizeof(IPPairDPortHashRow);
    if (!(IPPAIRDPORT_CHECK_MEMCAP(hash_size))) {
        SCLogError("allocating ippairdport hash failed: "
                   "max ippairdport memcap is smaller than projected hash size. "
                   "Memcap: %" PRIu64 ", Hash table size %" PRIu64 ". Calculate "
                   "total hash size by multiplying \"ippairdport.hash-size\" with %" PRIuMAX ", "
                   "which is the hash bucket size.",
                SC_ATOMIC_GET(ippairdport_config.memcap), hash_size,
                (uintmax_t)sizeof(IPPairDPortHashRow));
        exit(EXIT_FAILURE);
    }
    ippairdport_hash =
            SCMallocAligned(ippairdport_config.hash_size * sizeof(IPPairDPortHashRow), CLS);
    if (unlikely(ippairdport_hash == NULL)) {
        FatalError("Fatal error encountered in IPPairDPortInitConfig. Exiting...");
    }
    memset(ippairdport_hash, 0, ippairdport_config.hash_size * sizeof(IPPairDPortHashRow));

    uint32_t i = 0;
    for (i = 0; i < ippairdport_config.hash_size; i++) {
        HRLOCK_INIT(&ippairdport_hash[i]);
    }
    (void)SC_ATOMIC_ADD(
            ippairdport_memuse, (ippairdport_config.hash_size * sizeof(IPPairDPortHashRow)));

    if (!quiet) {
        SCLogConfig("allocated %" PRIu64 " bytes of memory for the ippairdport hash... "
                    "%" PRIu32 " buckets of size %" PRIuMAX "",
                SC_ATOMIC_GET(ippairdport_memuse), ippairdport_config.hash_size,
                (uintmax_t)sizeof(IPPairDPortHashRow));
    }

    /* pre allocate ippairdports */
    for (i = 0; i < ippairdport_config.prealloc; i++) {
        if (!(IPPAIRDPORT_CHECK_MEMCAP(g_ippairdport_size))) {
            SCLogError("preallocating ippairdports failed: "
                       "max ippairdport memcap reached. Memcap %" PRIu64 ", "
                       "Memuse %" PRIu64 ".",
                    SC_ATOMIC_GET(ippairdport_config.memcap),
                    ((uint64_t)SC_ATOMIC_GET(ippairdport_memuse) + g_ippairdport_size));
            exit(EXIT_FAILURE);
        }

        IPPairDPort *h = IPPairDPortAlloc();
        if (h == NULL) {
            SCLogError("preallocating ippairdport failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        IPPairDPortEnqueue(&ippairdport_spare_q, h);
    }

    if (!quiet) {
        SCLogConfig("preallocated %" PRIu32 " ippairdports of size %" PRIu16 "",
                ippairdport_spare_q.len, g_ippairdport_size);
        SCLogConfig("ippairdport memory usage: %" PRIu64 " bytes, maximum: %" PRIu64,
                SC_ATOMIC_GET(ippairdport_memuse), SC_ATOMIC_GET(ippairdport_config.memcap));
    }

    return;
}

/** \brief print some ippairdport stats
 *  \warning Not thread safe */
void IPPairDPortPrintStats(void)
{
#ifdef IPPAIRDPORTBITS_STATS
    SCLogPerf("ippairdportbits added: %" PRIu32 ", removed: %" PRIu32 ", max memory usage: %" PRIu32
              "",
            ippairdportbits_added, ippairdportbits_removed, ippairdportbits_memuse_max);
#endif /* IPPAIRDPORTBITS_STATS */
    SCLogPerf("ippairdport memory usage: %" PRIu64 " bytes, maximum: %" PRIu64,
            SC_ATOMIC_GET(ippairdport_memuse), SC_ATOMIC_GET(ippairdport_config.memcap));
    return;
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void IPPairDPortShutdown(void)
{
    IPPairDPort *h;
    uint32_t u;

    IPPairDPortPrintStats();

    /* free spare queue */
    while ((h = IPPairDPortDequeue(&ippairdport_spare_q))) {
        BUG_ON(SC_ATOMIC_GET(h->use_cnt) > 0);
        IPPairDPortFree(h);
    }

    /* clear and free the hash */
    if (ippairdport_hash != NULL) {
        for (u = 0; u < ippairdport_config.hash_size; u++) {
            h = ippairdport_hash[u].head;
            while (h) {
                IPPairDPort *n = h->hnext;
                IPPairDPortFree(h);
                h = n;
            }

            HRLOCK_DESTROY(&ippairdport_hash[u]);
        }
        SCFreeAligned(ippairdport_hash);
        ippairdport_hash = NULL;
    }
    (void)SC_ATOMIC_SUB(
            ippairdport_memuse, ippairdport_config.hash_size * sizeof(IPPairDPortHashRow));
    IPPairDPortQueueDestroy(&ippairdport_spare_q);
    return;
}

/** \brief Cleanup the ippairdport engine
 *
 * Cleanup the ippairdport engine from tag and threshold.
 *
 */
void IPPairDPortCleanup(void)
{
    IPPairDPort *h;
    uint32_t u;

    if (ippairdport_hash != NULL) {
        for (u = 0; u < ippairdport_config.hash_size; u++) {
            h = ippairdport_hash[u].head;
            IPPairDPortHashRow *hb = &ippairdport_hash[u];
            HRLOCK_LOCK(hb);
            while (h) {
                if ((SC_ATOMIC_GET(h->use_cnt) > 0)) {
                    /* iprep is attached to ippairdport only clear local storage */
                    IPPairDPortFreeStorage(h);
                    h = h->hnext;
                } else {
                    IPPairDPort *n = h->hnext;
                    /* remove from the hash */
                    if (h->hprev != NULL)
                        h->hprev->hnext = h->hnext;
                    if (h->hnext != NULL)
                        h->hnext->hprev = h->hprev;
                    if (hb->head == h)
                        hb->head = h->hnext;
                    if (hb->tail == h)
                        hb->tail = h->hprev;
                    h->hnext = NULL;
                    h->hprev = NULL;
                    IPPairDPortClearMemory(h);
                    IPPairDPortMoveToSpare(h);
                    h = n;
                }
            }
            HRLOCK_UNLOCK(hb);
        }
    }

    return;
}

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the FlowHashKey6 struct, without all
 *        the SCNtohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 * Copied from FlowHashRawAddressIPv6GtU32
 */
static inline int IPPairDPortHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source address
 */
static uint32_t IPPairDPortGetKey(Address *a, Address *b, uint32_t *c)
{
    uint32_t key;

    if (a->family == AF_INET) {
        uint32_t triple[3] = { MIN(a->addr_data32[0], b->addr_data32[0]),
            MAX(a->addr_data32[0], b->addr_data32[0]), *c };
        uint32_t hash = hashword(triple, 3, ippairdport_config.hash_rand);
        key = hash % ippairdport_config.hash_size;
    } else if (a->family == AF_INET6) {
        uint32_t triple[9];
        if (IPPairDPortHashRawAddressIPv6GtU32(&a->addr_data32[0], &b->addr_data32[0])) {
            triple[0] = b->addr_data32[0];
            triple[1] = b->addr_data32[1];
            triple[2] = b->addr_data32[2];
            triple[3] = b->addr_data32[3];
            triple[4] = a->addr_data32[0];
            triple[5] = a->addr_data32[1];
            triple[6] = a->addr_data32[2];
            triple[7] = a->addr_data32[3];
        } else {
            triple[0] = a->addr_data32[0];
            triple[1] = a->addr_data32[1];
            triple[2] = a->addr_data32[2];
            triple[3] = a->addr_data32[3];
            triple[4] = b->addr_data32[0];
            triple[5] = b->addr_data32[1];
            triple[6] = b->addr_data32[2];
            triple[7] = b->addr_data32[3];
        }
        triple[8] = *c;
        uint32_t hash = hashword(triple, 9, ippairdport_config.hash_rand);
        key = hash % ippairdport_config.hash_size;
    } else
        key = 0;

    return key;
}

/* Since two or more ippairdports can have the same hash key, we need to compare
 * the ippairdport with the current addresses. */
static inline int IPPairDPortCompare(IPPairDPort *p, Address *a, Address *b, uint16_t *c)
{
    /* compare in both directions */
    if ((CMP_ADDR(&p->a[0], a) && CMP_ADDR(&p->a[1], b) && CMP_PORT(&p->dp, c)) ||
            (CMP_ADDR(&p->a[0], b) && CMP_ADDR(&p->a[1], a) && CMP_PORT(&p->dp, c)))
        return 1;
    return 0;
}

/**
 *  \brief Get a new ippairdport
 *
 *  Get a new ippairdport. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \retval h *LOCKED* ippairdport on succes, NULL on error.
 */
static IPPairDPort *IPPairDPortGetNew(Address *a, Address *b, uint16_t *c)
{
    IPPairDPort *h = NULL;

    /* get a ippairdport from the spare queue */
    h = IPPairDPortDequeue(&ippairdport_spare_q);
    if (h == NULL) {
        /* If we reached the max memcap, we get a used ippairdport */
        if (!(IPPAIRDPORT_CHECK_MEMCAP(g_ippairdport_size))) {
            /* declare state of emergency */
            // if (!(SC_ATOMIC_GET(ippairdport_flags) & IPPAIRDPORT_EMERGENCY)) {
            //     SC_ATOMIC_OR(ippairdport_flags, IPPAIRDPORT_EMERGENCY);

            /* under high load, waking up the flow mgr each time leads
             * to high cpu usage. Flows are not timed out much faster if
             * we check a 1000 times a second. */
            //    FlowWakeupFlowManagerThread();
            //}

            h = IPPairDPortGetUsedIPPairDPort();
            if (h == NULL) {
                return NULL;
            }

            /* freed a ippairdport, but it's unlocked */
        } else {
            /* now see if we can alloc a new ippairdport */
            h = IPPairDPortNew(a, b, c);
            if (h == NULL) {
                return NULL;
            }

            /* ippairdport is initialized but *unlocked* */
        }
    } else {
        /* ippairdport has been recycled before it went into the spare queue */

        /* ippairdport is initialized (recycled) but *unlocked* */
    }

    (void)SC_ATOMIC_ADD(ippairdport_counter, 1);
    SCMutexLock(&h->m);
    return h;
}

static void IPPairDPortInit(IPPairDPort *h, Address *a, Address *b, uint16_t *c)
{
    COPY_ADDRESS(a, &h->a[0]);
    COPY_ADDRESS(b, &h->a[1]);
    COPY_PORT(c, &h->dp);
    (void)IPPairDPortIncrUsecnt(h);
}

void IPPairDPortRelease(IPPairDPort *h)
{
    (void)IPPairDPortDecrUsecnt(h);
    SCMutexUnlock(&h->m);
}

void IPPairDPortLock(IPPairDPort *h)
{
    SCMutexLock(&h->m);
}

void IPPairDPortUnlock(IPPairDPort *h)
{
    SCMutexUnlock(&h->m);
}

/* IPPairDPortGetIPPairDPortFromHash
 *
 * Hash retrieval function for ippairdports. Looks up the hash bucket containing the
 * ippairdport pointer. Then compares the packet with the found ippairdport to see if it is
 * the ippairdport we need. If it isn't, walk the list until the right ippairdport is found.
 *
 * returns a *LOCKED* ippairdport or NULL
 */
IPPairDPort *IPPairDPortGetIPPairDPortFromHash(Address *a, Address *b, uint16_t *c)
{
    IPPairDPort *h = NULL;

    /* get the key to our bucket */
    uint32_t key = IPPairDPortGetKey(a, b, c);
    /* get our hash bucket and lock it */
    IPPairDPortHashRow *hb = &ippairdport_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a ippairdport */
    if (hb->head == NULL) {
        h = IPPairDPortGetNew(a, b, c);
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* ippairdport is locked */
        hb->head = h;
        hb->tail = h;

        /* got one, now lock, initialize and return */
        IPPairDPortInit(h, a, b, c);

        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a ippairdport in the bucket. Let's find out if it is our ippairdport */
    h = hb->head;

    /* see if this is the ippairdport we are looking for */
    if (IPPairDPortCompare(h, a, b, c) == 0) {
        IPPairDPort *ph = NULL; /* previous ippairdport */

        while (h) {
            ph = h;
            h = h->hnext;

            if (h == NULL) {
                h = ph->hnext = IPPairDPortGetNew(a, b, c);
                if (h == NULL) {
                    HRLOCK_UNLOCK(hb);
                    return NULL;
                }
                hb->tail = h;

                /* ippairdport is locked */

                h->hprev = ph;

                /* initialize and return */
                IPPairDPortInit(h, a, b, c);

                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (IPPairDPortCompare(h, a, b, c) != 0) {
                /* we found our ippairdport, lets put it on top of the
                 * hash list -- this rewards active ippairdports */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our ippairdport, lock & return */
                SCMutexLock(&h->m);
                (void)IPPairDPortIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void)IPPairDPortIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \brief look up a ippairdport in the hash
 *
 *  \param a address to look up
 *
 *  \retval h *LOCKED* ippairdport or NULL
 */
IPPairDPort *IPPairDPortLookupIPPairDPortFromHash(Address *a, Address *b, uint16_t *c)
{
    IPPairDPort *h = NULL;

    /* get the key to our bucket */
    uint32_t key = IPPairDPortGetKey(a, b, c);
    /* get our hash bucket and lock it */
    IPPairDPortHashRow *hb = &ippairdport_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a ippairdport */
    if (hb->head == NULL) {
        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a ippairdport in the bucket. Let's find out if it is our ippairdport */
    h = hb->head;

    /* see if this is the ippairdport we are looking for */
    if (IPPairDPortCompare(h, a, b, c) == 0) {
        while (h) {
            h = h->hnext;

            if (h == NULL) {
                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (IPPairDPortCompare(h, a, b, c) != 0) {
                /* we found our ippairdport, lets put it on top of the
                 * hash list -- this rewards active ippairdports */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our ippairdport, lock & return */
                SCMutexLock(&h->m);
                (void)IPPairDPortIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void)IPPairDPortIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \internal
 *  \brief Get a ippairdport from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a ippairdport can be freed. "ippairdport_prune_idx" atomic int makes
 *  sure we don't start at the top each time since that would clear the top of
 *  the hash leading to longer and longer search times under high pressure (observed).
 *
 *  \retval h ippairdport or NULL
 */
static IPPairDPort *IPPairDPortGetUsedIPPairDPort(void)
{
    uint32_t idx = SC_ATOMIC_GET(ippairdport_prune_idx) % ippairdport_config.hash_size;
    uint32_t cnt = ippairdport_config.hash_size;

    while (cnt--) {
        if (++idx >= ippairdport_config.hash_size)
            idx = 0;

        IPPairDPortHashRow *hb = &ippairdport_hash[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        IPPairDPort *h = hb->tail;
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        if (SCMutexTrylock(&h->m) != 0) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        /** never prune a ippairdport that is used by a packets
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(h->use_cnt) > 0) {
            HRLOCK_UNLOCK(hb);
            SCMutexUnlock(&h->m);
            continue;
        }

        /* remove from the hash */
        if (h->hprev != NULL)
            h->hprev->hnext = h->hnext;
        if (h->hnext != NULL)
            h->hnext->hprev = h->hprev;
        if (hb->head == h)
            hb->head = h->hnext;
        if (hb->tail == h)
            hb->tail = h->hprev;

        h->hnext = NULL;
        h->hprev = NULL;
        HRLOCK_UNLOCK(hb);

        IPPairDPortClearMemory(h);

        SCMutexUnlock(&h->m);

        (void)SC_ATOMIC_ADD(ippairdport_prune_idx, (ippairdport_config.hash_size - cnt));
        return h;
    }

    return NULL;
}

void IPPairDPortRegisterUnittests(void)
{
    RegisterIPPairDPortStorageTests();
}
