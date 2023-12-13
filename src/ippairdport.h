/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 */

#ifndef __IPPAIRDPORT_H__
#define __IPPAIRDPORT_H__

#include "decode.h"
#include "util-storage.h"

/** Spinlocks or Mutex for the flow buckets. */
//#define HRLOCK_SPIN
#define HRLOCK_MUTEX

#ifdef HRLOCK_SPIN
    #ifdef HRLOCK_MUTEX
        #error Cannot enable both HRLOCK_SPIN and HRLOCK_MUTEX
    #endif
#endif

#ifdef HRLOCK_SPIN
    #define HRLOCK_TYPE SCSpinlock
    #define HRLOCK_INIT(fb) SCSpinInit(&(fb)->lock, 0)
    #define HRLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCSpinLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->lock)
#elif defined HRLOCK_MUTEX
    #define HRLOCK_TYPE SCMutex
    #define HRLOCK_INIT(fb) SCMutexInit(&(fb)->lock, NULL)
    #define HRLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCMutexLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCMutexTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->lock)
#else
    #error Enable HRLOCK_SPIN or HRLOCK_MUTEX
#endif

typedef struct IPPairDPort_ {
    /** ippairdport mutex */
    SCMutex m;

    /** ippairdport addresses -- ipv4 or ipv6 */
    Address a[2];
    uint16_t dp;     // Destination port


    /** use cnt, reference counter */
    SC_ATOMIC_DECLARE(unsigned int, use_cnt);

    /** storage api handle */
    Storage *storage;

    /** hash pointers, protected by hash row mutex/spin */
    struct IPPairDPort_ *hnext;
    struct IPPairDPort_ *hprev;

    /** list pointers, protected by ippairdport-queue mutex/spin */
    struct IPPairDPort_ *lnext;
    struct IPPairDPort_ *lprev;
} IPPairDPort;

typedef struct IPPairDPortHashRow_ {
    HRLOCK_TYPE lock;
    IPPairDPort *head;
    IPPairDPort *tail;
} __attribute__((aligned(CLS))) IPPairDPortHashRow;

/** ippairdport hash table */
extern IPPairDPortHashRow *ippairdport_hash;

#define IPPAIRDPORT_QUIET      1

typedef struct IPPairDPortConfig_ {
    SC_ATOMIC_DECLARE(uint64_t, memcap);
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t prealloc;
} IPPairDPortConfig;

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define IPPAIRDPORT_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(ippairdport_memuse) + (uint64_t)(size)) <= SC_ATOMIC_GET(ippairdport_config.memcap)))

#define IPPairDPortIncrUsecnt(h) \
    (void)SC_ATOMIC_ADD((h)->use_cnt, 1)
#define IPPairDPortDecrUsecnt(h) \
    (void)SC_ATOMIC_SUB((h)->use_cnt, 1)

extern IPPairDPortConfig ippairdport_config;
SC_ATOMIC_EXTERN(uint64_t,ippairdport_memuse);
SC_ATOMIC_EXTERN(uint32_t,ippairdport_counter);
SC_ATOMIC_EXTERN(uint32_t,ippairdport_prune_idx);

void IPPairDPortInitConfig(bool quiet);
void IPPairDPortShutdown(void);
void IPPairDPortCleanup(void);

IPPairDPort *IPPairDPortLookupIPPairDPortFromHash (Address *, Address *, u_int16_t);
IPPairDPort *IPPairDPortGetIPPairDPortFromHash (Address *, Address *, u_int16_t);
void IPPairDPortRelease(IPPairDPort *);
void IPPairDPortLock(IPPairDPort *);
void IPPairDPortClearMemory(IPPairDPort *);
void IPPairDPortMoveToSpare(IPPairDPort *);
uint32_t IPPairDPortSpareQueueGetSize(void);
void IPPairDPortPrintStats (void);

void IPPairDPortRegisterUnittests(void);

IPPairDPort *IPPairDPortAlloc(void);
void IPPairDPortFree(IPPairDPort *);

void IPPairDPortLock(IPPairDPort *);
void IPPairDPortUnlock(IPPairDPort *);

int IPPairDPortSetMemcap(uint64_t size);
uint64_t IPPairDPortGetMemcap(void);
uint64_t IPPairDPortGetMemuse(void);

#endif /* __IPPAIRDPORT_H__ */
