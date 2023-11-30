/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * Implements per ippairdport bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 */

#include "suricata-common.h"
#include "threads.h"
#include "ippairdport-bit.h"
#include "ippairdport.h"
#include "detect.h"
#include "util-var.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "ippairdport-storage.h"

static IPPairDPortStorageId g_ippairdport_bit_storage_id = { .id = -1 }; /**< IPPairDPort storage id for bits */

static void XBitFreeAll(void *store)
{
    GenericVar *gv = store;
    GenericVarFree(gv);
}

void IPPairDPortBitInitCtx(void)
{
    g_ippairdport_bit_storage_id = IPPairDPortStorageRegister("bit", sizeof(void *), NULL, XBitFreeAll);
    if (g_ippairdport_bit_storage_id.id == -1) {
        FatalError("Can't initiate ippairdport storage for bits");
    }
}

/* lock before using this */
int IPPairDPortHasBits(IPPairDPort *ippairdport)
{
    if (ippairdport == NULL)
        return 0;
    return IPPairDPortGetStorageById(ippairdport, g_ippairdport_bit_storage_id) ? 1 : 0;
}

/** \retval 1 ippairdport timed out wrt xbits
  * \retval 0 ippairdport still has active (non-expired) xbits */
int IPPairDPortBitsTimedoutCheck(IPPairDPort *h, SCTime_t ts)
{
    GenericVar *gv = IPPairDPortGetStorageById(h, g_ippairdport_bit_storage_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS) {
            XBit *xb = (XBit *)gv;
            if (xb->expire > (uint32_t)SCTIME_SECS(ts))
                return 0;
        }
    }
    return 1;
}

/* get the bit with idx from the ippairdport */
static XBit *IPPairDPortBitGet(IPPairDPort *h, uint32_t idx)
{
    GenericVar *gv = IPPairDPortGetStorageById(h, g_ippairdport_bit_storage_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
            return (XBit *)gv;
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void IPPairDPortBitAdd(IPPairDPort *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(XBit));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_XBITS;
        fb->idx = idx;
        fb->next = NULL;
        fb->expire = expire;

        GenericVar *gv = IPPairDPortGetStorageById(h, g_ippairdport_bit_storage_id);
        GenericVarAppend(&gv, (GenericVar *)fb);
        IPPairDPortSetStorageById(h, g_ippairdport_bit_storage_id, gv);

        // bit already set, lets update it's timer
    } else {
        fb->expire = expire;
    }
}

static void IPPairDPortBitRemove(IPPairDPort *h, uint32_t idx)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb == NULL)
        return;

    GenericVar *gv = IPPairDPortGetStorageById(h, g_ippairdport_bit_storage_id);
    if (gv) {
        GenericVarRemove(&gv, (GenericVar *)fb);
        XBitFree(fb);
        IPPairDPortSetStorageById(h, g_ippairdport_bit_storage_id, gv);
    }
}

void IPPairDPortBitSet(IPPairDPort *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb == NULL) {
        IPPairDPortBitAdd(h, idx, expire);
    }
}

void IPPairDPortBitUnset(IPPairDPort *h, uint32_t idx)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb != NULL) {
        IPPairDPortBitRemove(h, idx);
    }
}

void IPPairDPortBitToggle(IPPairDPort *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb != NULL) {
        IPPairDPortBitRemove(h, idx);
    } else {
        IPPairDPortBitAdd(h, idx, expire);
    }
}

int IPPairDPortBitIsset(IPPairDPort *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb != NULL) {
        if (fb->expire < ts) {
            IPPairDPortBitRemove(h, idx);
            return 0;
        }

        return 1;
    }
    return 0;
}

int IPPairDPortBitIsnotset(IPPairDPort *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = IPPairDPortBitGet(h, idx);
    if (fb == NULL) {
        return 1;
    }

    if (fb->expire < ts) {
        IPPairDPortBitRemove(h, idx);
        return 1;
    }

    return 0;
}


/* TESTS */
#ifdef UNITTESTS
static int IPPairDPortBitTest01 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0, 0);

    XBit *fb = IPPairDPortBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest02 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    XBit *fb = IPPairDPortBitGet(h,0);
    if (fb == NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest03 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0, 30);

    XBit *fb = IPPairDPortBitGet(h,0);
    if (fb == NULL) {
        printf("fb == NULL although it was just added: ");
        goto end;
    }

    IPPairDPortBitRemove(h, 0);

    fb = IPPairDPortBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL although it was just removed: ");
        goto end;
    } else {
        ret = 1;
    }

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest04 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,30);
    IPPairDPortBitAdd(h, 1,30);
    IPPairDPortBitAdd(h, 2,30);
    IPPairDPortBitAdd(h, 3,30);

    XBit *fb = IPPairDPortBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest05 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,1);
    if (fb != NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest06 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,2);
    if (fb != NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest07 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,3);
    if (fb != NULL)
        ret = 1;

    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest08 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,0);
    if (fb == NULL)
        goto end;

    IPPairDPortBitRemove(h,0);

    fb = IPPairDPortBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest09 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,1);
    if (fb == NULL)
        goto end;

    IPPairDPortBitRemove(h,1);

    fb = IPPairDPortBitGet(h,1);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest10 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,2);
    if (fb == NULL)
        goto end;

    IPPairDPortBitRemove(h,2);

    fb = IPPairDPortBitGet(h,2);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

static int IPPairDPortBitTest11 (void)
{
    int ret = 0;

    IPPairDPortInitConfig(true);
    IPPairDPort *h = IPPairDPortAlloc();
    if (h == NULL)
        goto end;

    IPPairDPortBitAdd(h, 0,90);
    IPPairDPortBitAdd(h, 1,90);
    IPPairDPortBitAdd(h, 2,90);
    IPPairDPortBitAdd(h, 3,90);

    XBit *fb = IPPairDPortBitGet(h,3);
    if (fb == NULL)
        goto end;

    IPPairDPortBitRemove(h,3);

    fb = IPPairDPortBitGet(h,3);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairDPortFree(h);
end:
    IPPairDPortCleanup();
    return ret;
}

#endif /* UNITTESTS */

void IPPairDPortBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairDPortBitTest01", IPPairDPortBitTest01);
    UtRegisterTest("IPPairDPortBitTest02", IPPairDPortBitTest02);
    UtRegisterTest("IPPairDPortBitTest03", IPPairDPortBitTest03);
    UtRegisterTest("IPPairDPortBitTest04", IPPairDPortBitTest04);
    UtRegisterTest("IPPairDPortBitTest05", IPPairDPortBitTest05);
    UtRegisterTest("IPPairDPortBitTest06", IPPairDPortBitTest06);
    UtRegisterTest("IPPairDPortBitTest07", IPPairDPortBitTest07);
    UtRegisterTest("IPPairDPortBitTest08", IPPairDPortBitTest08);
    UtRegisterTest("IPPairDPortBitTest09", IPPairDPortBitTest09);
    UtRegisterTest("IPPairDPortBitTest10", IPPairDPortBitTest10);
    UtRegisterTest("IPPairDPortBitTest11", IPPairDPortBitTest11);
#endif /* UNITTESTS */
}
