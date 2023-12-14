/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * IPPairDPort wrapper around storage api
 */

#include "suricata-common.h"
#include "ippairdport-storage.h"
#include "util-unittest.h"

unsigned int IPPairDPortStorageSize(void)
{
    return StorageGetSize(STORAGE_IPPAIRDPORT);
}

void *IPPairDPortGetStorageById(IPPairDPort *h, IPPairDPortStorageId id)
{
    return StorageGetById((Storage *)((void *)h + sizeof(IPPairDPort)), STORAGE_IPPAIRDPORT, id.id);
}

int IPPairDPortSetStorageById(IPPairDPort *h, IPPairDPortStorageId id, void *ptr)
{
    return StorageSetById((Storage *)((void *)h + sizeof(IPPairDPort)), STORAGE_IPPAIRDPORT, id.id, ptr);
}

void *IPPairDPortAllocStorageById(IPPairDPort *h, IPPairDPortStorageId id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)h + sizeof(IPPairDPort)), STORAGE_IPPAIRDPORT, id.id);
}

void IPPairDPortFreeStorageById(IPPairDPort *h, IPPairDPortStorageId id)
{
    StorageFreeById((Storage *)((void *)h + sizeof(IPPairDPort)), STORAGE_IPPAIRDPORT, id.id);
}

void IPPairDPortFreeStorage(IPPairDPort *h)
{
    if (IPPairDPortStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)h + sizeof(IPPairDPort)), STORAGE_IPPAIRDPORT);
}

IPPairDPortStorageId IPPairDPortStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_IPPAIRDPORT, name, size, Alloc, Free);
    IPPairDPortStorageId ippsi = { .id = id };
    return ippsi;
}

#ifdef UNITTESTS

static void *StorageTestAlloc(unsigned int size)
{
    void *x = SCMalloc(size);
    return x;
}
static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int IPPairDPortStorageTest01(void)
{
    StorageInit();

    IPPairDPortStorageId id1 = IPPairDPortStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1.id < 0)
        goto error;
    IPPairDPortStorageId id2 = IPPairDPortStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2.id < 0)
        goto error;
    IPPairDPortStorageId id3 =
            IPPairDPortStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairDPortInitConfig(1);

    Address a, b;
    u_int16_t dp = 8080;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPairDPort *h = IPPairDPortGetIPPairDPortFromHash(&a, &b, dp);
    if (h == NULL) {
        printf("failed to get ippairdport: ");
        goto error;
    }

    void *ptr = IPPairDPortGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }
    ptr = IPPairDPortGetStorageById(h, id2);
    if (ptr != NULL) {
        goto error;
    }
    ptr = IPPairDPortGetStorageById(h, id3);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = IPPairDPortAllocStorageById(h, id1);
    if (ptr1a == NULL) {
        goto error;
    }
    void *ptr2a = IPPairDPortAllocStorageById(h, id2);
    if (ptr2a == NULL) {
        goto error;
    }
    void *ptr3a = IPPairDPortAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = IPPairDPortGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = IPPairDPortGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = IPPairDPortGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    IPPairDPortRelease(h);

    IPPairDPortShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairDPortShutdown();
    StorageCleanup();
    return 0;
}

static int IPPairDPortStorageTest02(void)
{
    StorageInit();

    IPPairDPortStorageId id1 = IPPairDPortStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairDPortInitConfig(1);

    Address a, b;
    u_int16_t dp = 8080;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPairDPort *h = IPPairDPortGetIPPairDPortFromHash(&a, &b, dp);
    if (h == NULL) {
        printf("failed to get ippairdport: ");
        goto error;
    }

    void *ptr = IPPairDPortGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    IPPairDPortSetStorageById(h, id1, ptr1a);

    void *ptr1b = IPPairDPortGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }

    IPPairDPortRelease(h);

    IPPairDPortShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairDPortShutdown();
    StorageCleanup();
    return 0;
}

static int IPPairDPortStorageTest03(void)
{
    StorageInit();

    IPPairDPortStorageId id1 = IPPairDPortStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;
    IPPairDPortStorageId id2 = IPPairDPortStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2.id < 0)
        goto error;
    IPPairDPortStorageId id3 = IPPairDPortStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairDPortInitConfig(1);

    Address a, b;
    u_int16_t dp = 8080;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPairDPort *h = IPPairDPortGetIPPairDPortFromHash(&a, &b, dp);
    if (h == NULL) {
        printf("failed to get ippairdport: ");
        goto error;
    }

    void *ptr = IPPairDPortGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    IPPairDPortSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    if (unlikely(ptr2a == NULL)) {
        goto error;
    }
    IPPairDPortSetStorageById(h, id2, ptr2a);

    void *ptr3a = IPPairDPortAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = IPPairDPortGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = IPPairDPortGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = IPPairDPortGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    IPPairDPortRelease(h);

    IPPairDPortShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairDPortShutdown();
    StorageCleanup();
    return 0;
}
#endif

void RegisterIPPairDPortStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairDPortStorageTest01", IPPairDPortStorageTest01);
    UtRegisterTest("IPPairDPortStorageTest02", IPPairDPortStorageTest02);
    UtRegisterTest("IPPairDPortStorageTest03", IPPairDPortStorageTest03);
#endif
}
