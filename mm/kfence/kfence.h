/****************************************************************************
 * NuttX Electric-Fence (KFENCE). Memory debugging tool for detecting
 * out-of-bounds and use-after-free bugs.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/
#ifndef __INCLUDE_NUTTX_MM_KFENCE_H
#define __INCLUDE_NUTTX_MM_KFENCE_H

 /****************************************************************************
  * Included Files
  ****************************************************************************/
#include <sys/types.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef CONFIG_MM_KFENCE

  /****************************************************************************
   * Pre-processor Definitions
   ****************************************************************************/

   /**
    * Ϊ@addr��ȡcanary�ֽ�ģʽ��ʹ�û��ڵ�ַ��3λ�仯��ģʽ���Ը��ߵĸ��ʼ���ڴ��𻵣�
    * �ر�����ʹ�����Ƴ���������¡�
    */
#define KFENCE_CANARY_PATTERN_U8(addr) ((uint8_t)0xaa ^ (uint8_t)((uintptr_t)(addr) & 0x7))

    /**
     * �����8�ı�����ʼ������8�ֽ�canary��ÿ���ֽڵ�canaryֻ�����ַ�������λ��أ�
     * ���ÿ8���ֽڵ�canary����ͬ�ġ�����һ�����ͼ��64λ�ڴ棬���������ֽڲ�����
     * ��������ܡ�
     */
#define KFENCE_CANARY_PATTERN_U64 ((uint64_t)0xaaaaaaaaaaaaaaaa ^ (uint64_t)(0x0706050403020100))

     /* ���������ջ��� */
#define KFENCE_STACK_DEPTH 32


/****************************************************************************
 * Public Types
 ****************************************************************************/

 /* ����Ĭ��ֵ */

#ifndef CONFIG_MM_KFENCE_SAMPLE_INTERVAL
#define CONFIG_MM_KFENCE_SAMPLE_INTERVAL 100 
#endif


/* ȫ�ֱ������� */
extern unsigned long kfence_sample_interval;
extern bool kfence_is_enabled(void);
extern void kfence_disable(void);

 /* KFENCE����״̬ */
enum kfence_object_state_e
{
    KFENCE_OBJECT_UNUSED,         /* ����δʹ�� */
    KFENCE_OBJECT_ALLOCATED,      /* ����ǰ�ѷ��� */
    KFENCE_OBJECT_FREEING,        /* ���������ͷŹ����� */
    KFENCE_OBJECT_FREED,          /* �����ѷ�����ͷ� */
};

/* ����/�ͷŸ�����Ϣ */
struct kfence_track_s
{
    pid_t    pid;                 /* ִ�в����Ľ���ID */
    int      cpu;                 /* ִ�в�����CPU */
    uint64_t ts_nsec;             /* ʱ��������룩 */
    int      num_stack_entries;   /* ��Ч�Ķ�ջ��Ŀ���� */
    uintptr_t stack_entries[KFENCE_STACK_DEPTH]; /* ��ջ���ٵ�ַ */
};

/* ÿ���ܱ��������KFENCEԪ���� */
struct kfence_metadata_s
{
    FAR struct kfence_metadata_s* next; /* �����б��е���һ�� */

    /*
     * �����������ݵ�������ȷ��һ���ԣ���Ϊ���²������ܲ���ִ��:
     * kfence_alloc()��kfence_free()��kfence_handle_page_fault()
     */
    spinlock_t lock;

    /* ����ĵ�ǰ״̬ */
    enum kfence_object_state_e state;

    /*
     * �ѷ������ĵ�ַ�����ڶ���Ҫ���޷��Ӵ�С���������
     */
    uintptr_t addr;

    /* ԭʼ����Ĵ�С */
    size_t size;

    /*
     * �ϴη����mm_heap�������δ�������ѱ����٣���ΪNULL��
     */
    FAR struct mm_heap_s* heap;

    /*
     * ����Ч���ʵ�����£���ȡ��������ҳ�棻
     * �����ֹ۵�ֻ�洢һ����ַ��
     */
    uintptr_t unprotected_page;

    /* ������ͷŵĶ�ջ��Ϣ */
    struct kfence_track_s alloc_track;
    struct kfence_track_s free_track;

    /* ���ڸ��·���ͳ����Ϣ */
    uint32_t alloc_stack_hash;
};

/* KFENCE�������ͣ��������ɱ��� */
enum kfence_error_type_e
{
    KFENCE_ERROR_OOB,         /* ��⵽Խ����� */
    KFENCE_ERROR_UAF,         /* ��⵽�ͷź�ʹ�÷��� */
    KFENCE_ERROR_CORRUPTION,  /* ��⵽�ͷ�ʱ���ڴ��� */
    KFENCE_ERROR_INVALID,     /* δ֪���͵���Ч���� */
    KFENCE_ERROR_INVALID_FREE /* ��Ч���ͷŲ��� */
};

/****************************************************************************
 * Public Data
 ****************************************************************************/

#ifdef CONFIG_MM_KFENCE_POOL_SIZE
#  define KFENCE_POOL_SIZE CONFIG_MM_KFENCE_POOL_SIZE
#else
#  define KFENCE_POOL_SIZE (2 * 1024 * 1024) /* Ĭ��2MB�� */
#endif

#ifdef CONFIG_MM_KFENCE_NUM_OBJECTS
#  define KFENCE_NUM_OBJECTS CONFIG_MM_KFENCE_NUM_OBJECTS
#else
#  define KFENCE_NUM_OBJECTS 64
#endif

 /* ����KFENCE������ڴ�� */
extern FAR void* g_kfence_pool;

/* KFENCE�����Ԫ���� */
extern FAR struct kfence_metadata_s* g_kfence_metadata;



/****************************************************************************
 * ����: kfence_alloc
 *
 * ����:ʹ��KFENCE��ط����ڴ�
 *
 * �������:
 *   heap  - Ҫ�����ڴ�Ķ�
 *   size  - ����Ĵ�С
 *   align - ����Ҫ��2���ݣ�
 *
 * ����ֵ:
 *   �ѷ����ڴ�ĵ�ַ�������ʧ��ʱ����NULL
 *
 ****************************************************************************/

FAR void* kfence_alloc(FAR struct mm_heap_s* heap, size_t size, size_t align);

/****************************************************************************
 * ����: kfence_free
 *
 * ����:
 *   �ͷ�ͨ��kfence_alloc������ڴ�
 *
 * �������:
 *   addr - Ҫ�ͷŵķ����ַ
 *
 * ����ֵ:
 *   �ɹ�ʱ����OK��ʧ��ʱ���ظ���errno
 *
 ****************************************************************************/

int kfence_free(FAR void* addr);

/****************************************************************************
 * ����: is_kfence_address
 *
 * ����:
 *   ����ַ�Ƿ�����KFENCE��
 *
 * �������:
 *   addr - Ҫ���ĵ�ַ
 *
 * ����ֵ:
 *   �����ַ��KFENCE�����򷵻�true�����򷵻�false
 *
 ****************************************************************************/

bool is_kfence_address(FAR const void* addr);

/****************************************************************************
 * ����: addr_to_metadata
 *
 * ����:
 *   ��ȡKFENCE��ַ��Ԫ����
 *
 * �������:
 *   addr - ��ȡԪ���ݵĵ�ַ
 *
 * ����ֵ:
 *   Ԫ����ָ�룬�������KFENCE��ַ�򷵻�NULL
 *
 ****************************************************************************/

static inline FAR struct kfence_metadata_s* addr_to_metadata(uintptr_t addr)
{
    int index;

    /* ����Ƿ���KFENCE��ַ */
    if (!is_kfence_address((FAR void*)addr))
    {
        return NULL;
    }

    /*
     * ���ʹ��g_kfence_pool��Ե�ĵ�ַ���ã���������Ч������
     * ����������£����ǻᱨ��"��Ч����"����
     */
    index = (addr - (uintptr_t)g_kfence_pool) / (MM_PGSIZE * 2) - 1;
    if (index < 0 || index >= KFENCE_NUM_OBJECTS)
    {
        return NULL;
    }

    return &g_kfence_metadata[index];
}

/****************************************************************************
 * ����: kfence_report_error
 *
 * ����:
 *   ����KFENCE����
 *
 * �������:
 *   address - ��⵽����ĵ�ַ
 *   is_write - �������д������Ϊtrue��������Ϊfalse
 *   meta - �����Ԫ���ݣ�����ΪNULL��
 *   type - ��⵽�Ĵ�������
 *
 ****************************************************************************/

void kfence_report_error(uintptr_t address, bool is_write,
    FAR const struct kfence_metadata_s* meta,
    enum kfence_error_type_e type);

/****************************************************************************
 * ����: kfence_handle_page_fault
 *
 * ����:
 *   ���������KFENCE��ص�ҳ�����
 *
 * �������:
 *   addr - �����ַ
 *   is_write - �������д������Ϊtrue
 *
 * ����ֵ:
 *   ���������KFENCE�����򷵻�true�����򷵻�false
 *
 ****************************************************************************/

bool kfence_handle_page_fault(uintptr_t addr, bool is_write);



#endif /* CONFIG_MM_KFENCE */
#endif /* __INCLUDE_NUTTX_MM_KFENCE_H */
