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
    * 为@addr获取canary字节模式。使用基于地址低3位变化的模式，以更高的概率检测内存损坏，
    * 特别是在使用类似常量的情况下。
    */
#define KFENCE_CANARY_PATTERN_U8(addr) ((uint8_t)0xaa ^ (uint8_t)((uintptr_t)(addr) & 0x7))

    /**
     * 定义从8的倍数开始的连续8字节canary。每个字节的canary只与其地址的最低三位相关，
     * 因此每8个字节的canary是相同的。可以一次填充和检查64位内存，而不是逐字节操作，
     * 以提高性能。
     */
#define KFENCE_CANARY_PATTERN_U64 ((uint64_t)0xaaaaaaaaaaaaaaaa ^ (uint64_t)(0x0706050403020100))

     /* 报告的最大堆栈深度 */
#define KFENCE_STACK_DEPTH 32


/****************************************************************************
 * Public Types
 ****************************************************************************/

 /* 配置默认值 */

#ifndef CONFIG_MM_KFENCE_SAMPLE_INTERVAL
#define CONFIG_MM_KFENCE_SAMPLE_INTERVAL 100 
#endif


/* 全局变量声明 */
extern unsigned long kfence_sample_interval;
extern bool kfence_is_enabled(void);
extern void kfence_disable(void);

 /* KFENCE对象状态 */
enum kfence_object_state_e
{
    KFENCE_OBJECT_UNUSED,         /* 对象未使用 */
    KFENCE_OBJECT_ALLOCATED,      /* 对象当前已分配 */
    KFENCE_OBJECT_FREEING,        /* 对象正在释放过程中 */
    KFENCE_OBJECT_FREED,          /* 对象已分配后被释放 */
};

/* 分配/释放跟踪信息 */
struct kfence_track_s
{
    pid_t    pid;                 /* 执行操作的进程ID */
    int      cpu;                 /* 执行操作的CPU */
    uint64_t ts_nsec;             /* 时间戳（纳秒） */
    int      num_stack_entries;   /* 有效的堆栈条目数量 */
    uintptr_t stack_entries[KFENCE_STACK_DEPTH]; /* 堆栈跟踪地址 */
};

/* 每个受保护分配的KFENCE元数据 */
struct kfence_metadata_s
{
    FAR struct kfence_metadata_s* next; /* 空闲列表中的下一个 */

    /*
     * 保护以下数据的锁，以确保一致性，因为以下操作可能并发执行:
     * kfence_alloc()、kfence_free()、kfence_handle_page_fault()
     */
    spinlock_t lock;

    /* 对象的当前状态 */
    enum kfence_object_state_e state;

    /*
     * 已分配对象的地址；由于对齐要求，无法从大小计算出来。
     */
    uintptr_t addr;

    /* 原始分配的大小 */
    size_t size;

    /*
     * 上次分配的mm_heap；如果从未分配或堆已被销毁，则为NULL。
     */
    FAR struct mm_heap_s* heap;

    /*
     * 在无效访问的情况下，被取消保护的页面；
     * 我们乐观地只存储一个地址。
     */
    uintptr_t unprotected_page;

    /* 分配和释放的堆栈信息 */
    struct kfence_track_s alloc_track;
    struct kfence_track_s free_track;

    /* 用于更新分配统计信息 */
    uint32_t alloc_stack_hash;
};

/* KFENCE错误类型，用于生成报告 */
enum kfence_error_type_e
{
    KFENCE_ERROR_OOB,         /* 检测到越界访问 */
    KFENCE_ERROR_UAF,         /* 检测到释放后使用访问 */
    KFENCE_ERROR_CORRUPTION,  /* 检测到释放时的内存损坏 */
    KFENCE_ERROR_INVALID,     /* 未知类型的无效访问 */
    KFENCE_ERROR_INVALID_FREE /* 无效的释放操作 */
};

/****************************************************************************
 * Public Data
 ****************************************************************************/

#ifdef CONFIG_MM_KFENCE_POOL_SIZE
#  define KFENCE_POOL_SIZE CONFIG_MM_KFENCE_POOL_SIZE
#else
#  define KFENCE_POOL_SIZE (2 * 1024 * 1024) /* 默认2MB池 */
#endif

#ifdef CONFIG_MM_KFENCE_NUM_OBJECTS
#  define KFENCE_NUM_OBJECTS CONFIG_MM_KFENCE_NUM_OBJECTS
#else
#  define KFENCE_NUM_OBJECTS 64
#endif

 /* 用于KFENCE分配的内存池 */
extern FAR void* g_kfence_pool;

/* KFENCE对象的元数据 */
extern FAR struct kfence_metadata_s* g_kfence_metadata;



/****************************************************************************
 * 名称: kfence_alloc
 *
 * 描述:使用KFENCE监控分配内存
 *
 * 输入参数:
 *   heap  - 要分配内存的堆
 *   size  - 分配的大小
 *   align - 对齐要求（2的幂）
 *
 * 返回值:
 *   已分配内存的地址，或分配失败时返回NULL
 *
 ****************************************************************************/

FAR void* kfence_alloc(FAR struct mm_heap_s* heap, size_t size, size_t align);

/****************************************************************************
 * 名称: kfence_free
 *
 * 描述:
 *   释放通过kfence_alloc分配的内存
 *
 * 输入参数:
 *   addr - 要释放的分配地址
 *
 * 返回值:
 *   成功时返回OK；失败时返回负的errno
 *
 ****************************************************************************/

int kfence_free(FAR void* addr);

/****************************************************************************
 * 名称: is_kfence_address
 *
 * 描述:
 *   检查地址是否属于KFENCE池
 *
 * 输入参数:
 *   addr - 要检查的地址
 *
 * 返回值:
 *   如果地址在KFENCE池中则返回true，否则返回false
 *
 ****************************************************************************/

bool is_kfence_address(FAR const void* addr);

/****************************************************************************
 * 名称: addr_to_metadata
 *
 * 描述:
 *   获取KFENCE地址的元数据
 *
 * 输入参数:
 *   addr - 获取元数据的地址
 *
 * 返回值:
 *   元数据指针，如果不是KFENCE地址则返回NULL
 *
 ****************************************************************************/

static inline FAR struct kfence_metadata_s* addr_to_metadata(uintptr_t addr)
{
    int index;

    /* 检查是否是KFENCE地址 */
    if (!is_kfence_address((FAR void*)addr))
    {
        return NULL;
    }

    /*
     * 如果使用g_kfence_pool边缘的地址调用，可能是无效索引，
     * 在这种情况下，我们会报告"无效访问"错误。
     */
    index = (addr - (uintptr_t)g_kfence_pool) / (MM_PGSIZE * 2) - 1;
    if (index < 0 || index >= KFENCE_NUM_OBJECTS)
    {
        return NULL;
    }

    return &g_kfence_metadata[index];
}

/****************************************************************************
 * 名称: kfence_report_error
 *
 * 描述:
 *   报告KFENCE错误
 *
 * 输入参数:
 *   address - 检测到错误的地址
 *   is_write - 如果这是写操作则为true，读操作为false
 *   meta - 对象的元数据（可以为NULL）
 *   type - 检测到的错误类型
 *
 ****************************************************************************/

void kfence_report_error(uintptr_t address, bool is_write,
    FAR const struct kfence_metadata_s* meta,
    enum kfence_error_type_e type);

/****************************************************************************
 * 名称: kfence_handle_page_fault
 *
 * 描述:
 *   处理可能与KFENCE相关的页面错误
 *
 * 输入参数:
 *   addr - 错误地址
 *   is_write - 如果这是写操作则为true
 *
 * 返回值:
 *   如果错误由KFENCE处理则返回true，否则返回false
 *
 ****************************************************************************/

bool kfence_handle_page_fault(uintptr_t addr, bool is_write);



#endif /* CONFIG_MM_KFENCE */
#endif /* __INCLUDE_NUTTX_MM_KFENCE_H */
