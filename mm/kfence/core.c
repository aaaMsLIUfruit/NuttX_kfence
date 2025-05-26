#include <assert.h>
#include <syslog.h>
#include "kfence.h"

/* === 日志打印前缀设置 ================================================================= */
#define KFENCE_LOG_PRIORITY LOG_ERR
#define kfence_log(fmt, ...) syslog(KFENCE_LOG_PRIORITY, "kfence: " fmt, ##__VA_ARGS__)

/* 在第一次警告时禁用 KFENCE，假设错误不可恢复 */
#define KFENCE_WARN_ON(cond)                         \
    ({                                               \
        const bool __cond = (cond);                    \
        if(__cond){                                    \
            DEBUGPANIC();                             \
            atomic_store(&g_kfence_enabled, false);   \
            disabled_by_warn = true;                  \
        }                                               \
        __cond;                                  \
    })

/* === 数据段 ================================================================= */
/* 表示 KFENCE 的启用状态 */
static atomic_bool g_kfence_enabled = ATOMIC_VAR_INIT(true);
/* 标志位，记录是否因警告而禁用 KFENCE（用于调试日志） */
static bool g_disabled_by_warn;
/* 初始化采样间隔，默认值为 CONFIG_KFENCE_SAMPLE_INTERVAL（100） */
unsigned long kfence_sample_interval = CONFIG_MM_KFENCE_SAMPLE_INTERVAL;
EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */

/* 读取启用状态 */
bool kfence_is_enabled(void) {
    return atomic_load(&g_kfence_enabled);
}
/* 禁用 KFENCE，记录禁用原因 */
void kfence_disable(void) {
    atomic_store(&g_kfence_enabled, false);
    g_disabled_by_warn = true;
}

/* 初始化函数 */
void kfence_init(void) {
    
}

typedef struct {
    void *addr;
    size_t size;
    bool allocated;
} kfence_metadata;

static kfence_metadata g_metadata[10];  // 简单示例，实际需动态管理

void* kfence_alloc(size_t size) {
    if (!atomic_load(&g_kfence_enabled)) return NULL;

    // 简化的分配逻辑（需扩展为真实内存管理）
    for (int i = 0; i < 10; i++) {
        if (!g_metadata[i].allocated) {
            // g_metadata[i].addr = &g_kfence_pool[i * 64];  // 模拟分配
            g_metadata[i].size = size;
            g_metadata[i].allocated = true;
            return g_metadata[i].addr;
        }
    }
    return NULL;
}

void kfence_free(void *ptr) {
    // 查找并释放对象（省略错误检查）
    for (int i = 0; i < 10; i++) {
        if (g_metadata[i].addr == ptr) {
            g_metadata[i].allocated = false;
            break;
        }
    }
}
